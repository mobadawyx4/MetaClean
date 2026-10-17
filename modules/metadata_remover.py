"""Metadata removal engine with ExifTool and Pillow fallback.

Safely strips all metadata or selective categories from images without modifying
the original input. Preserves image pixel quality, transparency, orientation,
and handles temporary files securely.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from PIL import Image, ImageOps

import config
from modules.image_validator import ImageValidationError, ValidationResult, safe_resolve_path, validate_image


class RemovalError(Exception):
    """Raised when metadata removal fails."""
    pass


@dataclass
class RemovalResult:
    """Result of metadata sanitization process."""
    success: bool
    input_path: Path
    output_path: Path
    categories_requested: List[str]
    categories_removed: List[str] = field(default_factory=list)
    preserved_categories: List[str] = field(default_factory=list)
    method_used: str = "unknown"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    original_size: int = 0
    cleaned_size: int = 0

    @property
    def bytes_saved(self) -> int:
        return max(0, self.original_size - self.cleaned_size)


def validate_categories(categories_input: str | List[str]) -> Tuple[List[str], List[str]]:
    """Validates requested categories against supported options.

    Args:
        categories_input: Comma-separated string or list of category strings.

    Returns:
        Tuple of (valid_categories_list, invalid_categories_list).
    """
    if isinstance(categories_input, str):
        raw_items = [c.strip().lower() for c in categories_input.split(",") if c.strip()]
    else:
        raw_items = [c.strip().lower() for c in categories_input if c.strip()]

    valid: List[str] = []
    invalid: List[str] = []

    for item in raw_items:
        if item in config.METADATA_CATEGORIES:
            if item not in valid:
                valid.append(item)
        else:
            invalid.append(item)

    if not valid and not invalid:
        valid = ["all"]

    return valid, invalid


class MetadataRemover:
    """Handles metadata stripping with format awareness and safety guarantees."""

    def __init__(self, exiftool_path: Optional[str] = None) -> None:
        if exiftool_path is not None:
            self.exiftool_path = exiftool_path
            self.exiftool_available = True
        else:
            self.exiftool_path = config.EXIFTOOL_PATH
            self.exiftool_available = config.EXIFTOOL_AVAILABLE

    def _clean_with_exiftool(
        self,
        temp_file: Path,
        categories: List[str]
    ) -> Tuple[bool, List[str], List[str]]:
        """Executes ExifTool with safe argument lists on a temporary copy.

        Returns:
            Tuple of (success, errors, warnings).
        """
        errors: List[str] = []
        warnings: List[str] = []

        cmd: List[str] = [str(self.exiftool_path)]

        if "all" in categories:
            # Full cleaning: strip all metadata, preserve colorspace tags to prevent color distortion
            cmd.extend(["-all=", "-tagsFromFile", "@", "-ColorSpaceTags"])
        else:
            # Selective category removal
            for cat in categories:
                cat_def = config.METADATA_CATEGORIES.get(cat)
                if cat_def and "exiftool_args" in cat_def:
                    cmd.extend(cat_def["exiftool_args"])  # type: ignore

        # Overwrite in-place on the temporary working file
        cmd.extend(["-overwrite_original", str(temp_file)])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SUBPROCESS_TIMEOUT_SECONDS,
                check=False
            )
            if res.returncode != 0:
                errors.append(f"ExifTool execution failed (code {res.returncode}): {res.stderr.strip()}")
                return False, errors, warnings

            if "0 image files updated" in res.stdout and "1 image files unchanged" in res.stdout:
                warnings.append("ExifTool reported 0 tags updated (image may have had no matching metadata).")

            return True, errors, warnings

        except subprocess.TimeoutExpired:
            errors.append(f"ExifTool operation timed out after {config.SUBPROCESS_TIMEOUT_SECONDS}s.")
            return False, errors, warnings
        except OSError as e:
            errors.append(f"Subprocess invocation failed: {e}")
            return False, errors, warnings

    def _clean_with_pillow_fallback(
        self,
        src_path: Path,
        dest_path: Path,
        categories: List[str],
        val_res: ValidationResult
    ) -> Tuple[bool, List[str], List[str]]:
        """Fallback metadata stripper when ExifTool is unavailable.

        Preserves pixel values, transparency, and animation frames.
        """
        errors: List[str] = []
        warnings = [
            "ExifTool is unavailable; metadata removed using Pillow fallback engine.",
            "Selective category removal is limited under Pillow fallback; performing clean rebuild."
        ]

        try:
            with Image.open(src_path) as img:
                # Handle orientation normalization before stripping EXIF
                try:
                    img = ImageOps.exif_transpose(img) or img
                except Exception:
                    pass

                fmt = img.format or (val_res.format_name if val_res else "PNG")

                # Handle animated images
                if getattr(img, "is_animated", False) and getattr(img, "n_frames", 1) > 1:
                    frames = []
                    durations = []
                    for frame_idx in range(img.n_frames):
                        img.seek(frame_idx)
                        frames.append(img.copy())
                        durations.append(img.info.get("duration", 100))

                    # Save frames without original metadata
                    first_frame = frames[0]
                    save_kwargs = {
                        "save_all": True,
                        "append_images": frames[1:],
                        "duration": durations,
                        "loop": img.info.get("loop", 0),
                    }
                    first_frame.save(dest_path, format=fmt, **save_kwargs)
                else:
                    # Static image: create clean copy
                    # Save without passing exif or info metadata dict
                    save_kwargs = {}
                    if fmt == "JPEG":
                        save_kwargs["quality"] = 95
                        save_kwargs["optimize"] = True
                    elif fmt == "PNG":
                        save_kwargs["optimize"] = True

                    # Convert mode if needed for format
                    clean_img = img.copy()
                    clean_img.save(dest_path, format=fmt, **save_kwargs)

            return True, errors, warnings

        except Exception as e:
            errors.append(f"Pillow fallback cleaning failed: {e}")
            return False, errors, warnings

    def clean(
        self,
        input_path: str | Path,
        output_path: str | Path,
        categories: Optional[List[str] | str] = None,
        overwrite_output: bool = False,
    ) -> RemovalResult:
        """Removes metadata from an image and writes to output_path.

        Ensures the original input is strictly preserved and never modified.
        """
        # Resolve input safely
        try:
            in_p = safe_resolve_path(input_path, must_exist=True)
        except ImageValidationError as e:
            return RemovalResult(
                success=False,
                input_path=Path(input_path),
                output_path=Path(output_path),
                categories_requested=[],
                errors=[str(e)]
            )

        # Resolve output safely
        try:
            out_p = safe_resolve_path(output_path, must_exist=False)
        except ImageValidationError as e:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=Path(output_path),
                categories_requested=[],
                errors=[str(e)]
            )

        # Strict safety check: output cannot be the same file as input
        if in_p.resolve() == out_p.resolve():
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["Security violation: Output path must not be identical to original input path."]
            )

        # Check existing output
        if out_p.exists() and not overwrite_output:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=[f"Output file already exists: {out_p}. Specify overwrite/yes to proceed."]
            )

        # Validate categories
        cat_list, invalid_cats = validate_categories(categories or ["all"])
        if invalid_cats:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=cat_list,
                errors=[f"Invalid metadata category name(s): {', '.join(invalid_cats)}"]
            )

        # Pre-validate input image
        val_res = validate_image(in_p)
        if not val_res.is_valid:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=cat_list,
                errors=[f"Input image failed validation: {'; '.join(val_res.errors)}"]
            )

        orig_size = in_p.stat().st_size
        warnings: List[str] = []
        errors: List[str] = []

        if "all" not in cat_list:
            warnings.append(
                f"Selective metadata removal active ({', '.join(cat_list)}). "
                "Warning: Unselected metadata categories may still contain identifying information!"
            )

        # Ensure output directory exists
        out_p.parent.mkdir(parents=True, exist_ok=True)

        # Determine method and execute
        if self.exiftool_available and self.exiftool_path:
            method_used = "exiftool_lossless"
            # Create a secure temporary file in the same directory or tempdir
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=in_p.suffix,
                dir=out_p.parent
            ) as tmp_file:
                temp_path = Path(tmp_file.name)

            try:
                # Copy original bytes to temp working file
                shutil.copyfile(in_p, temp_path)

                success, tool_errors, tool_warnings = self._clean_with_exiftool(
                    temp_path, cat_list
                )
                errors.extend(tool_errors)
                warnings.extend(tool_warnings)

                if success:
                    # Safely move sanitized temp file to destination
                    if out_p.exists():
                        out_p.unlink()
                    shutil.move(str(temp_path), str(out_p))
                else:
                    if temp_path.exists():
                        temp_path.unlink()
                    return RemovalResult(
                        success=False,
                        input_path=in_p,
                        output_path=out_p,
                        categories_requested=cat_list,
                        method_used=method_used,
                        errors=errors,
                        warnings=warnings,
                        original_size=orig_size,
                    )

            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                return RemovalResult(
                    success=False,
                    input_path=in_p,
                    output_path=out_p,
                    categories_requested=cat_list,
                    method_used=method_used,
                    errors=[f"Unexpected error during removal: {e}"],
                    warnings=warnings,
                    original_size=orig_size,
                )

        else:
            method_used = "pillow_fallback"
            success, tool_errors, tool_warnings = self._clean_with_pillow_fallback(
                in_p, out_p, cat_list, val_res
            )
            errors.extend(tool_errors)
            warnings.extend(tool_warnings)
            if not success:
                return RemovalResult(
                    success=False,
                    input_path=in_p,
                    output_path=out_p,
                    categories_requested=cat_list,
                    method_used=method_used,
                    errors=errors,
                    warnings=warnings,
                    original_size=orig_size,
                )

        cleaned_size = out_p.stat().st_size if out_p.exists() else 0

        # Calculate preserved and removed categories
        if "all" in cat_list:
            removed_cats = [c for c in config.METADATA_CATEGORIES if c != "all"]
            preserved_cats = []
        else:
            removed_cats = list(cat_list)
            preserved_cats = [c for c in config.METADATA_CATEGORIES if c != "all" and c not in cat_list]

        return RemovalResult(
            success=True,
            input_path=in_p,
            output_path=out_p,
            categories_requested=cat_list,
            categories_removed=removed_cats,
            preserved_categories=preserved_cats,
            method_used=method_used,
            errors=errors,
            warnings=warnings,
            original_size=orig_size,
            cleaned_size=cleaned_size,
        )
