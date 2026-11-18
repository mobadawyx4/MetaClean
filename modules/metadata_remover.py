"""Metadata removal engine with ExifTool and Pillow fallback.

Safety guarantees:
* The original input file is never modified: cleaning happens on a private
  temporary copy in the destination directory, which is atomically moved into
  place only after ExifTool succeeds.
* The output path may not be identical to the input (inode/hardlink aware) and
  may not be a symbolic link.
* The cleaned output is re-opened and validated before success is reported.
* A successful ExifTool exit code is not treated as proof of removal; the
  verifier performs an independent scan afterwards.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from PIL import Image, ImageOps

import config
from modules.exiftool_backend import ExifToolBackend
from modules.image_validator import (
    FileIdentity,
    ImageValidationError,
    ValidationResult,
    copy_regular_file_no_follow,
    file_identity,
    is_symlink,
    safe_resolve_path,
    validate_image,
)
from modules.sanitizer_profiles import PROFILES, get_profile


class RemovalError(Exception):
    """Raised when metadata removal fails."""


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
    profile: Optional[str] = None
    operations_attempted: List[str] = field(default_factory=list)
    exiftool_args: List[str] = field(default_factory=list)
    output_validated: bool = False
    output_created: bool = False
    tags_updated_count: Optional[int] = None

    @property
    def bytes_saved(self) -> int:
        return max(0, self.original_size - self.cleaned_size)

    @property
    def size_delta(self) -> int:
        return self.cleaned_size - self.original_size


def validate_categories(
    categories_input: str | List[str],
    default_all: bool = True,
) -> Tuple[List[str], List[str]]:
    """Validates requested categories against supported options.

    Returns:
        Tuple of (valid_categories_list, invalid_categories_list).
    """
    if isinstance(categories_input, str):
        raw_items = [c.strip().lower() for c in categories_input.split(",") if c.strip()]
    else:
        raw_items = [c.strip().lower() for c in categories_input if str(c).strip()]

    valid: List[str] = []
    invalid: List[str] = []

    for item in raw_items:
        if item in config.METADATA_CATEGORIES:
            if item not in valid:
                valid.append(item)
        else:
            invalid.append(item)

    if not valid and not invalid and default_all:
        valid = ["all"]

    return valid, invalid


def _describe_operations(categories: List[str]) -> List[str]:
    operations: List[str] = []
    if "all" in categories:
        operations.append("Strip all writable metadata blocks (EXIF, GPS, IPTC, XMP, MakerNotes).")
        operations.append("Preserve colour-space/ICC and orientation tags required for correct rendering.")
        return operations
    for category in categories:
        definition = config.METADATA_CATEGORIES.get(category, {})
        operations.append(f"Remove category '{category}': {definition.get('description', category)}.")
    return operations


class MetadataRemover:
    """Handles metadata stripping with format awareness and safety guarantees."""

    def __init__(self, exiftool_path: Optional[str] = None) -> None:
        if exiftool_path is not None:
            self.exiftool_path = exiftool_path
            self.exiftool_available = True
        else:
            self.exiftool_path = config.EXIFTOOL_PATH
            self.exiftool_available = config.EXIFTOOL_AVAILABLE
        self.backend = ExifToolBackend(path=self.exiftool_path)
        if not self.exiftool_available:
            self.backend.available = False

    # ------------------------------------------------------------------
    # ExifTool cleaning
    # ------------------------------------------------------------------
    def _build_exiftool_args(self, categories: List[str]) -> List[str]:
        args: List[str] = []
        if "all" in categories:
            # Strip everything, then restore colour-space and orientation tags from
            # the same file so rendering is not altered.
            args.extend(
                ["-all=", "-tagsFromFile", "@", "-ColorSpaceTags", "-Orientation"]
            )
        else:
            for category in categories:
                definition = config.METADATA_CATEGORIES.get(category)
                if definition and "exiftool_args" in definition:
                    args.extend(str(a) for a in definition["exiftool_args"])  # type: ignore[index]
        return args

    def _clean_with_exiftool(
        self, temp_file: Path, categories: List[str]
    ) -> Tuple[bool, List[str], List[str], List[str], Optional[int]]:
        """Cleans a temporary working copy with ExifTool.

        Returns:
            (success, errors, warnings, args, updated_count)
        """
        errors: List[str] = []
        warnings: List[str] = []
        args = self._build_exiftool_args(categories)

        result = self.backend.write(temp_file, args)
        updated = self.backend.count_updated(result)

        if not result.ok:
            errors.append(
                result.diagnostics or f"ExifTool failed with exit code {result.returncode}."
            )
            return False, errors, warnings, args, updated

        if updated == 0:
            warnings.append(
                "ExifTool reported that no tags were updated; the requested fields may have "
                "already been absent, or the format may not support this operation."
            )
        elif updated is None:
            # ExifTool did not print the "N image files updated" summary line, so
            # we cannot prove anything was removed.  Warn rather than stay silent.
            warnings.append(
                "ExifTool did not report how many tags were updated; removal success could not "
                "be confirmed from the tool's own summary. Verify the output independently."
            )

        return True, errors, warnings, args, updated

    # ------------------------------------------------------------------
    # Pillow fallback
    # ------------------------------------------------------------------
    def _clean_with_pillow_fallback(
        self,
        src_path: Path,
        dest_path: Path,
        categories: List[str],
        val_res: ValidationResult,
    ) -> Tuple[bool, List[str], List[str]]:
        """Rebuilds the image without metadata when ExifTool is unavailable.

        Only full cleaning is supported: a pixel rebuild cannot selectively
        target metadata groups.
        """
        errors: List[str] = []
        warnings = [
            "ExifTool is unavailable; metadata removed using the Pillow fallback engine.",
            "The fallback re-encodes the image, so pixel data may change slightly.",
        ]

        if "all" not in categories:
            return (
                False,
                [
                    "Selective metadata removal requires ExifTool. Install ExifTool or request "
                    "full cleaning ('all')."
                ],
                warnings,
            )

        try:
            with Image.open(src_path) as img:
                try:
                    img = ImageOps.exif_transpose(img) or img
                except Exception:
                    warnings.append("EXIF orientation could not be applied before re-encoding.")

                fmt = img.format or (val_res.format_name if val_res else "PNG")
                save_kwargs = {}

                if getattr(img, "is_animated", False) and getattr(img, "n_frames", 1) > 1:
                    frames = []
                    durations = []
                    for frame_idx in range(img.n_frames):
                        img.seek(frame_idx)
                        frames.append(img.copy())
                        durations.append(img.info.get("duration", 100))
                    save_kwargs.update(
                        {
                            "save_all": True,
                            "append_images": frames[1:],
                            "duration": durations,
                            "loop": img.info.get("loop", 0),
                        }
                    )
                    first = frames[0]
                else:
                    first = img.copy()

                if fmt == "JPEG":
                    save_kwargs.update({"quality": 95, "optimize": True})
                elif fmt == "PNG":
                    save_kwargs.update({"optimize": True})
                elif fmt == "WEBP":
                    save_kwargs.update({"quality": 95})

                first.save(dest_path, format=fmt, **save_kwargs)

            return True, errors, warnings
        except Exception as exc:
            errors.append(f"Pillow fallback cleaning failed: {exc}")
            return False, errors, warnings

    # ------------------------------------------------------------------
    # Staged output helpers (F-06 / F-07)
    # ------------------------------------------------------------------
    @staticmethod
    def _create_temp_file(directory: Path, suffix: str) -> Tuple[Path, Optional[FileIdentity]]:
        """Creates an empty private working file in the destination directory.

        The file is created before the backup/cleaning step so that the final
        ``os.replace`` stays on the same filesystem and is therefore atomic.
        """
        fd, name = tempfile.mkstemp(prefix=".metaclean-", suffix=suffix, dir=str(directory))
        os.close(fd)
        path = Path(name)
        return path, file_identity(path)

    @staticmethod
    def _discard_temp(path: Optional[Path], identity: Optional[FileIdentity]) -> None:
        """Removes a temporary file only when it is still the file we created.

        A path whose inode changed is left alone: deleting it would destroy an
        unrelated file that happened to be moved into our temp name.
        """
        if path is None:
            return
        current = file_identity(path)
        if current is None:
            return
        if not current.is_same_entry(identity):
            return
        try:
            os.unlink(path)
        except OSError:
            pass

    def _validate_working_copy(
        self,
        temp_path: Path,
        val_res: ValidationResult,
        errors: List[str],
    ) -> bool:
        """Structural validation that must pass before installation."""
        temp_check = validate_image(temp_path)
        if not temp_check.is_valid:
            errors.append(
                "Cleaned working copy failed readability validation: "
                + "; ".join(temp_check.errors)
            )
            return False
        if temp_check.file_size == 0:
            errors.append("Cleaned working copy is empty.")
            return False
        if temp_check.dimensions and val_res.dimensions:
            if sorted(temp_check.dimensions) != sorted(val_res.dimensions):
                errors.append(
                    f"Output dimensions {temp_check.dimensions} do not match input "
                    f"dimensions {val_res.dimensions}."
                )
                return False
        return True

    def _install_validated_output(
        self,
        temp_path: Path,
        temp_identity: Optional[FileIdentity],
        out_p: Path,
        dest_identity: Optional[FileIdentity],
        parent_identity: Optional[FileIdentity],
        overwrite_output: bool,
    ) -> None:
        """Atomically installs a validated working copy over the destination.

        Every check below runs immediately before ``os.replace`` so a symlink
        swap or concurrent replacement is refused instead of being followed or
        silently overwritten.  Raises ``RemovalError`` when installation is not
        safe; the caller keeps the destination untouched and discards the temp
        file.
        """
        current_parent = file_identity(out_p.parent)
        if (
            parent_identity is not None
            and current_parent is not None
            and current_parent.key != parent_identity.key
        ):
            raise RemovalError(
                "Security violation: the output directory changed during cleaning; "
                "refusing to install the cleaned file."
            )

        if is_symlink(out_p):
            raise RemovalError(
                "Security violation: refusing to replace a symbolic link at the output path."
            )

        current_dest = file_identity(out_p)
        if current_dest is not None:
            if not overwrite_output:
                raise RemovalError(
                    f"Output file appeared during cleaning and overwrite was not requested: {out_p}"
                )
            if dest_identity is None or not current_dest.is_same_entry(dest_identity):
                raise RemovalError(
                    "Security violation: the output file changed during cleaning; "
                    "refusing to replace it."
                )

        current_temp = file_identity(temp_path)
        if current_temp is None:
            raise RemovalError("The cleaned working copy disappeared before installation.")
        if not current_temp.is_same_entry(temp_identity):
            raise RemovalError(
                "Security violation: the temporary output was replaced before installation; "
                "refusing to continue."
            )

        os.replace(temp_path, out_p)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def clean(
        self,
        input_path: str | Path,
        output_path: str | Path,
        categories: Optional[List[str] | str] = None,
        overwrite_output: bool = False,
        profile: Optional[str] = None,
    ) -> RemovalResult:
        """Removes metadata from an image and writes a new output file.

        Args:
            input_path: Original image; never modified.
            output_path: Destination for the cleaned copy.
            categories: Categories to remove. Ignored when ``profile`` supplies them.
            overwrite_output: Allow replacing an existing output file.
            profile: Optional sanitization profile key.
        """
        try:
            in_p = safe_resolve_path(input_path, must_exist=True, role="input file")
        except ImageValidationError as exc:
            return RemovalResult(
                success=False,
                input_path=Path(input_path),
                output_path=Path(output_path),
                categories_requested=[],
                errors=[str(exc)],
            )

        try:
            out_p = safe_resolve_path(output_path, must_exist=False, role="output file")
        except ImageValidationError as exc:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=Path(output_path),
                categories_requested=[],
                errors=[str(exc)],
            )

        # Defence in depth: safe_resolve_path already refuses a symlink final
        # component, but re-check after resolution in case the link was created
        # in between.  A symlinked destination must never be followed or
        # replaced: os.replace would either clobber the link target or unlink
        # the link, both of which surprise the user.
        if is_symlink(out_p):
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["Security violation: refusing to write through a symbolic link at the output path."],
            )

        if out_p.exists() and out_p.is_dir():
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["Output path is a directory, not a file."],
            )

        # Identities are captured once and re-checked immediately before the
        # atomic replace, so a same-file alias (hardlink, ``..``, symlinked
        # parent) cannot be mistaken for a fresh destination.
        in_identity = file_identity(in_p)
        if in_identity is None:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["Input file could not be inspected; it may have been removed."],
            )
        dest_identity = file_identity(out_p)

        same_file = False
        if dest_identity is not None:
            try:
                same_file = os.path.samefile(in_p, out_p)
            except OSError:
                same_file = in_identity.key == dest_identity.key
        else:
            same_file = in_p.resolve() == out_p.resolve()
        if same_file:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["Security violation: Output path must not be identical to the original input."],
            )

        if dest_identity is not None and not overwrite_output:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=[f"Output file already exists: {out_p}. Specify overwrite/yes to proceed."],
            )

        # Resolve the profile/category set.
        resolved_profile: Optional[str] = profile
        if profile:
            profile_obj = get_profile(profile)
            if profile_obj is None:
                return RemovalResult(
                    success=False,
                    input_path=in_p,
                    output_path=out_p,
                    categories_requested=[],
                    errors=[f"Unknown sanitization profile '{profile}'."],
                    profile=profile,
                )
            if profile_obj.key == "custom":
                if not categories:
                    return RemovalResult(
                        success=False,
                        input_path=in_p,
                        output_path=out_p,
                        categories_requested=[],
                        errors=["The 'custom' profile requires at least one category to remove."],
                        profile=resolved_profile,
                    )
                cat_list, invalid_cats = validate_categories(categories, default_all=False)
            else:
                cat_list = list(profile_obj.categories)
                invalid_cats = []
        else:
            if categories is not None and len(categories) == 0:
                return RemovalResult(
                    success=False,
                    input_path=in_p,
                    output_path=out_p,
                    categories_requested=[],
                    errors=["No valid metadata categories specified for removal."],
                    profile=resolved_profile,
                )
            cat_list, invalid_cats = validate_categories(categories or ["all"], default_all=False)

        if invalid_cats:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=cat_list,
                errors=[f"Invalid metadata category name(s): {', '.join(invalid_cats)}"],
                profile=resolved_profile,
            )

        if not cat_list:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=[],
                errors=["No valid metadata categories specified for removal."],
                profile=resolved_profile,
            )

        val_res = validate_image(in_p)
        if not val_res.is_valid:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=cat_list,
                errors=[f"Input image failed validation: {'; '.join(val_res.errors)}"],
                profile=resolved_profile,
            )

        orig_size = in_p.stat().st_size
        warnings: List[str] = []
        errors: List[str] = []
        operations = _describe_operations(cat_list)
        output_created = dest_identity is None

        if "all" not in cat_list:
            warnings.append(
                f"Selective metadata removal active ({', '.join(cat_list)}). "
                "Unselected metadata categories may still contain identifying information."
            )

        def _failure(
            *,
            method: str = "unknown",
            args_list: Optional[List[str]] = None,
            updated_count: Optional[int] = None,
        ) -> RemovalResult:
            return RemovalResult(
                success=False,
                input_path=in_p,
                output_path=out_p,
                categories_requested=cat_list,
                method_used=method,
                errors=errors,
                warnings=warnings,
                original_size=orig_size,
                profile=resolved_profile,
                operations_attempted=operations,
                exiftool_args=list(args_list or []),
                output_validated=False,
                tags_updated_count=updated_count,
            )

        try:
            out_p.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            errors.append(f"Could not create the output directory: {exc}")
            return _failure()
        parent_identity = file_identity(out_p.parent)

        args: List[str] = []
        updated: Optional[int] = None
        output_validated = False
        method_used = (
            "exiftool_lossless"
            if (self.exiftool_available and self.exiftool_path)
            else "pillow_fallback"
        )

        try:
            temp_path, temp_identity = self._create_temp_file(out_p.parent, in_p.suffix)
        except OSError as exc:
            errors.append(f"Could not create a temporary working file: {exc}")
            return _failure(method=method_used)

        try:
            if method_used == "exiftool_lossless":
                # Descriptor-level copy with identity verification: a swapped
                # input path cannot redirect the copy to a different file.
                try:
                    copy_regular_file_no_follow(in_p, temp_path, expected_identity=in_identity)
                except (ImageValidationError, OSError) as exc:
                    errors.append(f"Could not create the working copy: {exc}")
                    return _failure(method=method_used)

                success, tool_errors, tool_warnings, args, updated = self._clean_with_exiftool(
                    temp_path, cat_list
                )
                # The backend rewrites the working file; re-capture its identity
                # so a failed run still cleans up the file it actually wrote.
                temp_identity = file_identity(temp_path) or temp_identity
                errors.extend(tool_errors)
                warnings.extend(tool_warnings)
                if not success:
                    return _failure(
                        method=method_used, args_list=args, updated_count=updated
                    )
            else:
                # The fallback reads the source path itself; confirm it is still
                # the file that was validated before re-encoding.
                current_input = file_identity(in_p)
                if current_input is None or not current_input.is_same_entry(in_identity):
                    errors.append(
                        "Security violation: the input file changed between validation and "
                        "cleaning; refusing to continue."
                    )
                    return _failure(method=method_used)

                success, tool_errors, tool_warnings = self._clean_with_pillow_fallback(
                    in_p, temp_path, cat_list, val_res
                )
                temp_identity = file_identity(temp_path) or temp_identity
                errors.extend(tool_errors)
                warnings.extend(tool_warnings)
                if not success:
                    return _failure(method=method_used)

            # Snapshot the working copy before validating it, so the file that
            # was validated is provably the file that gets installed.  (The
            # snapshot above, taken right after the backend step, is the same
            # entry; it is re-read here to keep the invariant local.)
            temp_identity = file_identity(temp_path) or temp_identity
            if temp_identity is None or not temp_identity.is_regular_file:
                errors.append(
                    "The cleaned working copy is missing or is not a regular file."
                )
                return _failure(
                    method=method_used, args_list=args, updated_count=updated
                )

            # F-07: the destination is untouched until the working copy passes
            # structural validation (readable, non-empty, same dimensions).
            if not self._validate_working_copy(temp_path, val_res, errors):
                return _failure(
                    method=method_used, args_list=args, updated_count=updated
                )

            # The working copy must still be the entry that was validated;
            # otherwise a swap could install unvalidated bytes.
            validated_temp = file_identity(temp_path)
            if (
                validated_temp is None
                or not validated_temp.is_same_entry(temp_identity)
            ):
                errors.append(
                    "Security violation: the temporary output changed during "
                    "validation; refusing to continue."
                )
                return _failure(
                    method=method_used, args_list=args, updated_count=updated
                )
            temp_identity = validated_temp

            try:
                self._install_validated_output(
                    temp_path=temp_path,
                    temp_identity=temp_identity,
                    out_p=out_p,
                    dest_identity=dest_identity,
                    parent_identity=parent_identity,
                    overwrite_output=overwrite_output,
                )
            except RemovalError as exc:
                errors.append(str(exc))
                return _failure(
                    method=method_used, args_list=args, updated_count=updated
                )

            # From here the validated copy is the destination.  A pre-existing
            # destination has been atomically replaced and cannot be restored,
            # so no code below is allowed to delete or rewrite the output.
            output_validated = True
            temp_path = None  # consumed by os.replace
            try:
                cleaned_size = out_p.stat().st_size
            except OSError:
                cleaned_size = 0
        except Exception as exc:
            errors.append(f"Unexpected error during removal: {exc}")
            return _failure(method=method_used, args_list=args, updated_count=updated)
        finally:
            self._discard_temp(temp_path, temp_identity)
        removed_cats = (
            [c for c in config.METADATA_CATEGORIES if c != "all"]
            if "all" in cat_list
            else list(cat_list)
        )
        preserved_cats = (
            []
            if "all" in cat_list
            else [c for c in config.METADATA_CATEGORIES if c != "all" and c not in cat_list]
        )

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
            profile=resolved_profile,
            operations_attempted=operations,
            exiftool_args=args,
            output_validated=output_validated,
            output_created=output_created,
            tags_updated_count=updated,
        )
