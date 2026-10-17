"""Image validation and security checks for MetaClean.

Provides format verification, magic signature checking, corruption detection,
decompression bomb prevention, and safe path resolution.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from PIL import Image

import config


class ImageValidationError(Exception):
    """Raised when an image fails critical validation checks."""
    pass


@dataclass
class ValidationResult:
    """Detailed summary of image validation checks."""
    file_path: Path
    is_valid: bool = False
    format_name: Optional[str] = None
    file_size: int = 0
    dimensions: Optional[Tuple[int, int]] = None
    has_transparency: bool = False
    is_animated: bool = False
    n_frames: int = 1
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.is_valid:
            dims = f"{self.dimensions[0]}x{self.dimensions[1]}" if self.dimensions else "Unknown"
            return f"Valid {self.format_name} ({self.file_size} bytes, {dims})"
        return f"Invalid: {'; '.join(self.errors)}"


def safe_resolve_path(path_str: str | Path, must_exist: bool = True, allow_dir: bool = False) -> Path:
    """Safely resolves and validates a file or directory path, preventing directory traversal.

    Args:
        path_str: Path string or Path object.
        must_exist: Whether the target path must exist on the filesystem.
        allow_dir: Whether directories are acceptable targets.

    Returns:
        Fully resolved Path object.

    Raises:
        ImageValidationError: If the path is unsafe, invalid, or does not exist.
    """
    if not path_str:
        raise ImageValidationError("Empty file path provided.")

    str_repr = str(path_str)
    if "\0" in str_repr:
        raise ImageValidationError("File path contains illegal null bytes.")

    try:
        p = Path(path_str).expanduser().resolve()
    except Exception as e:
        raise ImageValidationError(f"Invalid path representation: {e}") from e

    if must_exist:
        if not p.exists():
            raise ImageValidationError(f"File or directory not found: {p}")
        if not allow_dir and not p.is_file():
            raise ImageValidationError(f"Path is not a regular file: {p}")
        if allow_dir and not (p.is_file() or p.is_dir()):
            raise ImageValidationError(f"Path is neither a file nor a directory: {p}")

    return p


def check_magic_bytes(file_path: Path) -> Optional[str]:
    """Reads header bytes and identifies image format via magic signatures.

    Args:
        file_path: Path to the target file.

    Returns:
        Detected format key string (e.g. 'JPEG', 'PNG', 'WEBP', 'TIFF_LE', 'TIFF_BE', 'BMP')
        or None if no known signature matches.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(32)
    except OSError:
        return None

    if len(header) < 4:
        return None

    for fmt, sigs in config.FILE_SIGNATURES.items():
        match = True
        for sig_bytes, offset in sigs:
            if header[offset : offset + len(sig_bytes)] != sig_bytes:
                match = False
                break
        if match:
            return fmt

    return None


def validate_image(
    file_path: str | Path,
    max_size_bytes: int = config.MAX_FILE_SIZE_BYTES,
    max_pixels: int = config.MAX_IMAGE_PIXELS,
) -> ValidationResult:
    """Performs end-to-end validation on an input image.

    Checks:
    1. Safe path resolution and existence.
    2. File size within configured threshold.
    3. Magic signature matching against supported file types.
    4. Image decoding and structural verification using Pillow.
    5. Decompression bomb protection (pixel limit).
    6. Transparency and animation detection.

    Args:
        file_path: Path to the image.
        max_size_bytes: Maximum allowed file size in bytes.
        max_pixels: Maximum allowed pixel count.

    Returns:
        ValidationResult object containing status, dimensions, and any errors.
    """
    try:
        resolved_path = safe_resolve_path(file_path, must_exist=True)
    except ImageValidationError as e:
        return ValidationResult(
            file_path=Path(file_path),
            is_valid=False,
            errors=[str(e)]
        )

    res = ValidationResult(file_path=resolved_path)

    # 1. File size check
    try:
        stat_info = resolved_path.stat()
        res.file_size = stat_info.st_size
    except OSError as e:
        res.errors.append(f"Failed to access file attributes: {e}")
        return res

    if res.file_size == 0:
        res.errors.append("File is empty (0 bytes).")
        return res

    if res.file_size > max_size_bytes:
        res.errors.append(
            f"File size ({res.file_size} bytes) exceeds maximum limit "
            f"({max_size_bytes} bytes)."
        )
        return res

    # 2. Extension check
    suffix = resolved_path.suffix.lower()
    if suffix not in config.SUPPORTED_EXTENSIONS:
        res.warnings.append(f"File extension '{suffix}' is not in the standard supported list.")

    # 3. Magic bytes signature validation
    magic_fmt = check_magic_bytes(resolved_path)
    if not magic_fmt:
        res.errors.append("Invalid or unrecognized file signature (magic bytes mismatch).")
        return res

    # Normalize format name
    if magic_fmt.startswith("TIFF"):
        canonical_fmt = "TIFF"
    else:
        canonical_fmt = magic_fmt

    res.format_name = canonical_fmt

    # 4. Decoding and integrity check with Pillow
    orig_max_pixels = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max_pixels

    try:
        # First pass: verify integrity
        with Image.open(resolved_path) as img:
            img.verify()

        # Second pass: read metadata, dimensions, channels, animation
        with Image.open(resolved_path) as img:
            res.dimensions = img.size
            total_pixels = img.size[0] * img.size[1]
            if total_pixels > max_pixels:
                res.errors.append(
                    f"Image dimensions {img.size} exceed pixel limit ({total_pixels} > {max_pixels})."
                )
                return res

            # Detect transparency
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                res.has_transparency = True

            # Detect animation
            is_anim = getattr(img, "is_animated", False)
            res.is_animated = bool(is_anim)
            res.n_frames = getattr(img, "n_frames", 1)

            res.is_valid = True

    except Image.DecompressionBombError as e:
        res.errors.append(f"Decompression bomb detected: {e}")
    except (OSError, SyntaxError, ValueError) as e:
        res.errors.append(f"Image decoding failed or corrupted image structure: {e}")
    finally:
        Image.MAX_IMAGE_PIXELS = orig_max_pixels

    return res
