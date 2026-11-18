"""Image validation and security checks for MetaClean.

Provides format verification, magic signature checking, corruption detection,
decompression bomb prevention, and safe path resolution.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple

from PIL import Image

import config


class ImageValidationError(Exception):
    """Raised when an image fails critical validation checks."""
    pass


@dataclass(frozen=True)
class FileIdentity:
    """Device/inode identity of a filesystem entry, captured with ``lstat``.

    ``device`` and ``inode`` identify the file; ``ctime_ns`` guards against an
    inode being recycled after the original entry was removed, which is common
    on tmpfs.  The mode is retained so callers can tell a regular file from a
    symlink without re-querying the filesystem.
    """

    device: int
    inode: int
    mode: int
    ctime_ns: int = 0

    @property
    def key(self) -> Tuple[int, int]:
        return (self.device, self.inode)

    @property
    def is_regular_file(self) -> bool:
        return stat.S_ISREG(self.mode)

    def is_same_entry(self, other: Optional["FileIdentity"]) -> bool:
        """True when both snapshots describe the same, unchanged directory entry."""
        if other is None:
            return False
        return (
            self.device == other.device
            and self.inode == other.inode
            and self.ctime_ns == other.ctime_ns
        )


# ``O_NOFOLLOW`` is POSIX.  Windows has no equivalent, so the policy degrades
# to an lstat check before opening (documented in docs/METHODOLOGY.md).
_SYMLINK_ERRNOS = tuple(
    value
    for value in (
        getattr(errno, "ELOOP", None),
        getattr(errno, "EMLINK", None),
        getattr(errno, "ENOTDIR", None),
    )
    if value is not None
)


def is_symlink(path: str | Path) -> bool:
    """Returns True only when the final path component is a symbolic link.

    Unlike ``Path.is_symlink`` this never raises for permission errors and
    never follows the link, so it is safe to use as a policy gate.
    """
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


def file_identity(path: str | Path) -> Optional[FileIdentity]:
    """Captures the device/inode of a path without following a final symlink.

    Returns ``None`` when the path does not exist (including a dangling
    symlink, whose identity is still returned because ``lstat`` inspects the
    link itself).
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return FileIdentity(info.st_dev, info.st_ino, info.st_mode, info.st_ctime_ns)


def open_no_follow(path: str | Path, flags: int) -> int:
    """Opens a regular file, refusing to follow a final-component symlink.

    ``O_NOFOLLOW`` is used where the platform provides it.  On platforms
    without it, the lstat gate below runs first and the identity is checked
    after the open; the residual race is documented as a platform limitation.
    """
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags | no_follow)
    except OSError as exc:
        if no_follow and exc.errno in _SYMLINK_ERRNOS:
            raise ImageValidationError(
                f"Security violation: refusing to follow symbolic link: {path}"
            ) from exc
        raise

    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ImageValidationError(f"Path is not a regular file: {path}")
    return fd


def _open_readonly(path: Path) -> BinaryIO:
    fd = open_no_follow(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    return os.fdopen(fd, "rb")


def copy_regular_file_no_follow(
    source: str | Path,
    destination: str | Path,
    expected_identity: Optional[FileIdentity] = None,
) -> FileIdentity:
    """Copies a regular file through descriptor-level handles.

    The source is opened with ``O_NOFOLLOW`` and its identity is compared with
    ``expected_identity`` (captured earlier by the caller).  This closes the
    window in which the input path could be swapped for a different file
    between validation and copying.

    ``destination`` must already exist as a regular file (the remover creates
    it with ``mkstemp``); it is truncated and rewritten in place.
    """
    with _open_readonly(Path(source)) as src_handle:
        info = os.fstat(src_handle.fileno())
        identity = FileIdentity(info.st_dev, info.st_ino, info.st_mode, info.st_ctime_ns)
        if expected_identity is not None and not identity.is_same_entry(expected_identity):
            raise ImageValidationError(
                "Security violation: the input file changed between validation and "
                "cleaning; refusing to continue."
            )

        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        fd = open_no_follow(Path(destination), flags)
        with os.fdopen(fd, "wb") as dst_handle:
            shutil.copyfileobj(src_handle, dst_handle, length=1024 * 1024)
            dst_handle.flush()
            os.fsync(dst_handle.fileno())

    return identity


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


def safe_resolve_path(
    path_str: str | Path,
    must_exist: bool = True,
    allow_dir: bool = False,
    *,
    refuse_symlinks: bool = True,
    role: str = "path",
) -> Path:
    """Safely resolves and validates a file or directory path.

    Args:
        path_str: Path string or Path object.
        must_exist: Whether the target path must exist on the filesystem.
        allow_dir: Whether directories are acceptable targets.
        refuse_symlinks: Reject a symbolic link in the final path component.
            Intermediate directory symlinks are still resolved, because system
            directories such as ``/tmp`` are commonly symlinked; refusing those
            would make the tool unusable.  Destructive operations additionally
            re-check identity immediately before replacement.
        role: Human-readable description used in error messages.

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

    raw = Path(path_str).expanduser()
    if refuse_symlinks and is_symlink(raw):
        raise ImageValidationError(
            f"Security violation: symbolic links are not accepted as a {role}: {raw}. "
            "Pass the real file path instead."
        )

    try:
        p = raw.resolve()
    except Exception as e:
        raise ImageValidationError(f"Invalid path representation: {e}") from e

    # Defence in depth: the link could have been created between lstat and
    # resolve.  A resolved final component that is itself a link is refused.
    if refuse_symlinks and is_symlink(p):
        raise ImageValidationError(
            f"Security violation: symbolic links are not accepted as a {role}: {p}."
        )

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
        with _open_readonly(Path(file_path)) as f:
            header = f.read(32)
    except (OSError, ImageValidationError):
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
        resolved_path = safe_resolve_path(file_path, must_exist=True, role="input file")
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
        # First pass: verify integrity through a non-following descriptor.
        with _open_readonly(resolved_path) as handle:
            with Image.open(handle) as img:
                img.verify()

        # Second pass: read metadata, dimensions, channels, animation.
        with _open_readonly(resolved_path) as handle:
            with Image.open(handle) as img:
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

    except ImageValidationError as e:
        res.errors.append(str(e))
    except Image.DecompressionBombError as e:
        res.errors.append(f"Decompression bomb detected: {e}")
    except (OSError, SyntaxError, ValueError) as e:
        res.errors.append(f"Image decoding failed or corrupted image structure: {e}")
    finally:
        Image.MAX_IMAGE_PIXELS = orig_max_pixels

    return res
