"""Deep, non-destructive file and container analysis.

This module inspects the physical file rather than trusting its extension:
container structure, image mode/bit depth, embedded colour profiles, animation,
trailing bytes after the format's end marker, and metadata inconsistencies.

Findings are explicitly separated into:

* ``CONFIRMED``    - a fact read from the file (e.g. extension/format mismatch)
* ``SUSPICIOUS``   - an indicator that *may* be benign, described without
                     claiming malicious intent
* ``INFORMATIONAL``- neutral observations

Only supported raster formats are inspected.  No network access is performed.
"""

from __future__ import annotations

import datetime
import mimetypes
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

import config
from modules.image_validator import check_magic_bytes

_FORMAT_EXTENSIONS: Dict[str, set[str]] = {
    "JPEG": {".jpg", ".jpeg", ".jpe", ".jfif"},
    "PNG": {".png"},
    "WEBP": {".webp"},
    "TIFF": {".tif", ".tiff"},
    "BMP": {".bmp", ".dib"},
}

_MODE_BITS: Dict[str, int] = {
    "1": 1, "L": 8, "LA": 8, "P": 8, "RGB": 8, "RGBA": 8, "CMYK": 8,
    "YCbCr": 8, "LAB": 8, "HSV": 8, "I": 32, "F": 32, "I;16": 16,
    "I;16B": 16, "I;16L": 16,
}

_PNG_COLOR_TYPES = {
    0: "Grayscale",
    2: "Truecolour (RGB)",
    3: "Indexed colour",
    4: "Grayscale + alpha",
    6: "Truecolour + alpha",
}


class FindingKind(str, Enum):
    """Confidence classification for a file-analysis observation."""

    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class FileFinding:
    """A single structural or consistency observation."""

    kind: FindingKind
    code: str
    title: str
    detail: str
    severity: str = "INFO"  # INFO | LOW | MEDIUM | HIGH
    evidence: str = ""


@dataclass
class FileAnalysis:
    """Result of deep container and consistency analysis."""

    detected_format: Optional[str] = None
    declared_extension: str = ""
    extension_matches: bool = True
    mime_type: Optional[str] = None
    file_size: int = 0
    dimensions: Optional[Tuple[int, int]] = None
    color_mode: Optional[str] = None
    bit_depth: Optional[int] = None
    color_model: Optional[str] = None
    has_alpha: bool = False
    is_animated: bool = False
    n_frames: int = 1
    frame_durations_ms: List[int] = field(default_factory=list)
    has_icc_profile: bool = False
    icc_profile_bytes: int = 0
    icc_description: Optional[str] = None
    embedded_thumbnail_tags: List[str] = field(default_factory=list)
    metadata_groups: Dict[str, int] = field(default_factory=dict)
    end_marker_found: Optional[bool] = None
    trailing_data_bytes: int = 0
    trailing_data_preview: str = ""
    structure_notes: List[str] = field(default_factory=list)
    findings: List[FileFinding] = field(default_factory=list)

    @property
    def confirmed_findings(self) -> List[FileFinding]:
        return [f for f in self.findings if f.kind == FindingKind.CONFIRMED]

    @property
    def suspicious_findings(self) -> List[FileFinding]:
        return [f for f in self.findings if f.kind == FindingKind.SUSPICIOUS]

    @property
    def informational_findings(self) -> List[FileFinding]:
        return [f for f in self.findings if f.kind == FindingKind.INFORMATIONAL]

    def add(self, finding: FileFinding) -> None:
        self.findings.append(finding)


def _read_head(path: Path, size: int = 64) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _read_tail(path: Path, size: int = config.STRUCTURE_PROBE_BYTES) -> bytes:
    try:
        file_size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, file_size - size))
            return fh.read(size)
    except OSError:
        return b""


def _trailing_bytes_jpeg(path: Path, file_size: int) -> Tuple[int, Optional[bool], bytes]:
    """Returns (trailing_byte_count, eoi_found, trailing_preview)."""
    tail = _read_tail(path)
    if not tail:
        return 0, False, b""
    index = tail.rfind(b"\xff\xd9")
    if index < 0:
        return 0, False, b""
    trailing = tail[index + 2 :]
    return len(trailing), True, trailing


def _trailing_bytes_png(path: Path, file_size: int) -> Tuple[int, Optional[bool], bytes]:
    tail = _read_tail(path)
    index = tail.rfind(b"IEND")
    if index < 0:
        return 0, False, b""
    # IEND chunk = 4-byte length + 4-byte type + 0 data + 4-byte CRC.
    end = (file_size - len(tail)) + index + 12
    trailing = file_size - end if file_size > end else 0
    preview = tail[index + 12 : index + 12 + 16] if trailing else b""
    return trailing, True, preview


def _riff_declared_size(path: Path) -> Optional[int]:
    head = _read_head(path, 12)
    if len(head) < 12 or head[0:4] != b"RIFF" or head[8:12] != b"WEBP":
        return None
    return struct.unpack("<I", head[4:8])[0] + 8


def _bmp_declared_size(path: Path) -> Optional[int]:
    head = _read_head(path, 26)
    if len(head) < 26 or head[0:2] != b"BM":
        return None
    return struct.unpack("<I", head[2:6])[0]


def _parse_png_header(head: bytes) -> Dict[str, Any]:
    if len(head) < 29 or head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return {}
    width, height = struct.unpack(">II", head[16:24])
    bit_depth = head[24]
    color_type = head[25]
    interlace = head[28]
    return {
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "color_model": _PNG_COLOR_TYPES.get(color_type, f"Unknown ({color_type})"),
        "interlace": bool(interlace),
    }


def _parse_exif_datetime(value: Any) -> Optional[datetime.datetime]:
    if value is None:
        return None
    text = str(value).strip()
    match = re.match(r"(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})", text)
    if not match:
        return None
    try:
        return datetime.datetime(
            int(match.group(1)), int(match.group(2)), int(match.group(3)),
            int(match.group(4)), int(match.group(5)), int(match.group(6)),
        )
    except ValueError:
        return None


def _safe_preview(data: bytes, limit: int = 16) -> str:
    """Hex preview of at most ``limit`` bytes; never interpreted as text."""
    return data[:limit].hex()


class FileAnalyzer:
    """Performs structural and consistency analysis on an image file."""

    def analyze(self, file_path: str | Path, scan: Any = None) -> FileAnalysis:
        path = Path(file_path)
        analysis = FileAnalysis()

        try:
            analysis.file_size = path.stat().st_size
        except OSError as exc:
            analysis.add(FileFinding(
                kind=FindingKind.CONFIRMED,
                code="file_unreadable",
                title="File could not be read",
                detail=str(exc),
                severity="HIGH",
            ))
            return analysis

        analysis.declared_extension = path.suffix.lower()
        magic = check_magic_bytes(path)
        analysis.detected_format = "TIFF" if magic and magic.startswith("TIFF") else magic
        head = _read_head(path, 64)

        # ---------------- Extension / MIME consistency ----------------
        if analysis.detected_format:
            allowed = _FORMAT_EXTENSIONS.get(analysis.detected_format, set())
            analysis.extension_matches = analysis.declared_extension in allowed
            if not analysis.extension_matches:
                analysis.add(FileFinding(
                    kind=FindingKind.CONFIRMED,
                    code="extension_mismatch",
                    title="File extension does not match detected format",
                    detail=(
                        f"Container signatures identify {analysis.detected_format}, but the file is "
                        f"named with the extension '{analysis.declared_extension or '(none)'}'."
                    ),
                    severity="MEDIUM",
                    evidence=f"magic={magic}, extension={analysis.declared_extension}",
                ))
        else:
            analysis.extension_matches = False
            analysis.add(FileFinding(
                kind=FindingKind.CONFIRMED,
                code="unknown_container",
                title="Unrecognized container signature",
                detail="The file header does not match any supported image signature.",
                severity="HIGH",
            ))

        analysis.mime_type = Image.MIME.get(analysis.detected_format or "")
        guessed, _ = mimetypes.guess_type(path.name)
        if analysis.mime_type and guessed and analysis.mime_type != guessed and analysis.extension_matches:
            analysis.add(FileFinding(
                kind=FindingKind.SUSPICIOUS,
                code="mime_mismatch",
                title="Extension-derived MIME type differs from detected MIME type",
                detail=f"Detected {analysis.mime_type}, extension suggests {guessed}.",
                severity="LOW",
            ))

        # ---------------- Pillow-level structure ----------------
        try:
            with Image.open(path) as img:
                img.load()
                analysis.dimensions = img.size
                analysis.color_mode = img.mode
                analysis.bit_depth = _MODE_BITS.get(img.mode)
                analysis.color_model = img.mode
                analysis.has_alpha = img.mode in ("RGBA", "LA", "PA") or (
                    img.mode == "P" and "transparency" in img.info
                )
                analysis.is_animated = bool(getattr(img, "is_animated", False))
                analysis.n_frames = int(getattr(img, "n_frames", 1) or 1)
                if analysis.is_animated:
                    for index in range(min(analysis.n_frames, 256)):
                        try:
                            img.seek(index)
                            analysis.frame_durations_ms.append(int(img.info.get("duration", 0) or 0))
                        except (EOFError, ValueError):
                            break
                    analysis.add(FileFinding(
                        kind=FindingKind.INFORMATIONAL,
                        code="animated_image",
                        title="Animated / multi-frame image",
                        detail=f"The file contains {analysis.n_frames} frames.",
                        severity="INFO",
                    ))

                icc = img.info.get("icc_profile")
                if icc:
                    analysis.has_icc_profile = True
                    analysis.icc_profile_bytes = len(icc) if hasattr(icc, "__len__") else 0
                    analysis.add(FileFinding(
                        kind=FindingKind.INFORMATIONAL,
                        code="icc_profile",
                        title="Embedded ICC colour profile",
                        detail=(
                            f"An ICC colour profile ({analysis.icc_profile_bytes} bytes) is embedded. "
                            "It describes colour management and is not personal metadata."
                        ),
                        severity="INFO",
                    ))
        except Exception as exc:  # Pillow failure must not crash analysis
            analysis.add(FileFinding(
                kind=FindingKind.CONFIRMED,
                code="decode_failure",
                title="Image could not be fully decoded",
                detail=f"Pillow raised: {exc}",
                severity="HIGH",
            ))

        # PNG-specific header values are more precise than Pillow's mode.
        if analysis.detected_format == "PNG":
            png = _parse_png_header(head)
            if png:
                analysis.dimensions = (png["width"], png["height"])
                analysis.bit_depth = png["bit_depth"]
                analysis.color_model = png["color_model"]
                analysis.structure_notes.append("PNG IHDR parsed directly from the file header.")
                if png["interlace"]:
                    analysis.structure_notes.append("PNG uses Adam7 interlacing.")

        # ---------------- Embedded previews / metadata groups ----------------
        if scan is not None:
            analysis.metadata_groups = dict(getattr(scan, "metadata_group_counts", {}) or {})
            for tag in getattr(scan, "image_metadata", {}).values():
                name = getattr(tag, "name", "")
                if name in {
                    "ThumbnailImage", "PreviewImage", "OtherImage", "JpgFromRaw",
                    "PreviewTIFF", "PreviewPDF",
                }:
                    analysis.embedded_thumbnail_tags.append(name)
            if analysis.embedded_thumbnail_tags:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="embedded_preview",
                    title="Embedded thumbnail or preview image present",
                    detail=(
                        "The file contains embedded preview data ("
                        + ", ".join(sorted(set(analysis.embedded_thumbnail_tags)))
                        + "). Previews can retain content that was cropped or removed from the main image."
                    ),
                    severity="MEDIUM",
                ))
            description = None
            for tag in getattr(scan, "image_metadata", {}).values():
                if getattr(tag, "name", "") in ("ProfileDescription", "ProfileDescriptionML"):
                    description = str(getattr(tag, "display_value", "") or "")[:120]
                    break
            analysis.icc_description = description

            # ExifTool warnings/limitations are reported as observations, not tags.
            for warning in list(getattr(scan, "warnings", []) or [])[:10]:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="metadata_parser_warning",
                    title="Metadata parser reported a warning",
                    detail=warning[:300],
                    severity="LOW",
                ))

        # ---------------- Trailing data after end marker ----------------
        trailing = 0
        eoi: Optional[bool] = None
        preview = b""
        if analysis.detected_format == "JPEG":
            trailing, found, preview = _trailing_bytes_jpeg(path, analysis.file_size)
            eoi = found
            analysis.end_marker_found = eoi
            if trailing:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="trailing_data_jpeg",
                    title="Data appended after JPEG end-of-image marker",
                    detail=(
                        f"{trailing} byte(s) follow the JPEG EOI marker. Appended data can be benign "
                        "(viewer metadata, container padding) or may hide a second payload. "
                        "MetaClean does not classify this as malicious by itself."
                    ),
                    severity="MEDIUM",
                    evidence=f"first_bytes_hex={_safe_preview(preview)}",
                ))
        elif analysis.detected_format == "PNG":
            trailing, found, preview = _trailing_bytes_png(path, analysis.file_size)
            eoi = found
            analysis.end_marker_found = eoi
            if trailing:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="trailing_data_png",
                    title="Data appended after PNG IEND chunk",
                    detail=(
                        f"{trailing} byte(s) follow the PNG IEND chunk. PNG decoders normally ignore "
                        "this data; it may contain hidden content or container padding."
                    ),
                    severity="MEDIUM",
                    evidence=f"first_bytes_hex={_safe_preview(preview)}",
                ))
        elif analysis.detected_format == "WEBP":
            declared = _riff_declared_size(path)
            if declared is not None:
                analysis.structure_notes.append(f"RIFF header declares {declared} bytes.")
                if analysis.file_size >= declared:
                    analysis.end_marker_found = True
                if analysis.file_size > declared:
                    trailing = analysis.file_size - declared
                    analysis.add(FileFinding(
                        kind=FindingKind.SUSPICIOUS,
                        code="trailing_data_webp",
                        title="Data beyond declared RIFF container size",
                        detail=f"{trailing} byte(s) exceed the size declared in the RIFF header.",
                        severity="MEDIUM",
                        evidence=f"declared_size={declared}, actual_size={analysis.file_size}",
                    ))
                elif analysis.file_size < declared:
                    analysis.add(FileFinding(
                        kind=FindingKind.SUSPICIOUS,
                        code="webp_size_mismatch",
                        title="WEBP file is smaller than declared RIFF size",
                        detail=(
                            f"The RIFF header declares {declared} bytes but the file on disk is "
                            f"{analysis.file_size} bytes; the container is truncated or corrupted."
                        ),
                        severity="HIGH",
                        evidence=f"declared_size={declared}, actual_size={analysis.file_size}",
                    ))
        elif analysis.detected_format == "BMP":
            declared = _bmp_declared_size(path)
            if declared is not None:
                analysis.structure_notes.append(f"BMP header declares {declared} bytes.")
                if analysis.file_size >= declared:
                    analysis.end_marker_found = True
                if analysis.file_size > declared:
                    trailing = analysis.file_size - declared
                    analysis.add(FileFinding(
                        kind=FindingKind.SUSPICIOUS,
                        code="trailing_data_bmp",
                        title="Data beyond declared BMP file size",
                        detail=f"{trailing} byte(s) exceed the size declared in the BMP header.",
                        severity="MEDIUM",
                        evidence=f"declared_size={declared}, actual_size={analysis.file_size}",
                    ))
                elif analysis.file_size < declared:
                    analysis.add(FileFinding(
                        kind=FindingKind.SUSPICIOUS,
                        code="bmp_size_mismatch",
                        title="BMP file is smaller than declared size",
                        detail=(
                            f"The BMP header declares {declared} bytes but the file on disk is "
                            f"{analysis.file_size} bytes; the container is truncated or corrupted."
                        ),
                        severity="HIGH",
                        evidence=f"declared_size={declared}, actual_size={analysis.file_size}",
                    ))

        analysis.trailing_data_bytes = trailing
        analysis.trailing_data_preview = _safe_preview(preview) if trailing else ""

        # ---------------- Metadata value safety / consistency ----------------
        if scan is not None:
            self._check_metadata_values(scan, analysis)
            self._check_timestamps(scan, analysis)

        return analysis

    # ------------------------------------------------------------------
    def _check_metadata_values(self, scan: Any, analysis: FileAnalysis) -> None:
        """Looks for control characters and active markup in text metadata."""
        active_markers = ("<script", "javascript:", "onerror=", "onload=", "data:text/html")
        checked = 0
        for tag in getattr(scan, "image_metadata", {}).values():
            if getattr(tag, "derived", False):
                continue
            if getattr(tag, "category", "") not in ("comments", "author", "copyright", "xmp", "iptc", "exif"):
                continue
            text = str(getattr(tag, "value", "") or "")
            if not text or len(text) > 10_000:
                continue
            checked += 1
            lowered = text.lower()
            if any(marker in lowered for marker in active_markers):
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="active_content_in_metadata",
                    title="Markup or script-like content inside metadata",
                    detail=(
                        f"Tag {getattr(tag, 'name', '?')} contains markup that may execute or render "
                        "unsafely in a downstream viewer. This is an indicator, not proof of intent."
                    ),
                    severity="MEDIUM",
                ))
            if "\x1b" in text:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="ansi_escape_in_metadata",
                    title="ANSI escape sequence inside metadata",
                    detail=(
                        f"Tag {getattr(tag, 'name', '?')} contains ESC control bytes, which can be used "
                        "to manipulate terminal output."
                    ),
                    severity="MEDIUM",
                ))
            if "\u202e" in text or "\u202d" in text:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="bidi_override_in_metadata",
                    title="Unicode bidirectional override inside metadata",
                    detail=(
                        f"Tag {getattr(tag, 'name', '?')} contains a bidirectional text override, which can "
                        "disguise filenames or strings in some interfaces."
                    ),
                    severity="LOW",
                ))
        if checked:
            analysis.structure_notes.append(f"{checked} free-text metadata value(s) screened for control content.")

    def _check_timestamps(self, scan: Any, analysis: FileAnalysis) -> None:
        """Compares capture and modification timestamps for contradictions."""
        values: Dict[str, Any] = {}
        for tag in getattr(scan, "image_metadata", {}).values():
            if getattr(tag, "derived", False):
                continue
            name = getattr(tag, "name", "").lower()
            if name in ("datetimeoriginal", "createdate", "modifydate"):
                values.setdefault(name, getattr(tag, "value", None))

        parsed = {name: _parse_exif_datetime(value) for name, value in values.items()}
        original = parsed.get("datetimeoriginal")
        created = parsed.get("createdate")
        modified = parsed.get("modifydate")
        now = datetime.datetime.now()

        for name, dt in parsed.items():
            if dt is None:
                continue
            if dt.year < 1970 or dt.year > now.year + 1:
                analysis.add(FileFinding(
                    kind=FindingKind.SUSPICIOUS,
                    code="implausible_timestamp",
                    title="Implausible metadata timestamp",
                    detail=f"{name} has the implausible value {dt.isoformat()}.",
                    severity="LOW",
                ))

        reference = original or created
        if reference and modified and modified < reference:
            analysis.add(FileFinding(
                kind=FindingKind.SUSPICIOUS,
                code="timestamp_order",
                title="Modification date precedes capture date",
                detail=(
                    f"ModifyDate ({modified.isoformat()}) is earlier than "
                    f"{'DateTimeOriginal' if original else 'CreateDate'} ({reference.isoformat()}). "
                    "This can indicate a clock error or metadata editing."
                ),
                severity="LOW",
            ))
        if original and created and abs((created - original).total_seconds()) > 86400:
            analysis.add(FileFinding(
                kind=FindingKind.INFORMATIONAL,
                code="timestamp_difference",
                title="Capture and creation dates differ by more than one day",
                detail=(
                    f"DateTimeOriginal ({original.isoformat()}) and CreateDate "
                    f"({created.isoformat()}) differ substantially; this is common after editing or export."
                ),
                severity="INFO",
            ))
