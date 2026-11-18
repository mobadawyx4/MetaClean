"""Image metadata extraction and organization scanner.

Extracts EXIF, GPS, IPTC, XMP, MakerNotes, ICC profiles, thumbnails and other
container metadata using ExifTool when available, with a reliable Pillow
fallback.  Filesystem timestamps are kept strictly separate from embedded
metadata.

Every tag records its metadata group, raw value (when available), human readable
value, inferred value type and an extraction status, so callers can distinguish
"tag absent" from "tag present but empty" from "extraction failed".
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PIL import ExifTags, Image

import config
from modules.exiftool_backend import ExifToolBackend
from modules.file_analyzer import FileAnalyzer
from modules.image_validator import ValidationResult, validate_image
from modules.privacy_analyzer import PrivacyReport, RuleBasedPrivacyAnalyzer

# Group families used for presentation and reporting.
_GROUP_FAMILIES: Tuple[Tuple[str, str], ...] = (
    ("ExifTool", "Tool"),
    ("System", "Filesystem"),
    ("File", "Container"),
    ("JFIF", "Container"),
    ("PNG", "Container"),
    ("RIFF", "Container"),
    ("Composite", "Derived"),
    ("GPS", "GPS"),
    ("ICC_Profile", "ICC"),
    ("MakerNotes", "MakerNotes"),
    ("IPTC", "IPTC"),
    ("XMP", "XMP"),
    ("IFD0", "EXIF"),
    ("IFD1", "EXIF"),
    ("ExifIFD", "EXIF"),
    ("InteropIFD", "EXIF"),
    ("SubIFD", "EXIF"),
    ("EXIF", "EXIF"),
)


def group_family(group: str) -> str:
    """Maps an ExifTool group name to a coarse family for display/reporting."""
    for prefix, family in _GROUP_FAMILIES:
        if group == prefix or group.startswith(prefix + "-"):
            return family
    if group.startswith("XMP"):
        return "XMP"
    if group.startswith("IPTC"):
        return "IPTC"
    return "Other"


def _infer_value_type(value: Any) -> str:
    """Infers a presentation-level type. Not an ExifTool schema type."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, (list, tuple)):
        return "list"
    if isinstance(value, dict):
        return "structure"
    text = str(value)
    if re.fullmatch(r"-?\d+", text):
        return "integer-string"
    if re.fullmatch(r"-?\d+\.\d+", text):
        return "decimal-string"
    if re.fullmatch(r"\d{4}:\d{2}:\d{2}[ T]\d{2}:\d{2}:\d{2}.*", text):
        return "datetime-string"
    if re.fullmatch(r"\d+/\d+", text):
        return "rational-string"
    return "string"


def _stringify(value: Any, limit: int = 2000) -> str:
    """Converts a metadata value to a safe display string."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(value)
    elif isinstance(value, bytes):
        text = value.hex()
    else:
        text = str(value)
    text = text.strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


@dataclass
class MetadataTag:
    """Represents a single detected metadata property."""

    name: str
    value: Any
    group: str
    category: str
    is_filesystem: bool = False
    display_value: Optional[str] = None
    raw_value: Optional[str] = None
    value_type: str = "unknown"
    extraction_status: str = "extracted"  # extracted | empty
    derived: bool = False  # True for ExifTool Composite tags
    key: str = ""

    def __post_init__(self) -> None:
        if self.display_value is None:
            self.display_value = _stringify(self.value)
        if not self.key:
            self.key = f"{self.group}:{self.name}"
        if self.value is None or _stringify(self.value) == "":
            self.extraction_status = "empty"

    @property
    def family(self) -> str:
        return group_family(self.group)


@dataclass
class CategorySummary:
    """Summary of a specific metadata category."""

    name: str
    description: str
    detected: bool
    tags: List[MetadataTag] = field(default_factory=list)


@dataclass
class GPSCoordinates:
    """Decoded and formatted geographic coordinates."""

    latitude: float
    longitude: float
    altitude: Optional[str] = None
    formatted: str = ""
    google_maps_url: str = ""
    openstreetmap_url: str = ""


@dataclass
class ScanResult:
    """Complete result of scanning an image for metadata."""

    file_path: Path
    validation: ValidationResult
    scanner_backend: str
    backend_version: Optional[str]
    filesystem_metadata: Dict[str, Any]
    image_metadata: Dict[str, MetadataTag]
    categories: Dict[str, CategorySummary]
    privacy_report: Optional[PrivacyReport] = None
    gps_coordinates: Optional[GPSCoordinates] = None
    limitations: List[str] = field(default_factory=list)
    uninspected_categories: List[str] = field(default_factory=list)
    mode: str = "standard"
    warnings: List[str] = field(default_factory=list)
    metadata_group_counts: Dict[str, int] = field(default_factory=dict)
    file_analysis: Any = None
    inspection_complete: bool = True

    @property
    def total_embedded_tags(self) -> int:
        return len(self.image_metadata)

    @property
    def empty_tag_count(self) -> int:
        return sum(1 for t in self.image_metadata.values() if t.extraction_status == "empty")

    def get_category_tags(self, category: str) -> List[MetadataTag]:
        cat_lower = category.lower()
        if cat_lower in self.categories:
            return self.categories[cat_lower].tags
        return []


class MetadataScanner:
    """Extracts, categorizes, and audits image metadata."""

    def __init__(self, exiftool_path: Optional[str] = None) -> None:
        if exiftool_path is not None:
            self.exiftool_path = exiftool_path
            self.exiftool_available = True
            self.exiftool_version = config.EXIFTOOL_VERSION
        else:
            self.exiftool_path = config.EXIFTOOL_PATH
            self.exiftool_available = config.EXIFTOOL_AVAILABLE
            self.exiftool_version = config.EXIFTOOL_VERSION

        self.backend = ExifToolBackend(
            path=self.exiftool_path,
            version=self.exiftool_version,
        )
        if not self.exiftool_available:
            self.backend.available = False
        self.privacy_analyzer = RuleBasedPrivacyAnalyzer()

    # ------------------------------------------------------------------
    # Filesystem attributes
    # ------------------------------------------------------------------
    def _get_filesystem_metadata(self, path: Path) -> Dict[str, Any]:
        """Reads OS filesystem timestamps and attributes, separated from EXIF."""
        try:
            stat_info = path.stat()
            return {
                "file_name": path.name,
                "file_size_bytes": stat_info.st_size,
                "fs_modified": datetime.datetime.fromtimestamp(
                    stat_info.st_mtime, tz=datetime.timezone.utc
                ).isoformat(),
                "fs_accessed": datetime.datetime.fromtimestamp(
                    stat_info.st_atime, tz=datetime.timezone.utc
                ).isoformat(),
                "fs_created": datetime.datetime.fromtimestamp(
                    stat_info.st_ctime, tz=datetime.timezone.utc
                ).isoformat(),
            }
        except OSError as exc:
            return {"error": f"Failed to retrieve filesystem metadata: {exc}"}

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    def _classify_tag(self, group: str, tag_name: str) -> Tuple[str, bool]:
        """Determines the semantic category of a tag and whether it is a filesystem property."""
        group_upper = group.upper()
        tag_lower = tag_name.lower()

        # ICC profiles are colour-management data, never personal metadata.
        if "ICC" in group_upper:
            return "informational", False

        if group_upper == "SYSTEM":
            return "filesystem", True

        if group_upper == "FILE" and any(
            k in tag_lower
            for k in (
                "filename", "directory", "filesize", "filemodifydate", "fileaccessdate",
                "filecreatedate", "filepermissions",
            )
        ):
            return "filesystem", True

        # Structural / technical informational tags (highest priority after ICC).
        # Camera composition settings such as SubjectDistance are included so a
        # broad "subject" match cannot route them into the comments category.
        if tag_lower in (
            "imagesize", "megapixels", "rotation", "jfifversion", "resolutionunit",
            "xresolution", "yresolution", "ycbcrpositioning", "ycbcrsubsampling",
            "orientation", "imageorientation", "colorspace", "exifversion",
            "flashpixversion", "interopversion", "exifbyteorder", "compression",
            "encodingprocess", "bitspersample", "colorcomponents",
            "photometricinterpretation", "samplesperpixel", "imagewidth",
            "imageheight", "bitdepth", "colortype", "interlace",
            "imageuniqueid", "currentiptcdigest", "filetype", "filetypeextension",
            "mimetype", "jpegqualityestimate", "jpegdigest", "jpegimagelength",
            "thumbnaillength", "thumbnailoffset", "subjectlocation",
            "subjectarea", "subjectdistance", "subjectdistancerange",
            "componentsconfiguration",
        ):
            if tag_lower == "imageuniqueid":
                return "identifiers", False
            return "informational", False

        # MakerNote blobs embedded in ordinary IFD0 groups.  Check before the
        # broad "note"/"comment" matching below so MakerNoteSafety and vendor
        # MakerNote* blobs are not reported as user comments.
        if tag_lower.startswith("makernote"):
            return "makernotes", False

        # Embedded thumbnails / previews.  Only content-bearing tags are
        # classified here; offset/length/size companions describe structure and
        # cannot be deleted safely on their own.
        thumbnail_content = {
            "thumbnailimage", "previewimage", "otherimage", "jpgfromraw",
            "thumbnailtiff", "previewtiff", "previewpdf", "thumbnailpng",
            "previewpng", "previewpict", "previewwmf", "thumbnailbpg",
            "photoshopthumbnail", "photoshopbgrthumbnail", "sanyothumbnail",
        }
        if tag_lower in thumbnail_content:
            return "thumbnail", False

        # Geographic positioning and textual location.  Explicit name sets are
        # used for city/state/country so unrelated fields (ClassifyState,
        # CreatorCity) are not mistaken for a place.  Coordinates in any group
        # (XMP-exif, XMP-iptcExt, XMP-Device) end with Latitude/Longitude.
        location_names = {
            "location", "sublocation", "sub-location", "locationname",
            "city", "city2", "state", "province-state", "country",
            "countrycode", "country-primarylocationcode",
            "country-primarylocationname", "contentlocationcode",
            "contentlocationname", "geography",
        }
        if (
            (
                group_upper == "GPS"
                or tag_lower.startswith(("gps", "location", "ratingregion", "earthpos"))
                or tag_lower in location_names
                or tag_lower.endswith(("latitude", "longitude", "coordinates"))
            )
            and "creator" not in tag_lower
        ):
            return "gps", False

        # Unique document/image identifiers.
        if tag_lower in {
            "documentid", "instanceid", "originaldocumentid", "versionid",
            "identifier", "imageuniqueid", "uniqueid", "photoidentifier",
        }:
            return "identifiers", False

        # MakerNotes blocks: serial/lens/model IDs are device identifiers.
        if "MAKERNOTE" in group_upper:
            if tag_lower.endswith(("model", "modelid", "modelname")) or any(
                k in tag_lower for k in ("serial", "lens", "firmware")
            ):
                return "device", False
            return "makernotes", False

        # Software / editing environment (before generic "creator" matching).
        if any(
            k in tag_lower
            for k in (
                "software", "creatortool", "processingsoftware", "xmptoolkit",
                "historysoftwareagent", "previewapplication", "creatorapp",
                "creatoropenwith",
            )
        ):
            return "software", False

        # Device / hardware identifiers.  Make/Model are exact matches so
        # GeoTIFF ModelTiePoint/ModelTransform and ModelAge are not classified
        # as camera hardware.
        device_exact = {
            "make", "model", "model2", "cameramodel", "uniquecameramodel",
            "localizedcameramodel", "xiaomimodel", "hostcomputer", "firmware",
            "camerafirmware", "cameramodelname",
        }
        if tag_lower in device_exact or tag_lower.endswith(
            ("model", "modelid", "modelname")
        ) or any(
            k in tag_lower for k in ("serial", "lens", "firmware", "device", "hostcomputer")
        ):
            return "device", False

        # Author / personal identity (including creator contact locations,
        # which are contact data rather than a scene location, and owner fields
        # such as OwnerName/CameraOwner/RightsOwner).
        author_exact = {
            "artist", "creator", "author", "ownername", "owner", "ownerid",
            "contact", "credit", "creditline", "source", "captionwriter",
            "writer-editor", "authorsposition", "creatorcontactinfo",
        }
        if (
            tag_lower in author_exact
            or tag_lower.startswith(("creator", "contributor", "by-line", "byline", "author"))
            or "ownername" in tag_lower
            or tag_lower.endswith(("owner", "ownerid"))
        ):
            return "author", False

        # Copyright / rights.
        if any(k in tag_lower for k in ("copyright", "rights", "usageterms", "webstatement")):
            return "copyright", False

        # Comments / descriptions.  Subject is matched exactly so camera
        # settings (SubjectArea/Distance/Location) stay informational.
        if any(
            k in tag_lower
            for k in (
                "comment", "description", "headline", "caption", "keyword",
                "notes", "instructions",
            )
        ) or tag_lower in {
            "subject", "xpsubject", "title", "xptitle", "objectname",
            "category", "supplementalcategories", "localcaption",
            "rasterizedcaption", "panasonictitle", "panasonictitle2",
        }:
            return "comments", False

        # Timestamps.  "date" and "timestamp" are safe substrings; a bare
        # "time" is not, because it would also match photographic settings such
        # as ExposureTime.  Named time fields are listed exactly so vendor
        # settings like Canon's ShortReleaseTimeLag are not treated as dates.
        if (
            any(
                k in tag_lower
                for k in (
                    "date", "timestamp", "subsectime", "offsettime",
                    "timezoneoffset", "timecode", "lastedited",
                )
            )
            or tag_lower
            in {
                "timecreated", "digitalcreationtime", "releasetime",
                "expirationtime", "timesent", "historywhen",
            }
        ):
            return "date", False

        if "IPTC" in group_upper:
            return "iptc", False

        if "XMP" in group_upper:
            return "xmp", False

        if group_upper in ("EXIF", "EXIFIFD", "IFD0", "IFD1", "SUBIFD", "INTEROP", "INTEROPIFD"):
            return "exif", False

        return "other", False

    # ------------------------------------------------------------------
    # ExifTool extraction
    # ------------------------------------------------------------------
    def _scan_with_exiftool(
        self, path: Path, mode: str = "standard"
    ) -> Tuple[Dict[str, MetadataTag], List[str], List[str], Dict[str, Any], bool]:
        """Uses ExifTool to extract structured metadata.

        Returns:
            (tags, limitations, warnings, raw_values, read_succeeded)
        """
        tags: Dict[str, MetadataTag] = {}
        limitations: List[str] = []
        warnings: List[str] = []

        structured = mode in ("deep", "privacy", "full")
        numeric = mode in ("deep", "privacy", "full")
        exhaustive = mode == "full"

        result = self.backend.read_tags(
            path, structured=structured, numeric=numeric, exhaustive=exhaustive
        )
        if not result.ok and not result.tags:
            limitations.extend(result.errors or ["ExifTool metadata extraction failed."])
            return tags, limitations, warnings, result.raw_tags, False

        limitations.extend(result.errors)
        warnings.extend(result.warnings)

        for full_key, value in result.tags.items():
            if ":" in full_key:
                group, tag_name = full_key.split(":", 1)
            else:
                # ExifTool emits "SourceFile" without a group.
                continue

            if group == "ExifTool":
                continue  # tool version/timing/guid output, not image metadata
            if group == "System":
                continue  # filesystem attributes handled separately

            category, is_fs = self._classify_tag(group, tag_name)
            if is_fs:
                continue

            raw = result.raw_tags.get(full_key)
            display = _stringify(value)
            raw_str = _stringify(raw) if raw is not None else None
            tags[full_key] = MetadataTag(
                name=tag_name,
                value=value,
                group=group,
                category=category,
                is_filesystem=is_fs,
                display_value=display,
                raw_value=raw_str,
                value_type=_infer_value_type(raw if raw is not None else value),
                derived=(group == "Composite"),
                key=full_key,
            )

        if mode == "full" and not tags:
            limitations.append(
                "Full inspection mode found no tags; embedded file extraction may be unsupported for this format."
            )

        # A read that reported errors (even with partial tags) is not a complete inspection.
        return tags, limitations, warnings, result.raw_tags, result.ok and not result.errors

    # ------------------------------------------------------------------
    # Pillow fallback
    # ------------------------------------------------------------------
    def _scan_with_pillow(self, path: Path) -> Tuple[Dict[str, MetadataTag], List[str], List[str]]:
        """Fallback metadata scanner using Pillow when ExifTool is not installed."""
        tags: Dict[str, MetadataTag] = {}
        warnings: List[str] = []
        limitations = [
            "ExifTool is unavailable; scanned using Pillow fallback engine.",
            "Deep XMP structures, IPTC application records, and proprietary MakerNotes cannot be fully inspected.",
            "Verification results are limited under the fallback engine.",
        ]

        def add(group: str, name: str, value: Any) -> None:
            category, is_fs = self._classify_tag(group, name)
            key = f"{group}:{name}"
            tags[key] = MetadataTag(
                name=name,
                value=value,
                group=group,
                category=category,
                is_filesystem=is_fs,
                key=key,
            )

        try:
            with Image.open(path) as img:
                exif_data = img.getexif()
                if exif_data:
                    for tag_id, val in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04x}")
                        add("EXIF", tag_name, val)

                    # Exif SubIFD (0x8769)
                    try:
                        sub_ifd = exif_data.get_ifd(0x8769)
                        for tag_id, val in sub_ifd.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"ExifSub_0x{tag_id:04x}")
                            add("ExifIFD", tag_name, val)
                    except Exception:
                        warnings.append("Pillow could not read the EXIF SubIFD.")

                    # GPS IFD (0x8825)
                    try:
                        gps_ifd = exif_data.get_ifd(0x8825)
                        for tag_id, val in gps_ifd.items():
                            tag_name = ExifTags.GPSTAGS.get(tag_id, f"GPS_0x{tag_id:04x}")
                            add("GPS", tag_name, val)
                    except Exception:
                        warnings.append("Pillow could not read the GPS IFD.")

                # General img.info (XMP, comments, ICC profile presence)
                for info_key, info_val in img.info.items():
                    key_str = str(info_key)
                    if key_str == "exif":
                        continue
                    if key_str == "icc_profile":
                        add("ICC_Profile", "ICCProfile", f"(present, {len(info_val)} bytes)"
                            if isinstance(info_val, (bytes, bytearray)) else info_val)
                        continue
                    if key_str == "xmp":
                        add("XMP", "XMPPacket", info_val)
                        continue
                    add("Info", key_str, info_val)

        except Exception as exc:
            limitations.append(f"Pillow metadata extraction encountered an error: {exc}")

        return tags, limitations, warnings

    # ------------------------------------------------------------------
    # GPS decoding
    # ------------------------------------------------------------------
    def _parse_coordinate(self, val: Any, ref: str = "N") -> Optional[float]:
        """Parses DMS string, decimal number, or rational tuple into decimal degrees."""
        if val is None:
            return None
        ref_clean = str(ref).strip().upper()
        negative = ref_clean in ("S", "W", "SOUTH", "WEST")

        if isinstance(val, (int, float)):
            v = float(val)
            return -abs(v) if negative else v

        if isinstance(val, (list, tuple)) and len(val) >= 3:
            try:
                def _to_f(x: Any) -> float:
                    if isinstance(x, (tuple, list)) and len(x) == 2:
                        return float(x[0]) / float(x[1]) if x[1] != 0 else 0.0
                    return float(x)

                d, m, s = _to_f(val[0]), _to_f(val[1]), _to_f(val[2])
                dec = d + (m / 60.0) + (s / 3600.0)
                return -dec if negative else dec
            except (TypeError, ValueError, ZeroDivisionError):
                return None

        if isinstance(val, str):
            s = val.strip()
            try:
                dec = float(s.replace("deg", "").replace("°", "").strip())
                return -abs(dec) if negative else dec
            except ValueError:
                pass
            match = re.search(
                r"(-?\d+(?:\.\d+)?)\s*(?:deg|°)?\s*(\d+(?:\.\d+)?)?['′]?\s*(\d+(?:\.\d+)?)?[\"″]?\s*([NSEW])?",
                s,
                re.IGNORECASE,
            )
            if match:
                d = float(match.group(1))
                minute = float(match.group(2) or 0.0)
                sec = float(match.group(3) or 0.0)
                direction = (match.group(4) or ref_clean).upper()
                dec = abs(d) + (minute / 60.0) + (sec / 3600.0)
                return -dec if direction in ("S", "W", "SOUTH", "WEST") else dec

        return None

    def _extract_gps_coordinates(
        self,
        tags: Dict[str, MetadataTag],
        raw_tags: Optional[Dict[str, Any]] = None,
    ) -> Optional[GPSCoordinates]:
        """Extracts latitude, longitude, and altitude and formats a readable location."""
        raw_tags = raw_tags or {}
        lat_val = raw_tags.get("GPS:GPSLatitude")
        lon_val = raw_tags.get("GPS:GPSLongitude")
        lat_ref = "N"
        lon_ref = "E"
        alt_str: Optional[str] = None

        for key, tag in tags.items():
            if tag.derived:
                continue
            name_lower = tag.name.lower()
            if name_lower == "gpslatituderef":
                lat_ref = str(tag.value).strip()
            elif name_lower == "gpslongituderef":
                lon_ref = str(tag.value).strip()
            elif name_lower == "gpsaltitude" and alt_str is None:
                alt_str = _stringify(tag.value)
            elif name_lower == "gpslatitude" and lat_val is None:
                lat_val = tag.value
            elif name_lower == "gpslongitude" and lon_val is None:
                lon_val = tag.value

        # Fallback: Composite:GPSPosition ("lat lon" or "lat, lon").
        if (lat_val is None or lon_val is None) and "Composite:GPSPosition" in tags:
            position = _stringify(tags["Composite:GPSPosition"].value)
            parts = re.split(r"\s*,\s*|\s+", position)
            if len(parts) >= 2:
                lat_val = lat_val if lat_val is not None else parts[0]
                lon_val = lon_val if lon_val is not None else parts[1]

        if lat_val is None or lon_val is None:
            return None

        lat = self._parse_coordinate(lat_val, lat_ref)
        lon = self._parse_coordinate(lon_val, lon_ref)
        if lat is None or lon is None:
            return None
        # Reject impossible coordinates rather than displaying fabricated data.
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            return None

        lat_dir = "N" if lat >= 0 else "S"
        lon_dir = "E" if lon >= 0 else "W"
        formatted = f"{abs(lat):.6f}° {lat_dir}, {abs(lon):.6f}° {lon_dir}"
        gmaps = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
        osm = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"
        return GPSCoordinates(
            latitude=lat,
            longitude=lon,
            altitude=alt_str,
            formatted=formatted,
            google_maps_url=gmaps,
            openstreetmap_url=osm,
        )

    # ------------------------------------------------------------------
    # Public scan entry point
    # ------------------------------------------------------------------
    def scan(self, file_path: str | Path, mode: str = "standard") -> ScanResult:
        """Executes a metadata scan and risk analysis on an image.

        Args:
            file_path: Image to scan.
            mode: One of ``standard``, ``deep``, ``privacy`` or ``full``.
        """
        if mode not in config.SCAN_MODES:
            mode = "standard"

        val_res = validate_image(file_path)
        path = val_res.file_path
        fs_meta = self._get_filesystem_metadata(path)

        if not val_res.is_valid:
            return ScanResult(
                file_path=path,
                validation=val_res,
                scanner_backend="none",
                backend_version=None,
                filesystem_metadata=fs_meta,
                image_metadata={},
                categories={},
                limitations=["Validation failed: Image cannot be inspected."],
                mode=mode,
                inspection_complete=False,
            )

        warnings: List[str] = []
        raw_map: Dict[str, Any] = {}
        if self.exiftool_available and self.exiftool_path:
            backend = "exiftool"
            version = self.exiftool_version
            image_tags, limitations, warnings, raw_map, inspection_complete = (
                self._scan_with_exiftool(path, mode)
            )
            uninspected: List[str] = []
            if mode != "full":
                uninspected.append(
                    "Embedded-file extraction (-ee) not enabled; run with --full for exhaustive inspection."
                )
        else:
            backend = "pillow_fallback"
            version = None
            image_tags, limitations, warnings = self._scan_with_pillow(path)
            uninspected = ["iptc", "xmp_advanced", "makernotes", "embedded_previews"]
            # Pillow cannot inspect IPTC/XMP/MakerNotes, so the scan is incomplete.
            inspection_complete = False

        # Organize into category summaries.
        category_summaries: Dict[str, CategorySummary] = {}
        for cat_key, cat_def in config.METADATA_CATEGORIES.items():
            if cat_key == "all":
                continue
            category_summaries[cat_key] = CategorySummary(
                name=cat_key,
                description=str(cat_def["description"]),
                detected=False,
                tags=[],
            )

        for tag_item in image_tags.values():
            if tag_item.category in category_summaries:
                category_summaries[tag_item.category].tags.append(tag_item)
                category_summaries[tag_item.category].detected = True

        # Privacy analysis operates on real (non-derived) tags.
        privacy_report = self.privacy_analyzer.analyze_tags(
            list(image_tags.values()), mode=mode
        )

        # The numeric values from the ExifTool pass are used for accurate GPS decoding.
        gps_coords = self._extract_gps_coordinates(image_tags, raw_map)

        group_counts: Dict[str, int] = {}
        for tag in image_tags.values():
            family = tag.family
            group_counts[family] = group_counts.get(family, 0) + 1

        scan_result = ScanResult(
            file_path=path,
            validation=val_res,
            scanner_backend=backend,
            backend_version=version,
            filesystem_metadata=fs_meta,
            image_metadata=image_tags,
            categories=category_summaries,
            privacy_report=privacy_report,
            gps_coordinates=gps_coords,
            limitations=limitations,
            uninspected_categories=uninspected,
            mode=mode,
            warnings=warnings,
            metadata_group_counts=group_counts,
            inspection_complete=inspection_complete,
        )

        # Deep/privacy/full modes also inspect the physical container.
        if mode in ("deep", "privacy", "full"):
            try:
                scan_result.file_analysis = FileAnalyzer().analyze(path, scan=scan_result)
            except Exception as exc:  # analysis must never break a scan
                scan_result.limitations.append(f"Deep file analysis failed: {exc}")

        return scan_result
