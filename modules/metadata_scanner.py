"""Image metadata extraction and organization scanner.

Extracts EXIF, GPS, IPTC, XMP, comments, and maker notes using ExifTool
when available, with a reliable Pillow fallback. Separates filesystem timestamps
from embedded image metadata.
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PIL import ExifTags, Image

import config
from modules.image_validator import ValidationResult, validate_image
from modules.privacy_analyzer import PrivacyReport, RuleBasedPrivacyAnalyzer


@dataclass
class MetadataTag:
    """Represents a single detected metadata property."""
    name: str
    value: Any
    group: str
    category: str
    is_filesystem: bool = False
    display_value: Optional[str] = None

    def __post_init__(self) -> None:
        if self.display_value is None:
            self.display_value = str(self.value)


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

    @property
    def total_embedded_tags(self) -> int:
        return len(self.image_metadata)

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

        self.privacy_analyzer = RuleBasedPrivacyAnalyzer()

    def _get_filesystem_metadata(self, path: Path) -> Dict[str, Any]:
        """Reads OS filesystem timestamps and attributes, strictly separated from image EXIF."""
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
        except OSError as e:
            return {"error": f"Failed to retrieve filesystem metadata: {e}"}

    def _classify_tag(self, group: str, tag_name: str) -> Tuple[str, bool]:
        """Determines the semantic category of a tag and whether it is a filesystem property."""
        group_upper = group.upper()
        tag_lower = tag_name.lower()

        # Filesystem attributes
        if group_upper == "SYSTEM":
            return "filesystem", True

        if group_upper == "FILE" and any(k in tag_lower for k in ("filename", "directory", "filesize", "filemodifydate", "fileaccessdate", "filecreatedate", "filepermissions")):
            return "filesystem", True

        # Informational geometry, sampling, and format markers (PRIORITY to avoid false positives)
        if tag_lower in (
            "imagesize", "megapixels", "rotation", "jfifversion", "resolutionunit",
            "xresolution", "yresolution", "ycbcrpositioning", "ycbcrsubsampling",
            "orientation", "colorspace", "exifversion", "flashpixversion", "interopversion"
        ):
            return "informational", False

        # Technical Camera Settings & Exposure Parameters
        if tag_lower in (
            "exposuretime", "lightsource", "fnumber", "aperture", "iso", "shutterspeed",
            "focallength", "whitebalance", "flash", "meteringmode", "exposureprogram",
            "exposurecompensation", "maxaperturevalue", "scenetype", "scenecapturetype",
            "sensingmethod", "digitalzoomratio", "gaincontrol", "contrast", "saturation", "sharpness"
        ):
            return "exif", False

        # GPS Category (Only actual GPS coordinates / positioning)
        if group_upper == "GPS" or tag_lower.startswith("gps") or any(k in tag_lower for k in ("latitude", "longitude", "altitude", "coordinates", "gpsposition")):
            return "gps", False

        # Date / Timestamp Category
        if any(k in tag_lower for k in ("datetime", "createdate", "modifydate", "timestamp", "subsectime", "offsettime", "historywhen", "digitalcreation")):
            return "date", False

        # Device Category
        if any(k in tag_lower for k in ("make", "model", "serial", "lens", "software", "firmware", "device", "hostcomputer")):
            return "device", False

        # Author / Creator
        if any(k in tag_lower for k in ("artist", "creator", "by-line", "author", "ownername", "creatorcontactinfo")) or (tag_lower in ("credit", "source", "owner")):
            return "author", False

        # Copyright
        if any(k in tag_lower for k in ("copyright", "rights", "usageterms", "webstatement")):
            return "copyright", False

        # Comments
        if any(k in tag_lower for k in ("comment", "description", "note", "headline", "caption", "xpcomment")):
            return "comments", False

        # IPTC Block
        if "IPTC" in group_upper:
            return "iptc", False

        # XMP Block
        if "XMP" in group_upper:
            return "xmp", False

        # Standard EXIF Technical properties
        if group_upper in ("EXIF", "EXIFIFD", "IFD0", "SUBIFD", "INTEROP"):
            return "exif", False

        return "other", False

    def _scan_with_exiftool(self, path: Path) -> Tuple[Dict[str, MetadataTag], List[str]]:
        """Uses ExifTool subprocess to extract structured metadata."""
        tags: Dict[str, MetadataTag] = {}
        limitations: List[str] = []

        cmd = [
            str(self.exiftool_path),
            "-json",
            "-a",   # duplicate tags
            "-u",   # unknown tags
            "-G1",  # group 1 names (EXIF, IPTC, XMP, GPS, System, etc.)
            str(path)
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SUBPROCESS_TIMEOUT_SECONDS,
                check=False
            )
        except subprocess.TimeoutExpired:
            limitations.append(f"ExifTool scan timed out after {config.SUBPROCESS_TIMEOUT_SECONDS}s.")
            return tags, limitations
        except OSError as e:
            limitations.append(f"Failed to execute ExifTool: {e}")
            return tags, limitations

        if res.returncode != 0:
            limitations.append(f"ExifTool returned non-zero code {res.returncode}: {res.stderr.strip()}")
            return tags, limitations

        try:
            records = json.loads(res.stdout)
            if not records or not isinstance(records, list):
                limitations.append("ExifTool returned empty or invalid JSON array.")
                return tags, limitations
            raw_dict = records[0]
        except (json.JSONDecodeError, IndexError) as e:
            limitations.append(f"Failed to parse ExifTool JSON: {e}")
            return tags, limitations

        for full_key, value in raw_dict.items():
            if ":" in full_key:
                group, tag_name = full_key.split(":", 1)
            else:
                group = "General"
                tag_name = full_key

            # Skip tool metadata
            if tag_name.lower() in ("exiftoolversion", "sourcefile"):
                continue

            category, is_fs = self._classify_tag(group, tag_name)
            if not is_fs:
                tags[full_key] = MetadataTag(
                    name=tag_name,
                    value=value,
                    group=group,
                    category=category,
                    is_filesystem=is_fs,
                )

        return tags, limitations

    def _scan_with_pillow(self, path: Path) -> Tuple[Dict[str, MetadataTag], List[str]]:
        """Fallback metadata scanner using Pillow when ExifTool is not installed."""
        tags: Dict[str, MetadataTag] = {}
        limitations = [
            "ExifTool is unavailable; scanned using Pillow fallback engine.",
            "Deep XMP structures, IPTC application records, and proprietary MakerNotes cannot be fully inspected."
        ]

        try:
            with Image.open(path) as img:
                # 1. Standard EXIF
                exif_data = img.getexif()
                if exif_data:
                    # Root IFD
                    for tag_id, val in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04x}")
                        cat, is_fs = self._classify_tag("EXIF", tag_name)
                        tags[f"EXIF:{tag_name}"] = MetadataTag(
                            name=tag_name,
                            value=val,
                            group="EXIF",
                            category=cat,
                            is_filesystem=is_fs,
                        )

                    # Exif SubIFD (0x8769)
                    try:
                        sub_ifd = exif_data.get_ifd(0x8769)
                        for tag_id, val in sub_ifd.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"ExifSub_0x{tag_id:04x}")
                            cat, is_fs = self._classify_tag("ExifIFD", tag_name)
                            tags[f"ExifIFD:{tag_name}"] = MetadataTag(
                                name=tag_name,
                                value=val,
                                group="ExifIFD",
                                category=cat,
                                is_filesystem=is_fs,
                            )
                    except Exception:
                        pass

                    # GPS IFD (0x8825)
                    try:
                        gps_ifd = exif_data.get_ifd(0x8825)
                        for tag_id, val in gps_ifd.items():
                            tag_name = ExifTags.GPSTAGS.get(tag_id, f"GPS_0x{tag_id:04x}")
                            cat, is_fs = self._classify_tag("GPS", tag_name)
                            tags[f"GPS:{tag_name}"] = MetadataTag(
                                name=tag_name,
                                value=val,
                                group="GPS",
                                category="gps",
                                is_filesystem=is_fs,
                            )
                    except Exception:
                        pass

                # 2. General img.info (XMP, comments, icc)
                for info_key, info_val in img.info.items():
                    key_str = str(info_key)
                    if key_str in ("exif", "icc_profile"):
                        continue
                    cat, is_fs = self._classify_tag("Info", key_str)
                    tags[f"Info:{key_str}"] = MetadataTag(
                        name=key_str,
                        value=info_val,
                        group="Info",
                        category=cat,
                        is_filesystem=is_fs,
                    )

        except Exception as e:
            limitations.append(f"Pillow metadata extraction encountered an error: {e}")

        return tags, limitations

    def _parse_coordinate(self, val: Any, ref: str = "N") -> Optional[float]:
        """Parses DMS string, decimal number, or rational tuple into decimal degrees."""
        if val is None:
            return None
        ref_clean = str(ref).strip().upper()
        if isinstance(val, (int, float)):
            v = float(val)
            return -abs(v) if ref_clean in ("S", "W", "SOUTH", "WEST") else v

        if isinstance(val, (list, tuple)) and len(val) >= 3:
            try:
                def _to_f(x):
                    if isinstance(x, (tuple, list)) and len(x) == 2:
                        return float(x[0]) / float(x[1]) if x[1] != 0 else 0.0
                    return float(x)
                d = _to_f(val[0])
                m = _to_f(val[1])
                s = _to_f(val[2])
                dec = d + (m / 60.0) + (s / 3600.0)
                return -dec if ref_clean in ("S", "W", "SOUTH", "WEST") else dec
            except Exception:
                return None

        if isinstance(val, str):
            s = val.strip()
            # Try plain float
            try:
                dec = float(s.replace("deg", "").replace("°", "").strip())
                return -abs(dec) if ref_clean in ("S", "W", "SOUTH", "WEST") else dec
            except ValueError:
                pass
            m = re.search(
                r"(\d+(?:\.\d+)?)\s*(?:deg|°)?\s*(\d+(?:\.\d+)?)?['′]?\s*(\d+(?:\.\d+)?)?[\"″]?\s*([NSEW])?",
                s,
                re.IGNORECASE,
            )
            if m:
                d = float(m.group(1))
                minute = float(m.group(2) or 0.0)
                sec = float(m.group(3) or 0.0)
                direction = m.group(4) or ref_clean
                dec = d + (minute / 60.0) + (sec / 3600.0)
                return -dec if direction.upper() in ("S", "W", "SOUTH", "WEST") else dec

        return None

    def _extract_gps_coordinates(self, tags: Dict[str, MetadataTag]) -> Optional[GPSCoordinates]:
        """Extracts latitude, longitude, and altitude and formats human-readable location."""
        lat_val = None
        lat_ref = "N"
        lon_val = None
        lon_ref = "E"
        alt_str = None

        for k, tag in tags.items():
            name_lower = tag.name.lower()
            val = tag.value
            if "latituderef" in name_lower:
                lat_ref = str(val).strip()
            elif "longituderef" in name_lower:
                lon_ref = str(val).strip()
            elif "altitude" in name_lower and not alt_str:
                alt_str = str(val).strip()
            elif name_lower == "gpslatitude" or (name_lower == "latitude" and lat_val is None):
                if lat_val is None or "composite" in k.lower():
                    lat_val = val
            elif name_lower == "gpslongitude" or (name_lower == "longitude" and lon_val is None):
                if lon_val is None or "composite" in k.lower():
                    lon_val = val

        if lat_val is not None and lon_val is not None:
            lat = self._parse_coordinate(lat_val, lat_ref)
            lon = self._parse_coordinate(lon_val, lon_ref)
            if lat is not None and lon is not None:
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
        return None

    def scan(self, file_path: str | Path) -> ScanResult:
        """Executes a full metadata scan and risk analysis on an image."""
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
            )

        # Choose backend
        if self.exiftool_available and self.exiftool_path:
            backend = "exiftool"
            version = self.exiftool_version
            image_tags, limitations = self._scan_with_exiftool(path)
            uninspected: List[str] = []
        else:
            backend = "pillow_fallback"
            version = None
            image_tags, limitations = self._scan_with_pillow(path)
            uninspected = ["iptc", "xmp_advanced", "makernotes"]

        # Organize into categories
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

        # Categorize detected tags
        for tag_item in image_tags.values():
            cat = tag_item.category
            if cat in category_summaries:
                category_summaries[cat].tags.append(tag_item)
                category_summaries[cat].detected = True
            elif cat in ("exif", "other"):
                # Check if tag is device or date or gps
                pass

        # Perform privacy analysis
        raw_dict = {k: v.value for k, v in image_tags.items()}
        privacy_report = self.privacy_analyzer.analyze(raw_dict)

        # Extract decoded GPS coordinates
        gps_coords = self._extract_gps_coordinates(image_tags)

        return ScanResult(
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
        )
