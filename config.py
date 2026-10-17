"""Configuration settings, constants, and tool resolvers for MetaClean.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Application Info
APP_NAME = "MetaClean"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Comprehensive Image Metadata Scanner, Privacy Risk Analyzer, and Sanitizer CLI"

# Exit Codes
EXIT_SUCCESS = 0
EXIT_WARNING = 1
EXIT_FAIL = 2
EXIT_USAGE_ERROR = 3

# Security & Processing Constraints
DEFAULT_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_FILE_SIZE_BYTES = int(os.environ.get("METACLEAN_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE_BYTES))
MAX_IMAGE_PIXELS = int(os.environ.get("METACLEAN_MAX_PIXELS", 100_000_000))  # 100 MP limit
SUBPROCESS_TIMEOUT_SECONDS = int(os.environ.get("METACLEAN_TIMEOUT", 30))

# Supported Image Formats and Extensions
SUPPORTED_EXTENSIONS: Set[str] = {
    ".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp"
}

# Magic Signatures for Header Validation
FILE_SIGNATURES: Dict[str, List[Tuple[bytes, int]]] = {
    "JPEG": [(b"\xff\xd8\xff", 0)],
    "PNG": [(b"\x89PNG\r\n\x1a\n", 0)],
    "TIFF_LE": [(b"II\x2a\x00", 0)],
    "TIFF_BE": [(b"MM\x00\x2a", 0)],
    "WEBP": [(b"RIFF", 0), (b"WEBP", 8)],
    "BMP": [(b"BM", 0)],
}

# Metadata Categories and Target Tag Patterns
METADATA_CATEGORIES: Dict[str, Dict[str, object]] = {
    "gps": {
        "description": "Geographic positioning data (coordinates, altitude, speed, track)",
        "risk_level": "HIGH",
        "exiftool_args": ["-GPS:all="],
        "tags": [
            "GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSPosition",
            "GPSLatitudeRef", "GPSLongitudeRef", "GPSAltitudeRef",
            "GPSTimeStamp", "GPSDateStamp", "GPSDestLatitude",
            "GPSDestLongitude", "GPSProcessingMethod", "GPSAreaInformation"
        ],
    },
    "date": {
        "description": "Capture, creation, modification, and digitization timestamps",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-DateTimeOriginal=", "-CreateDate=", "-ModifyDate=",
            "-SubSecTimeOriginal=", "-SubSecTimeDigitized=", "-SubSecTime=",
            "-HistoryWhen="
        ],
        "tags": [
            "DateTimeOriginal", "CreateDate", "ModifyDate",
            "SubSecTimeOriginal", "SubSecTimeDigitized", "SubSecTime",
            "OffsetTime", "OffsetTimeOriginal", "OffsetTimeDigitized",
            "DigitalCreationDate", "DigitalCreationTime", "HistoryWhen"
        ],
    },
    "device": {
        "description": "Hardware and software identifiers (camera make/model, serial numbers, lens, software)",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-Make=", "-Model=", "-SerialNumber=", "-InternalSerialNumber=",
            "-CameraSerialNumber=", "-LensMake=", "-LensModel=",
            "-LensSerialNumber=", "-Software=", "-Firmware="
        ],
        "tags": [
            "Make", "Model", "SerialNumber", "InternalSerialNumber",
            "CameraSerialNumber", "LensMake", "LensModel", "LensSerialNumber",
            "Software", "Firmware", "DeviceSettingDescription", "HostComputer"
        ],
    },
    "author": {
        "description": "Personal identity info, creator, artist, owner, and contact data",
        "risk_level": "HIGH",
        "exiftool_args": [
            "-Artist=", "-Creator=", "-By-line=", "-Author=", "-OwnerName=",
            "-Contact=", "-Credit=", "-Source=", "-CaptionWriter="
        ],
        "tags": [
            "Artist", "Creator", "By-line", "Author", "OwnerName", "Contact",
            "Credit", "Source", "CaptionWriter", "CreatorContactInfo"
        ],
    },
    "copyright": {
        "description": "Copyright notices, usage rights, and licensing terms",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-Copyright=", "-CopyrightNotice=", "-Rights=", "-UsageTerms=", "-WebStatement="
        ],
        "tags": [
            "Copyright", "CopyrightNotice", "Rights", "UsageTerms", "WebStatement"
        ],
    },
    "comments": {
        "description": "User comments, descriptions, notes, and custom text annotations",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-Comment=", "-UserComment=", "-ImageDescription=",
            "-Description=", "-XPComment=", "-Notes="
        ],
        "tags": [
            "Comment", "UserComment", "ImageDescription", "Description",
            "XPComment", "XPKeywords", "Notes", "Headline"
        ],
    },
    "exif": {
        "description": "Standard Exchangeable Image File Format metadata block",
        "risk_level": "VARIES",
        "exiftool_args": ["-exif:all="],
        "tags": ["*EXIF*"],
    },
    "iptc": {
        "description": "International Press Telecommunications Council metadata block",
        "risk_level": "VARIES",
        "exiftool_args": ["-iptc:all="],
        "tags": ["*IPTC*"],
    },
    "xmp": {
        "description": "Extensible Metadata Platform XML metadata block",
        "risk_level": "VARIES",
        "exiftool_args": ["-xmp:all="],
        "tags": ["*XMP*"],
    },
    "all": {
        "description": "All supported metadata structures (EXIF, GPS, IPTC, XMP, Comments, Thumbnails)",
        "risk_level": "ALL",
        "exiftool_args": ["-all=", "-tagsFromFile", "@", "-ColorSpaceTags"],
        "tags": ["*ALL*"],
    },
}

# Privacy Risk Categories and Rules
RISK_RULES: Dict[str, Dict[str, object]] = {
    "HIGH": {
        "description": "High Privacy Risk: Directly identifies location or person (threat of physical stalking or deanonymization).",
        "patterns": [
            "gps", "latitude", "longitude", "altitude", "gpsposition", "coordinates", "coord",
            "artist", "creator", "author", "ownername", "by-line", "faceinfo", "creatorcontactinfo"
        ],
    },
    "MEDIUM": {
        "description": "Medium Privacy Risk: Indirectly identifying or correlatable data (exact timestamps, hardware serials, device models).",
        "patterns": [
            "datetime", "createdate", "modifydate", "timestamp", "subsectime", "offsettime",
            "serial", "model", "lens", "software", "firmware", "comment", "description",
            "copyright", "documentid", "historywhen", "thumbnail"
        ],
    },
    "LOW": {
        "description": "Low Privacy Risk: Technical shooting parameters with minimal personal privacy impact.",
        "patterns": [
            "iso", "fnumber", "aperture", "shutterspeed", "exposuretime", "exposureprogram",
            "exposurecompensation", "maxaperturevalue", "focallength", "whitebalance",
            "lightsource", "flash", "meteringmode", "sensingmethod", "scenetype", "scenecapturetype"
        ],
    },
    "INFORMATIONAL": {
        "description": "Informational: Purely technical image dimensions, color profiles, or encoding parameters.",
        "patterns": [
            "imagewidth", "imageheight", "bitspersample", "colortype", "colorspace",
            "compression", "photometricinterpretation", "resolution", "xresolution",
            "yresolution", "samplesperpixel", "mimetype", "filesize", "filetype",
            "ycbcrpositioning", "ycbcrsubsampling", "orientation", "exifversion", "flashpixversion"
        ],
    },
}


def find_exiftool() -> Tuple[Optional[str], Optional[str]]:
    """Detects and resolves the ExifTool binary and its version.

    Checks:
    1. METACLEAN_EXIFTOOL or EXIFTOOL_PATH environment variables.
    2. System PATH (via shutil.which).
    3. Standard Linux Mint / Ubuntu installation paths.
    4. Standard Windows installation paths.

    Returns:
        Tuple of (path_to_binary, version_string) or (None, None) if not found.
    """
    candidates: List[str] = []

    # 1. Environment variables
    for env_var in ("METACLEAN_EXIFTOOL", "EXIFTOOL_PATH"):
        val = os.environ.get(env_var)
        if val:
            candidates.append(val)

    # 2. System PATH
    for cmd in ("exiftool", "ExifTool", "exiftool.exe"):
        found = shutil.which(cmd)
        if found:
            candidates.append(found)

    # 3. Standard Linux Mint / Unix paths
    candidates.extend([
        "/usr/bin/exiftool",
        "/usr/local/bin/exiftool",
        "/bin/exiftool",
    ])

    # 4. Standard Windows locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
    if local_app_data:
        candidates.append(str(Path(local_app_data) / "Programs" / "ExifTool" / "ExifTool.exe"))
        candidates.append(str(Path(local_app_data) / "Programs" / "ExifTool" / "exiftool.exe"))
    candidates.append(str(Path(program_files) / "ExifTool" / "exiftool.exe"))
    candidates.append(str(Path(program_files_x86) / "ExifTool" / "exiftool.exe"))

    # Verify candidate execution
    for candidate in candidates:
        if not candidate:
            continue
        cand_path = Path(candidate)
        if cand_path.is_file() or shutil.which(candidate):
            try:
                res = subprocess.run(
                    [str(cand_path), "-ver"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False
                )
                if res.returncode == 0:
                    ver = res.stdout.strip()
                    return str(cand_path), ver
            except (OSError, subprocess.SubprocessError):
                continue

    return None, None


# Resolve ExifTool on module load
EXIFTOOL_PATH, EXIFTOOL_VERSION = find_exiftool()
EXIFTOOL_AVAILABLE = EXIFTOOL_PATH is not None
