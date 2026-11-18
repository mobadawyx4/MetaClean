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
APP_VERSION = "2.0.0"
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
# Upper bound on the number of files a single batch run may process.
MAX_BATCH_FILES = int(os.environ.get("METACLEAN_MAX_BATCH_FILES", 10_000))
# Hard ceiling for an explicit --max-files request.  ``MAX_BATCH_FILES`` is the
# default selection limit; an operator may raise it per run, but not without a
# bound, so a typo cannot turn into an effective "unlimited" batch.
MAX_BATCH_FILES_CEILING = int(
    os.environ.get("METACLEAN_MAX_BATCH_FILES_CEILING", 100_000)
)
# Maximum number of bytes read from the tail of a file for structural checks.
STRUCTURE_PROBE_BYTES = 256 * 1024
# Structural parser resource limits (F-10 / F-21).  Parsing walks the container
# with seeks; these caps stop a crafted file from turning the walk into an
# unbounded loop or an unbounded memory allocation.
STRUCTURE_MAX_SEGMENTS = 100_000
STRUCTURE_MAX_CHUNKS = 100_000
STRUCTURE_MAX_ENTROPY_SCAN_BYTES = 512 * 1024 * 1024
# Bytes that are treated as container padding rather than an appended payload.
STRUCTURE_PADDING_BYTES = frozenset({0x00, 0x0A, 0x0D, 0x20, 0xFF})
# Private mode applied to every exported report (mode bits only).
REPORT_FILE_MODE = 0o600

# Scan modes. These control how much information ExifTool is asked to extract.
#   standard: classic extraction (all named tags, unknown tags included)
#   deep:     adds structured XMP/IPTC parsing and raw (numeric) values
#   privacy:  deep extraction with privacy-focused reporting
#   full:     deep extraction plus embedded-file extraction (-ee)
SCAN_MODES: Tuple[str, ...] = ("standard", "deep", "privacy", "full")

# Single source of truth for scan-mode help text (F-26).  The CLI help, the
# ``info`` command and the documentation all describe the modes from here.
SCAN_MODE_DESCRIPTIONS: Dict[str, str] = {
    "standard": (
        "Classic extraction: every named and unknown tag ExifTool reports. "
        "No -struct structured XMP/IPTC parsing, no -n raw numeric pass, and no "
        "physical container analysis."
    ),
    "deep": (
        "Adds -struct structured XMP/IPTC values, a -n raw numeric pass, and "
        "physical container analysis (extension/format consistency, structural "
        "validation, trailing data)."
    ),
    "privacy": (
        "Extraction is identical to --deep (structured XMP/IPTC, raw numeric "
        "values, container analysis); the report and console output are framed "
        "around the privacy-risk assessment."
    ),
    "full": (
        "Everything in --deep plus -ee embedded-file extraction. This is the "
        "slowest and most exhaustive mode."
    ),
}

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
        "description": "Geographic positioning and textual location data (coordinates, altitude, direction, city/country names)",
        "risk_level": "HIGH",
        # Native GPS plus XMP/IPTC location aliases.  ``-GPS*`` spans every
        # group, so XMP-exif GPS fields are covered without touching unrelated
        # XMP properties.  Textual location uses explicit names because a
        # generic ``*location*`` wildcard would also match SubjectLocation
        # (image-relative pixel coordinates, not a place).
        "exiftool_args": [
            "-GPS:all=", "-GPS*=",
            "-*GPSLatitude=", "-*GPSLongitude=", "-*GPSAltitude=",
            "-*GPSDateTime=", "-*GPSDestBearing=", "-*EarthPos*=",
            "-Location=", "-Sub-location=", "-LocationName=",
            "-LocationCreated*=", "-LocationShown*=", "-RatingRegion*=",
            "-*LocationAreaCode=", "-*LocationBody=", "-*LocationNote=",
            "-*LocationRole=", "-*LocationAccuracy*=",
            "-*LocationInformation=", "-*LocationInfo*=",
            "-*LocationCode=", "-*LocationDate=",
            "-*Latitude=", "-*Longitude=", "-*Coordinates=",
            "-City=", "-City2=", "-State=", "-Province-State=",
            "-Country=", "-CountryCode=", "-Country-PrimaryLocationCode=",
            "-Country-PrimaryLocationName=", "-ContentLocationCode=",
            "-ContentLocationName=", "-Geography=",
        ],
        "tags": [
            "GPSVersionID", "GPSLatitude", "GPSLongitude", "GPSAltitude",
            "GPSPosition", "GPSDateTime", "GPSLatitudeRef", "GPSLongitudeRef",
            "GPSAltitudeRef", "GPSTimeStamp", "GPSDateStamp", "GPSSatellites",
            "GPSStatus", "GPSMeasureMode", "GPSDOP", "GPSSpeedRef", "GPSSpeed",
            "GPSTrackRef", "GPSTrack", "GPSImgDirectionRef", "GPSImgDirection",
            "GPSMapDatum", "GPSDestLatitude", "GPSDestLongitude",
            "GPSDestLatitudeRef", "GPSDestLongitudeRef", "GPSDestBearingRef",
            "GPSDestDistanceRef", "GPSDestBearing", "GPSDestDistance",
            "GPSProcessingMethod",
            "GPSAreaInformation", "GPSDifferential", "GPSHPositioningError",
            "Location", "Sub-location", "LocationName", "City", "City2",
            "State", "Province-State", "Country", "CountryCode",
            "Country-PrimaryLocationCode", "Country-PrimaryLocationName",
            "ContentLocationCode", "ContentLocationName", "Geography",
            "LocationCreated*", "LocationShown*", "RatingRegion*",
            "EarthPosLatitude", "EarthPosLongitude", "EarthPosAltitude",
        ],
    },
    "date": {
        "description": "Capture, creation, modification, digitization, release, and expiration timestamps",
        "risk_level": "MEDIUM",
        # ``-*Date*`` catches the many date aliases across EXIF/IPTC/XMP.
        # Time fields are enumerated instead of using a ``*Time*`` wildcard,
        # which would also delete photographic settings such as ExposureTime.
        "exiftool_args": [
            "-*Date*=", "-*Timestamp*=", "-*Timecode*=", "-SubSecTime*=",
            "-OffsetTime*=", "-TimeZoneOffset=", "-TimeCreated=",
            "-DigitalCreationTime=", "-ReleaseTime=", "-ExpirationTime=",
            "-TimeSent=", "-HistoryWhen=", "-IPTCLastEdited=",
            "-MetadataLastEdited=",
        ],
        "tags": [
            "DateTimeOriginal", "CreateDate", "ModifyDate", "DateTimeDigitized",
            "SubSecTimeOriginal", "SubSecTimeDigitized", "SubSecTime",
            "OffsetTime", "OffsetTimeOriginal", "OffsetTimeDigitized",
            "TimeZoneOffset", "DigitalCreationDate", "DigitalCreationTime",
            "DateCreated", "TimeCreated", "ReleaseDate", "ReleaseTime",
            "ExpirationDate", "ExpirationTime", "ReferenceDate", "DateSent",
            "TimeSent", "MetadataDate", "HistoryWhen", "PreviewDateTime",
            "TimeCodes", "StartTimecode", "Date", "DateTime",
            "IPTCLastEdited", "MetadataLastEdited",
            "SubSecDateTimeOriginal", "DateTimeCreated",
            "DigitalCreationDateTime",
        ],
    },
    "device": {
        "description": "Hardware and software identifiers (camera make/model, serial numbers, lens, owner/device IDs)",
        "risk_level": "MEDIUM",
        # Wildcards cover manufacturer-specific aliases (BodySerialNumber,
        # CameraFirmware, DNGLensInfo, RecDevice*) without enumerating every
        # vendor spelling.  Make/Model stay exact so GeoTIFF tags such as
        # ModelTiePoint/ModelTransform are not mistaken for camera hardware.
        "exiftool_args": [
            "-Make=", "-*Model=", "-*ModelID=", "-*ModelName=",
            "-*Serial*=", "-*Lens*=", "-*Firmware*=", "-*Software*=",
            "-HostComputer=", "-*Device*=",
        ],
        "tags": [
            "Make", "Model", "UniqueCameraModel", "LocalizedCameraModel",
            "CameraModel", "XiaomiModel", "CanonModelID", "CameraModelID",
            "SonyModelID", "SerialNumber", "InternalSerialNumber",
            "CameraSerialNumber", "BodySerialNumber", "LensMake", "LensModel",
            "LensSerialNumber", "LensInfo", "LensSpecification", "DNGLensInfo",
            "Software", "ProcessingSoftware", "Firmware", "CameraFirmware",
            "DeviceSettingDescription", "HostComputer",
            "RecDeviceManufacturer", "RecDeviceModelName",
            "RecDeviceSerialNumber", "RecDeviceOwnersDeviceId",
        ],
    },
    "author": {
        "description": "Personal identity info, creator, artist, owner, and contact data",
        "risk_level": "HIGH",
        "exiftool_args": [
            "-Artist=", "-*Creator*=", "-*Contributor*=", "-By-line=",
            "-By-lineTitle=", "-Author*=", "-*OwnerName=", "-*Owner=",
            "-*OwnerID=", "-Contact=", "-Credit=", "-CreditLine=",
            "-Source=", "-CaptionWriter=", "-Writer-Editor=",
            "-AuthorsPosition=",
        ],
        "tags": [
            "Artist", "Creator", "CreatorName", "CreatorIdentifier",
            "CreatorRole", "CreatorContactInfo", "CreatorCity",
            "CreatorCountry", "CreatorRegion", "CreatorAddress",
            "CreatorPostalCode", "CreatorWorkEmail", "CreatorWorkTelephone",
            "CreatorWorkURL", "Contributor", "ContributorName",
            "ContributorIdentifier", "ContributorRole", "By-line",
            "By-lineTitle", "Author", "OwnerName", "Owner", "OwnerID",
            "RightsOwner", "CopyrightOwner", "CopyrightOwnerName",
            "CopyrightOwnerID", "Contact", "Credit", "CreditLine", "Source",
            "CaptionWriter", "Writer-Editor", "AuthorsPosition",
        ],
    },
    "copyright": {
        "description": "Copyright notices, usage rights, and licensing terms",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-*Copyright*=", "-*Rights*=", "-UsageTerms=", "-*WebStatement=",
        ],
        "tags": [
            "Copyright", "CopyrightNotice", "Rights", "UsageTerms", "WebStatement"
        ],
    },
    "comments": {
        "description": "User comments, descriptions, titles, headlines, and custom text annotations",
        "risk_level": "MEDIUM",
        # Description/Title/Subject are kept exact so unrelated names such as
        # DeviceSettingDescription or SubjectDistance are not swept in.
        "exiftool_args": [
            "-*Comment*=", "-ImageDescription=", "-*Description=",
            "-Title=", "-XPTitle=", "-PanasonicTitle=", "-PanasonicTitle2=",
            "-ObjectName=", "-Headline=", "-*Caption*=", "-Subject=",
            "-XPSubject=", "-*Keyword*=", "-*Notes=", "-DocumentNotes=",
            "-*Instructions=", "-Category=", "-SupplementalCategories=",
        ],
        "tags": [
            "Comment", "UserComment", "ImageDescription", "Description",
            "XPComment", "XPKeywords", "XPSubject", "XPTitle", "Notes",
            "DocumentNotes", "Headline", "Caption-Abstract", "Caption",
            "LocalCaption", "RasterizedCaption", "ObjectName", "Title",
            "Subject", "Keywords", "Category", "SupplementalCategories",
            "Instructions", "SpecialInstructions", "PanasonicTitle",
            "PanasonicTitle2",
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
    "software": {
        "description": "Software, editing environment, and processing-history identifiers",
        "risk_level": "LOW",
        # ``-*Software*`` catches EXIF/XMP software aliases; the remaining
        # names are application identifiers that do not contain "software".
        "exiftool_args": [
            "-*Software*=", "-CreatorTool=", "-XMPToolkit=",
            "-HistorySoftwareAgent=", "-PreviewApplicationName=",
            "-PreviewApplicationVersion=", "-CreatorAppID=",
            "-CreatorOpenWithUIOptions=",
        ],
        "tags": [
            "Software", "ProcessingSoftware", "RAWDevelopingSoftware",
            "ImageEditingSoftware", "MetadataEditingSoftware", "CreatorTool",
            "XMPToolkit", "HistorySoftwareAgent", "PreviewApplicationName",
            "PreviewApplicationVersion",
        ],
    },
    "identifiers": {
        "description": "Unique document, image, and instance identifiers used for tracking",
        "risk_level": "MEDIUM",
        "exiftool_args": [
            "-*UniqueID=", "-DocumentID=", "-InstanceID=",
            "-OriginalDocumentID=", "-VersionID=", "-Identifier=",
            "-*PhotoIdentifier=",
        ],
        "tags": [
            "ImageUniqueID", "DocumentID", "InstanceID", "OriginalDocumentID",
            "VersionID", "Identifier",
        ],
    },
    "thumbnail": {
        "description": "Embedded thumbnails and preview images that may retain original content",
        "risk_level": "MEDIUM",
        # Only these extraction names are writable for deletion.  Other preview
        # representations (PreviewTIFF/PreviewPDF/ThumbnailTIFF) are read-only
        # in ExifTool and have no writable key name; ``all`` still removes them.
        "exiftool_args": [
            "-ThumbnailImage=", "-ThumbnailPNG=", "-SanyoThumbnail=",
            "-PreviewImage=", "-OtherImage=", "-JpgFromRaw=",
            "-PhotoshopThumbnail=", "-PhotoshopBGRThumbnail=",
        ],
        "tags": [
            "ThumbnailImage", "PreviewImage", "OtherImage", "JpgFromRaw",
            "ThumbnailTIFF", "PreviewTIFF", "PreviewPDF",
            "PhotoshopThumbnail", "PhotoshopBGRThumbnail",
        ],
    },
    "makernotes": {
        "description": "Manufacturer-specific MakerNotes blocks (may contain serials and device state)",
        "risk_level": "MEDIUM",
        "exiftool_args": ["-MakerNotes:all=", "-MakerNote*="],
        "tags": ["*MakerNotes*"],
    },
    "all": {
        "description": "All supported metadata structures (EXIF, GPS, IPTC, XMP, Comments, Thumbnails)",
        "risk_level": "ALL",
        "exiftool_args": ["-all=", "-tagsFromFile", "@", "-ColorSpaceTags", "-Orientation"],
        "tags": ["*ALL*"],
    },
}

# Legacy reference table retained for backwards compatibility.  The authoritative
# classifier is RuleBasedPrivacyAnalyzer in modules/privacy_analyzer.py, which
# implements the five-level taxonomy (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL).
RISK_RULES: Dict[str, Dict[str, object]] = {
    "CRITICAL": {
        "description": "Critical Privacy Exposure: directly locates or contacts a person (GPS coordinates, email, phone).",
        "patterns": [
            "latitude", "longitude", "gpsposition", "coordinates", "coord",
            "email", "emailaddress", "phone", "phonenumber", "telephone",
            "contact", "creatorcontactinfo", "postaladdress",
        ],
    },
    "HIGH": {
        "description": "High Privacy Risk: directly identifies a person or device (author, serial number, unique ID, preview).",
        "patterns": [
            "artist", "creator", "author", "ownername", "by-line", "faceinfo",
            "serial", "documentid", "instanceid", "imageuniqueid", "thumbnail", "preview",
        ],
    },
    "MEDIUM": {
        "description": "Medium Privacy Risk: indirect or correlatable data (timestamps, camera model, comments, copyright).",
        "patterns": [
            "datetime", "createdate", "modifydate", "timestamp", "subsectime", "offsettime",
            "model", "lens", "firmware", "comment", "description", "copyright",
            "historywhen", "software",
        ],
    },
    "LOW": {
        "description": "Low Privacy Risk: technical shooting parameters with minimal personal privacy impact.",
        "patterns": [
            "iso", "fnumber", "aperture", "shutterspeed", "exposuretime", "exposureprogram",
            "exposurecompensation", "maxaperturevalue", "focallength", "whitebalance",
            "lightsource", "flash", "meteringmode", "sensingmethod", "scenetype", "scenecapturetype"
        ],
    },
    "INFORMATIONAL": {
        "description": "Informational: purely technical image dimensions, color profiles, or encoding parameters.",
        "patterns": [
            "imagewidth", "imageheight", "bitspersample", "colortype", "colorspace",
            "compression", "photometricinterpretation", "resolution", "xresolution",
            "yresolution", "samplesperpixel", "mimetype", "filesize", "filetype",
            "ycbcrpositioning", "ycbcrsubsampling", "orientation", "exifversion", "flashpixversion"
        ],
    },
}


# Tags that legitimately remain after a full metadata strip.  These describe the
# container, the decoded pixel array, or the output of ExifTool itself; they are
# not user/authored metadata.  The verifier uses this allowlist so it never claims
# "clean" just because ExifTool exited zero, and never flags structural tags as
# leftovers.
STRUCTURAL_GROUPS: Set[str] = {
    "File", "System", "ExifTool", "JFIF", "PNG", "RIFF", "GIF",
    "IFD0", "ExifIFD", "InteropIFD", "SubIFD", "EXIF", "ICC_Profile",
}
STRUCTURAL_COMPOSITE_TAGS: Set[str] = {"ImageSize", "Megapixels"}
STRUCTURAL_TAG_ALLOWLIST: Set[str] = {
    "ExifToolVersion", "SourceFile", "FileName", "Directory", "FileSize",
    "FileModifyDate", "FileAccessDate", "FileInodeChangeDate", "FilePermissions",
    "FileType", "FileTypeExtension", "MIMEType", "ImageWidth", "ImageHeight",
    "ImageSize", "Megapixels", "BitsPerSample", "ColorComponents",
    "EncodingProcess", "YCbCrSubSampling", "YCbCrPositioning", "ExifByteOrder", "JFIFVersion",
    "ResolutionUnit", "XResolution", "YResolution", "ColorSpace", "Orientation",
    "ComponentsConfiguration", "ExifVersion", "FlashpixVersion", "InteropVersion",
    "Compression", "PhotometricInterpretation", "SamplesPerPixel",
    "PlanarConfiguration", "BitDepth", "ColorType", "Interlace",
    "Filter", "VP8Version", "HorizontalScale", "VerticalScale",
}


def is_structural_tag(group: str, tag_name: str) -> bool:
    """Returns True when a tag is container/decoder structure rather than user metadata.

    Requires matching BOTH a recognized structural group and an allowed
    structural tag name. Structural tag names appearing in unrelated groups
    (e.g. IPTC, XMP, GPS, MakerNotes) are strictly rejected.
    """
    if not group or not tag_name:
        return False
    if group == "Composite":
        return tag_name in STRUCTURAL_COMPOSITE_TAGS
    if group not in STRUCTURAL_GROUPS:
        return False
    if group == "ICC_Profile" or group.startswith("ICC"):
        if any(
            k in tag_name.lower()
            for k in ("gps", "artist", "author", "creator", "date", "software", "serial", "uniqueid")
        ):
            return False
        return True
    return tag_name in STRUCTURAL_TAG_ALLOWLIST


# Categories considered when looking for personally identifying or privacy
# relevant metadata (as opposed to container/technical blocks).
PRIVACY_CATEGORIES: Set[str] = {
    "gps", "date", "device", "author", "copyright", "comments",
    "software", "identifiers", "thumbnail", "makernotes",
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
