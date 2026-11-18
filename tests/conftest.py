"""Pytest fixtures and synthetic image generators for MetaClean test suite.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Generator, Sequence

import pytest
from PIL import Image, PngImagePlugin


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provides an isolated temporary directory for test file generation."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def clean_jpeg(temp_dir: Path) -> Path:
    """Creates a basic valid JPEG image without metadata."""
    img_path = temp_dir / "clean_photo.jpg"
    img = Image.new("RGB", (64, 64), color=(100, 150, 200))
    img.save(img_path, format="JPEG", quality=90)
    return img_path


@pytest.fixture
def jpeg_with_exif(temp_dir: Path) -> Path:
    """Creates a JPEG with camera device and author metadata."""
    img_path = temp_dir / "device_author.jpg"
    img = Image.new("RGB", (64, 64), color=(200, 100, 50))
    exif = img.getexif()
    exif[0x010F] = "Nikon Corporation"  # Make
    exif[0x0110] = "NIKON Z 6_2"       # Model
    exif[0x013B] = "Alice Cybersecurity"  # Artist
    exif[0x8298] = "Copyright 2026 Alice"  # Copyright
    exif[0x0131] = "MetaClean Test Suite"  # Software
    img.save(img_path, format="JPEG", exif=exif)
    return img_path


@pytest.fixture
def jpeg_with_gps_and_date(temp_dir: Path) -> Path:
    """Creates a JPEG with GPS coordinates and capture timestamps."""
    img_path = temp_dir / "gps_date.jpg"
    img = Image.new("RGB", (64, 64), color=(50, 200, 100))
    exif = img.getexif()

    # SubIFD 0x8769 for DateTimeOriginal
    sub_ifd = {
        0x9003: "2026:06:15 14:30:00",  # DateTimeOriginal
        0x9004: "2026:06:15 14:30:00",  # CreateDate
    }
    exif[0x8769] = sub_ifd

    from fractions import Fraction

    # GPS IFD 0x8825
    gps_ifd = {
        0x0001: "N",  # GPSLatitudeRef
        0x0002: (Fraction(37, 1), Fraction(46, 1), Fraction(2976, 100)),  # 37 deg 46' 29.76" N
        0x0003: "W",  # GPSLongitudeRef
        0x0004: (Fraction(122, 1), Fraction(25, 1), Fraction(984, 100)),  # 122 deg 25' 9.84" W
        0x0006: Fraction(15, 1),  # Altitude 15m
    }
    exif[0x8825] = gps_ifd

    img.save(img_path, format="JPEG", exif=exif)
    return img_path


@pytest.fixture
def transparent_png(temp_dir: Path) -> Path:
    """Creates a PNG with alpha channel transparency and text metadata."""
    img_path = temp_dir / "transparent.png"
    img = Image.new("RGBA", (64, 64), color=(255, 0, 0, 128))

    png_info = PngImagePlugin.PngInfo()
    png_info.add_text("Author", "CyberSec Lab")
    png_info.add_text("Comment", "Confidential diagram")

    img.save(img_path, format="PNG", pnginfo=png_info)
    return img_path


@pytest.fixture
def valid_webp(temp_dir: Path) -> Path:
    """Creates a valid WebP image."""
    img_path = temp_dir / "photo.webp"
    img = Image.new("RGB", (64, 64), color=(80, 80, 180))
    exif = img.getexif()
    exif[0x010F] = "WebP Camera"
    img.save(img_path, format="WEBP", exif=exif)
    return img_path


@pytest.fixture
def valid_tiff(temp_dir: Path) -> Path:
    """Creates a valid TIFF image with metadata."""
    img_path = temp_dir / "scan.tiff"
    img = Image.new("RGB", (64, 64), color=(180, 80, 80))
    exif = img.getexif()
    exif[0x010F] = "TIFF Scanner"
    img.save(img_path, format="TIFF", exif=exif)
    return img_path


@pytest.fixture
def corrupted_image(temp_dir: Path) -> Path:
    """Creates a corrupted image file with partial/broken header."""
    img_path = temp_dir / "corrupted.jpg"
    with open(img_path, "wb") as f:
        # Invalid JPEG header with junk bytes
        f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00CORRUPT_DATA_TRUNCATED")
    return img_path


@pytest.fixture
def fake_extension_file(temp_dir: Path) -> Path:
    """Creates a text file masquerading as a JPEG."""
    img_path = temp_dir / "fake.jpg"
    with open(img_path, "w", encoding="utf-8") as f:
        f.write("This is a plain text file, not a JPEG image.")
    return img_path


def _exiftool_available() -> bool:
    return shutil.which("exiftool") is not None


def _write_exiftool_tags(path: Path, assignments: Sequence[str]) -> None:
    """Writes ExifTool assignments in place and rejects invalid tag names.

    ``-q`` suppresses the "1 image files updated" chatter but warnings still go
    to stderr.  A warning about an undefined or read-only tag means the fixture
    (or the argument under test) is wrong, so it is surfaced as a test failure
    rather than silently producing a weaker fixture.
    """
    command = ["exiftool", "-q", "-overwrite_original"]
    command.extend(f"-{assignment}" for assignment in assignments)
    command.append(str(path))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    diagnostics = (result.stderr or "").strip()
    assert result.returncode < 2, f"ExifTool failed for {assignments}: {diagnostics}"
    assert "not defined" not in diagnostics, diagnostics
    assert "not writable" not in diagnostics, diagnostics
    assert "doesn't exist" not in diagnostics, diagnostics


@pytest.fixture
def jpeg_with_category_metadata(temp_dir: Path) -> Path:
    """Creates a JPEG carrying representative tags from every targeted category.

    The fixture is built with ExifTool (rather than Pillow) because Pillow can
    only write a subset of EXIF tags and no IPTC/XMP.  Coverage:

    * ``gps``: native GPS coordinates/altitude/direction plus IPTC and XMP
      textual locations (city/state/country/sublocation) and XMP coordinates.
    * ``date``: EXIF capture dates, sub-second/offset fields, and IPTC
      created/released/expired dates and times.
    * ``device``: make/model, body/lens serials, lens identity, and host name
      (the fixture avoids vendor-specific MakerNote tags).
    * ``author``: EXIF Artist/OwnerName, IPTC by-line/credit/source/contact,
      XMP creator and owner/rights owner.
    * ``copyright``: EXIF/IPTC/XMP copyright and usage terms.
    * ``comments``: EXIF/IPTC/XMP titles, descriptions, comments, headlines,
      captions and keywords.
    * ``software``: EXIF/IPTC/XMP software and editor identifiers.
    * ``identifiers``: unique document/instance identifiers.
    * ``thumbnail``: an embedded EXIF thumbnail that still shows the scene.

    Orientation 6 (rotate 90 CW) is set so category cleaning can be checked for
    structural preservation at the same time.
    """
    if not _exiftool_available():
        pytest.skip("ExifTool is required to build the category-coverage fixture.")

    image_path = temp_dir / "category_metadata.jpg"
    image = Image.new("RGB", (64, 48), color=(60, 120, 180))
    exif = image.getexif()
    exif[0x0112] = 6  # Orientation: Rotate 90 CW
    image.save(image_path, format="JPEG", quality=95, exif=exif)

    _write_exiftool_tags(
        image_path,
        [
            # --- device / software ---------------------------------------
            "Make=AcmeCam",
            "Model=Model X",
            "SerialNumber=SN-EXIF-1",
            "CameraSerialNumber=CSN-1",
            "LensMake=AcmeOptics",
            "LensModel=Lens 50",
            "LensSerialNumber=LS-1",
            "HostComputer=WORKSTATION-1",
            "Software=Editor 1.0",
            # --- author / copyright --------------------------------------
            "Artist=Alice Author",
            "OwnerName=Owner EXIF",
            "Copyright=Copyright Alice",
            # --- comments ------------------------------------------------
            "ImageDescription=Description text",
            "UserComment=User comment",
            "XPTitle=XP title",
            "XPComment=XP comment",
            "XPKeywords=XP keyword",
            "XPSubject=XP subject",
            "Title=EXIF title",
            # --- date ----------------------------------------------------
            "DateTimeOriginal=2024:05:01 10:11:12",
            "CreateDate=2024:05:01 10:11:12",
            "ModifyDate=2024:05:02 11:12:13",
            "OffsetTimeOriginal=+02:00",
            "SubSecTimeOriginal=123",
            "TimeZoneOffset=+02:00",
            # --- gps -----------------------------------------------------
            "GPSLatitude=37.7749",
            "GPSLongitude=-122.4194",
            "GPSAltitude=15",
            "GPSImgDirection=90",
            "GPSDestBearing=12",
            "GPSDateStamp=2024:05:01",
            # --- non-targeted photographic/structural controls -----------
            "ExposureTime=1/125",
            "FNumber=2.8",
            "ISO=200",
            "FocalLength=50",
            "SubjectArea=100 100 200 200",
            "SubjectLocation=10 20",
        ],
    )

    _write_exiftool_tags(
        image_path,
        [
            "IPTC:City=Springfield",
            "IPTC:Sub-location=Downtown",
            "IPTC:Province-State=CA",
            "IPTC:Country-PrimaryLocationName=USA",
            "IPTC:ContentLocationCode=US-CA",
            "IPTC:ContentLocationName=California",
            "IPTC:Headline=Headline text",
            "IPTC:Caption-Abstract=Caption text",
            "IPTC:ObjectName=Object name",
            "IPTC:By-line=Bob Byline",
            "IPTC:By-lineTitle=Photographer",
            "IPTC:Credit=Credit Co",
            "IPTC:Source=Source Co",
            "IPTC:Writer-Editor=Carol Writer",
            "IPTC:Contact=Contact info",
            "IPTC:OwnerID=OwnerID-1",
            "IPTC:CopyrightNotice=IPTC Copyright",
            "IPTC:Keywords=keyword-one,keyword-two",
            "IPTC:DateCreated=2024:05:01",
            "IPTC:TimeCreated=10:11:12",
            "IPTC:DigitalCreationDate=2024:05:01",
            "IPTC:DigitalCreationTime=10:11:12",
            "IPTC:ReleaseDate=2024:06:01",
            "IPTC:ReleaseTime=09:00:00",
            "IPTC:ExpirationDate=2025:01:01",
            "IPTC:ExpirationTime=09:00:00",
        ],
    )

    _write_exiftool_tags(
        image_path,
        [
            "XMP-exif:GPSLatitude=37.7749",
            "XMP-exif:GPSLongitude=-122.4194",
            "XMP-exif:GPSAltitude=15",
            "XMP-iptcCore:Location=Bay Area",
            "XMP-photoshop:City=Springfield",
            "XMP-photoshop:State=CA",
            "XMP-photoshop:Country=USA",
            "XMP-photoshop:DateCreated=2024:05:01",
            "XMP-photoshop:Headline=XMP headline",
            "XMP-photoshop:CaptionWriter=XMP writer",
            "XMP-photoshop:Credit=XMP credit",
            "XMP-photoshop:Source=XMP source",
            "XMP-dc:Creator=Alice Creator",
            "XMP-dc:Description=XMP description",
            "XMP-dc:Title=XMP title",
            "XMP-xmp:CreateDate=2024:05:01",
            "XMP-xmp:ModifyDate=2024:05:02",
            "XMP-xmp:CreatorTool=XMP Tool",
            "XMP-tiff:Make=AcmeCam",
            "XMP-tiff:Model=Model X",
            "XMP-tiff:Software=Editor 1.0",
            "XMP-exifEX:SerialNumber=XMP-SN",
            "XMP-exifEX:OwnerName=Owner XMP",
            "XMP-xmpRights:Owner=Rights Owner",
            "XMP-xmpRights:UsageTerms=Rights terms",
            "XMP-iptcExt:LocationCreatedCity=Springfield",
            "XMP-iptcExt:LocationShownCountryName=USA",
            "XMP-Device:EarthPosLatitude=37.7",
            "XMP-Device:EarthPosLongitude=-122.4",
            "XMP-xmpMM:DocumentID=doc-1",
            "XMP-xmpMM:InstanceID=inst-1",
        ],
    )

    # Embedded thumbnail: a separate small image stored inside IFD1.
    thumbnail_path = temp_dir / "category_thumbnail.jpg"
    Image.new("RGB", (16, 12), color=(200, 40, 40)).save(thumbnail_path, format="JPEG", quality=90)
    _write_exiftool_tags(image_path, [f"ThumbnailImage<={thumbnail_path}"])

    return image_path
