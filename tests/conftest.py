"""Pytest fixtures and synthetic image generators for MetaClean test suite.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Generator

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
