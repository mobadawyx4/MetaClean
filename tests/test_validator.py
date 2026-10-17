"""Automated unit and integration tests for image_validator module.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

import config
from modules.image_validator import (
    ImageValidationError,
    check_magic_bytes,
    safe_resolve_path,
    validate_image,
)


def test_validate_valid_jpeg(clean_jpeg: Path) -> None:
    """Verifies standard clean JPEG passes validation."""
    res = validate_image(clean_jpeg)
    assert res.is_valid is True
    assert res.format_name == "JPEG"
    assert res.dimensions == (64, 64)
    assert res.file_size > 0
    assert len(res.errors) == 0


def test_validate_png_with_transparency(transparent_png: Path) -> None:
    """Verifies PNG validation and alpha transparency detection."""
    res = validate_image(transparent_png)
    assert res.is_valid is True
    assert res.format_name == "PNG"
    assert res.has_transparency is True
    assert res.dimensions == (64, 64)


def test_validate_webp(valid_webp: Path) -> None:
    """Verifies WebP validation."""
    res = validate_image(valid_webp)
    assert res.is_valid is True
    assert res.format_name == "WEBP"


def test_validate_tiff(valid_tiff: Path) -> None:
    """Verifies TIFF format validation."""
    res = validate_image(valid_tiff)
    assert res.is_valid is True
    assert res.format_name == "TIFF"


def test_validate_corrupted_image(corrupted_image: Path) -> None:
    """Verifies that truncated or corrupted files fail validation."""
    res = validate_image(corrupted_image)
    assert res.is_valid is False
    assert len(res.errors) > 0


def test_validate_invalid_signature_fake_extension(fake_extension_file: Path) -> None:
    """Verifies that text files disguised as JPEGs are caught by magic signature checks."""
    res = validate_image(fake_extension_file)
    assert res.is_valid is False
    assert any("signature" in err.lower() or "magic" in err.lower() for err in res.errors)


def test_validate_oversized_file(clean_jpeg: Path) -> None:
    """Verifies file size limits are strictly enforced."""
    # Enforce a tiny max limit of 10 bytes
    res = validate_image(clean_jpeg, max_size_bytes=10)
    assert res.is_valid is False
    assert any("exceeds maximum limit" in err for err in res.errors)


def test_validate_decompression_bomb(temp_dir: Path) -> None:
    """Verifies protection against decompression bomb attacks."""
    huge_img_path = temp_dir / "large.png"
    # Create an image that exceeds max pixels limit
    img = Image.new("RGB", (200, 200), color="white")
    img.save(huge_img_path, format="PNG")

    # Set threshold lower than 200*200 = 40,000 pixels
    res = validate_image(huge_img_path, max_pixels=1000)
    assert res.is_valid is False
    assert any("pixel limit" in err.lower() or "decompression" in err.lower() for err in res.errors)


def test_safe_resolve_path_null_bytes() -> None:
    """Verifies null byte injection in paths is caught."""
    with pytest.raises(ImageValidationError, match="null bytes"):
        safe_resolve_path("image\0.jpg")


def test_safe_resolve_path_nonexistent(temp_dir: Path) -> None:
    """Verifies non-existent path raises ImageValidationError."""
    with pytest.raises(ImageValidationError, match="not found"):
        safe_resolve_path(temp_dir / "does_not_exist.jpg", must_exist=True)


def test_check_magic_bytes(clean_jpeg: Path, transparent_png: Path) -> None:
    """Verifies signature detection functions correctly."""
    assert check_magic_bytes(clean_jpeg) == "JPEG"
    assert check_magic_bytes(transparent_png) == "PNG"
