"""Automated unit and integration tests for metadata_remover module.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.image_validator import validate_image
from modules.metadata_remover import MetadataRemover, validate_categories
from modules.metadata_scanner import MetadataScanner


def get_file_hash(path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_full_removal_preserves_original(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    """Verifies that full removal preserves the original file bit-for-bit while cleaning copy."""
    orig_hash = get_file_hash(jpeg_with_gps_and_date)
    orig_size = jpeg_with_gps_and_date.stat().st_size
    out_path = temp_dir / "cleaned_copy.jpg"

    remover = MetadataRemover()
    res = remover.clean(
        input_path=jpeg_with_gps_and_date,
        output_path=out_path,
        categories=["all"],
        overwrite_output=True,
    )

    assert res.success is True
    assert out_path.exists()
    assert out_path.stat().st_size > 0

    # Ensure original file is strictly untouched
    assert get_file_hash(jpeg_with_gps_and_date) == orig_hash
    assert jpeg_with_gps_and_date.stat().st_size == orig_size

    # Verify metadata was removed from output
    scanner = MetadataScanner()
    scan_out = scanner.scan(out_path)
    assert scan_out.categories["gps"].detected is False
    assert scan_out.categories["date"].detected is False


def test_selective_category_removal_gps_only(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    """Verifies selective removal strips only requested category (e.g. GPS) and retains others."""
    out_path = temp_dir / "gps_stripped.jpg"

    remover = MetadataRemover()
    res = remover.clean(
        input_path=jpeg_with_gps_and_date,
        output_path=out_path,
        categories=["gps"],
        overwrite_output=True,
    )

    assert res.success is True
    assert "gps" in res.categories_removed
    assert "date" in res.preserved_categories

    scanner = MetadataScanner()
    scan_out = scanner.scan(out_path)
    # GPS must be gone
    assert scan_out.categories["gps"].detected is False


def test_removal_rejects_identical_input_output(jpeg_with_exif: Path) -> None:
    """Verifies security violation when output path is identical to input path."""
    remover = MetadataRemover()
    res = remover.clean(
        input_path=jpeg_with_exif,
        output_path=jpeg_with_exif,
        categories=["all"],
        overwrite_output=True,
    )
    assert res.success is False
    assert any("Security violation" in err for err in res.errors)


def test_removal_existing_output_without_overwrite(jpeg_with_exif: Path, temp_dir: Path) -> None:
    """Verifies error when target output file already exists and overwrite=False."""
    out_path = temp_dir / "already_exists.jpg"
    out_path.write_text("dummy")

    remover = MetadataRemover()
    res = remover.clean(
        input_path=jpeg_with_exif,
        output_path=out_path,
        categories=["all"],
        overwrite_output=False,
    )
    assert res.success is False
    assert any("already exists" in err for err in res.errors)


def test_validate_categories_helper() -> None:
    """Verifies category string parsing and validation."""
    valid, invalid = validate_categories("gps,date,device")
    assert valid == ["gps", "date", "device"]
    assert invalid == []

    valid2, invalid2 = validate_categories("gps,invalid_cat,author")
    assert valid2 == ["gps", "author"]
    assert invalid2 == ["invalid_cat"]


def test_png_transparency_preserved(transparent_png: Path, temp_dir: Path) -> None:
    """Verifies transparency and alpha channels are preserved after cleaning."""
    out_path = temp_dir / "clean_transparent.png"
    remover = MetadataRemover()
    res = remover.clean(
        input_path=transparent_png,
        output_path=out_path,
        categories=["all"],
        overwrite_output=True,
    )

    assert res.success is True
    val = validate_image(out_path)
    assert val.is_valid is True
    assert val.has_transparency is True
    assert val.dimensions == (64, 64)


def test_pillow_fallback_cleaning(jpeg_with_exif: Path, temp_dir: Path) -> None:
    """Verifies metadata removal works via Pillow fallback when ExifTool is not present."""
    out_path = temp_dir / "pillow_cleaned.jpg"
    remover = MetadataRemover(exiftool_path=None)
    remover.exiftool_available = False

    res = remover.clean(
        input_path=jpeg_with_exif,
        output_path=out_path,
        categories=["all"],
        overwrite_output=True,
    )

    assert res.success is True
    assert res.method_used == "pillow_fallback"
    assert out_path.exists()

    # Verify output is valid
    val = validate_image(out_path)
    assert val.is_valid is True


def test_temporary_files_cleaned_up(jpeg_with_exif: Path, temp_dir: Path) -> None:
    """Verifies that no orphaned temporary files remain after cleaning."""
    out_dir = temp_dir / "output_clean_dir"
    out_dir.mkdir()
    out_path = out_dir / "cleaned.jpg"

    remover = MetadataRemover()
    res = remover.clean(
        input_path=jpeg_with_exif,
        output_path=out_path,
        categories=["all"],
        overwrite_output=True,
    )

    assert res.success is True
    # The output directory should contain ONLY cleaned.jpg
    files = list(out_dir.iterdir())
    assert len(files) == 1
    assert files[0].name == "cleaned.jpg"
