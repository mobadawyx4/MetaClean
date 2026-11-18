"""Tests for sanitization profiles and profile-aware cleaning/verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import config
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationOutcome
from modules.sanitizer_profiles import (
    ALL_REMOVABLE_CATEGORIES,
    PROFILES,
    describe_profiles,
    get_profile,
    resolve_profile,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_all_profiles_are_described_and_valid() -> None:
    assert set(PROFILES) == {"basic", "location", "personal", "maximum", "custom"}
    described = describe_profiles()
    assert len(described) == 5
    for entry in described:
        assert entry["key"] in PROFILES
        assert entry["name"]
        for category in entry["categories"]:
            assert category in config.METADATA_CATEGORIES
    assert set(ALL_REMOVABLE_CATEGORIES) == {
        key for key in config.METADATA_CATEGORIES if key != "all"
    }


def test_resolve_profiles() -> None:
    profile, categories = resolve_profile("maximum")
    assert profile.full_clean is True
    assert categories == ["all"]

    profile, categories = resolve_profile("location")
    assert categories == ["gps"]
    assert profile.full_clean is False

    profile, categories = resolve_profile("custom", "gps, author,unknown")
    assert categories == ["gps", "author", "unknown"]

    profile, categories = resolve_profile("custom", ["gps", "identifiers"])
    assert categories == ["gps", "identifiers"]


def test_resolve_profile_errors() -> None:
    with pytest.raises(ValueError, match="Unknown sanitization profile"):
        resolve_profile("super-secret")
    with pytest.raises(ValueError, match="requires at least one"):
        resolve_profile("custom")
    with pytest.raises(ValueError, match="requires at least one"):
        resolve_profile("custom", " , ")


def test_get_profile_is_case_insensitive() -> None:
    assert get_profile("MAXIMUM") is not None
    assert get_profile("nonexistent") is None
    assert get_profile("") is None


def test_maximum_profile_verifies_clean_and_preserves_original(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    original_hash = _sha256(jpeg_with_gps_and_date)
    out = temp_dir / "clean.jpg"

    removal = MetadataRemover().clean(
        jpeg_with_gps_and_date, out, profile="maximum", overwrite_output=True
    )
    assert removal.success, removal.errors
    assert out.exists()
    assert removal.profile == "maximum"
    assert removal.output_validated is True
    assert "all" in removal.categories_requested
    assert _sha256(jpeg_with_gps_and_date) == original_hash

    verification = MetadataVerifier().verify(
        out,
        original_image_path=jpeg_with_gps_and_date,
        profile="maximum",
    )
    assert verification.outcome == VerificationOutcome.VERIFIED_CLEAN
    assert verification.status.value == "PASS"
    assert verification.comparison is not None
    assert verification.comparison.sensitive_removed_count > 0
    assert verification.comparison.sensitive_remaining_count == 0

    rescan = MetadataScanner().scan(out)
    assert rescan.privacy_report is not None
    assert rescan.privacy_report.overall_risk.value in ("INFORMATIONAL", "LOW")
    assert rescan.gps_coordinates is None


def test_location_profile_removes_only_gps(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    out = temp_dir / "location.jpg"
    removal = MetadataRemover().clean(
        jpeg_with_gps_and_date, out, profile="location", overwrite_output=True
    )
    assert removal.success, removal.errors
    assert removal.categories_requested == ["gps"]

    rescan = MetadataScanner().scan(out)
    assert rescan.categories["gps"].detected is False
    assert rescan.gps_coordinates is None
    # Capture timestamps are not part of the location profile.
    assert rescan.categories["date"].detected is True


def test_personal_profile_keeps_device_metadata(jpeg_with_exif: Path, temp_dir: Path) -> None:
    out = temp_dir / "personal.jpg"
    removal = MetadataRemover().clean(
        jpeg_with_exif, out, profile="personal", overwrite_output=True
    )
    assert removal.success, removal.errors

    rescan = MetadataScanner().scan(out)
    assert rescan.categories["author"].detected is False
    assert rescan.categories["copyright"].detected is False
    assert rescan.categories["device"].detected is True


def test_custom_profile_uses_explicit_categories(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    out = temp_dir / "custom.jpg"
    removal = MetadataRemover().clean(
        jpeg_with_gps_and_date,
        out,
        categories="gps",
        profile="custom",
        overwrite_output=True,
    )
    assert removal.success, removal.errors
    assert removal.categories_requested == ["gps"]
    assert removal.profile == "custom"


def test_unknown_profile_is_rejected(jpeg_with_exif: Path, temp_dir: Path) -> None:
    removal = MetadataRemover().clean(
        jpeg_with_exif, temp_dir / "x.jpg", profile="does-not-exist", overwrite_output=True
    )
    assert removal.success is False
    assert any("Unknown sanitization profile" in error for error in removal.errors)


def test_custom_profile_requires_categories(jpeg_with_exif: Path, temp_dir: Path) -> None:
    removal = MetadataRemover().clean(
        jpeg_with_exif, temp_dir / "custom_empty.jpg", profile="custom", categories=[], overwrite_output=True
    )
    assert removal.success is False
    assert any("requires at least one" in error.lower() for error in removal.errors)


def test_empty_categories_rejected(jpeg_with_exif: Path, temp_dir: Path) -> None:
    removal = MetadataRemover().clean(
        jpeg_with_exif, temp_dir / "empty_cats.jpg", categories=[], overwrite_output=True
    )
    assert removal.success is False
    assert any("No valid metadata categories" in error for error in removal.errors)


def test_selective_removal_warns_about_residuals(
    jpeg_with_exif: Path, temp_dir: Path
) -> None:
    removal = MetadataRemover().clean(
        jpeg_with_exif, temp_dir / "sel.jpg", categories="gps", overwrite_output=True
    )
    assert removal.success, removal.errors
    assert any("Selective metadata removal" in warning for warning in removal.warnings)
    assert "author" in removal.preserved_categories
