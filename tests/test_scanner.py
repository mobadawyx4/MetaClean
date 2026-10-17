"""Automated unit and integration tests for metadata_scanner and privacy_analyzer.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from modules.metadata_scanner import MetadataScanner
from modules.privacy_analyzer import RiskLevel, RuleBasedPrivacyAnalyzer


def test_scan_jpeg_with_gps_and_date(jpeg_with_gps_and_date: Path) -> None:
    """Verifies GPS and date extraction and HIGH privacy risk assessment."""
    scanner = MetadataScanner()
    res = scanner.scan(jpeg_with_gps_and_date)

    assert res.validation.is_valid is True
    assert res.categories["gps"].detected is True
    assert len(res.categories["gps"].tags) > 0

    assert res.privacy_report is not None
    assert res.privacy_report.overall_risk == RiskLevel.HIGH
    assert res.privacy_report.risk_score >= 70
    assert res.privacy_report.high_risk_count > 0

    # Ensure GPS explanation is included
    high_items = [i for i in res.privacy_report.items if i.risk_level == RiskLevel.HIGH]
    assert any("geographical coordinates" in i.explanation.lower() for i in high_items)


def test_scan_jpeg_with_device_and_author(jpeg_with_exif: Path) -> None:
    """Verifies camera device, author, and copyright metadata detection."""
    scanner = MetadataScanner()
    res = scanner.scan(jpeg_with_exif)

    assert res.validation.is_valid is True
    assert res.categories["device"].detected is True
    assert res.categories["author"].detected is True
    assert res.categories["copyright"].detected is True

    # Device & author should be classified as MEDIUM or HIGH
    assert res.privacy_report is not None
    assert res.privacy_report.overall_risk in (RiskLevel.HIGH, RiskLevel.MEDIUM)


def test_scan_clean_image_without_metadata(clean_jpeg: Path) -> None:
    """Verifies clean images contain no detected categories and produce low/informational risk."""
    scanner = MetadataScanner()
    res = scanner.scan(clean_jpeg)

    assert res.validation.is_valid is True
    assert res.categories["gps"].detected is False
    assert res.categories["author"].detected is False

    assert res.privacy_report is not None
    assert res.privacy_report.overall_risk in (RiskLevel.LOW, RiskLevel.INFORMATIONAL)
    assert res.privacy_report.high_risk_count == 0


def test_filesystem_metadata_separation(clean_jpeg: Path) -> None:
    """Verifies filesystem attributes (mtime, ctime) are isolated from embedded tags."""
    scanner = MetadataScanner()
    res = scanner.scan(clean_jpeg)

    assert "fs_modified" in res.filesystem_metadata
    assert "fs_created" in res.filesystem_metadata
    # Filesystem attributes must not be included in image embedded tags
    for tag in res.image_metadata.values():
        assert tag.is_filesystem is False


def test_scanner_pillow_fallback_when_exiftool_missing(jpeg_with_exif: Path) -> None:
    """Verifies graceful fallback to Pillow engine when ExifTool is not available."""
    # Initialize scanner with simulated missing ExifTool
    scanner = MetadataScanner(exiftool_path=None)
    scanner.exiftool_available = False

    res = scanner.scan(jpeg_with_exif)
    assert res.validation.is_valid is True
    assert res.scanner_backend == "pillow_fallback"
    assert len(res.limitations) > 0
    assert any("fallback" in lim.lower() for lim in res.limitations)
    # Pillow fallback should still extract EXIF device tags
    assert res.categories["device"].detected is True


def test_scan_corrupted_image(corrupted_image: Path) -> None:
    """Verifies scanner handles corrupted images safely without crashing."""
    scanner = MetadataScanner()
    res = scanner.scan(corrupted_image)
    assert res.validation.is_valid is False
    assert res.scanner_backend == "none"
    assert len(res.image_metadata) == 0


def test_privacy_analyzer_direct_rules() -> None:
    """Unit test for RuleBasedPrivacyAnalyzer tag classification."""
    analyzer = RuleBasedPrivacyAnalyzer()

    # High risk GPS
    item_gps = analyzer.evaluate_tag("GPSLatitude", "37.7749", group="GPS")
    assert item_gps.risk_level == RiskLevel.HIGH
    assert "37.7749" in item_gps.value_preview

    # Medium risk Serial Number
    item_serial = analyzer.evaluate_tag("SerialNumber", "SN12345678", group="ExifIFD")
    assert item_serial.risk_level == RiskLevel.MEDIUM
    assert "****" in item_serial.value_preview

    # Low risk technical ISO
    item_iso = analyzer.evaluate_tag("ISO", 100, group="ExifIFD")
    assert item_iso.risk_level == RiskLevel.LOW

    # Informational
    item_dim = analyzer.evaluate_tag("ImageWidth", 1920, group="File")
    assert item_dim.risk_level == RiskLevel.INFORMATIONAL
def test_icc_profile_tags_are_informational():
    """ICC color-profile tags must not be misclassified as personal metadata."""
    from modules.metadata_scanner import MetadataScanner

    scanner = MetadataScanner()

    assert scanner._classify_tag("ICC_Profile", "ProfileDateTime")[0] == "informational"
    assert scanner._classify_tag("ICC_Profile", "DeviceModel")[0] == "informational"
    assert scanner._classify_tag("ICC_Profile", "ProfileCreator")[0] == "informational"
    assert scanner._classify_tag("ICC_Profile", "ProfileCopyright")[0] == "informational"
    assert scanner._classify_tag("ICC_Profile", "ProfileDescription")[0] == "informational"


def test_real_gps_and_author_tags_are_still_detected():
    """Actual GPS and author tags must retain their sensitive classifications."""
    from modules.metadata_scanner import MetadataScanner

    scanner = MetadataScanner()

    assert scanner._classify_tag("GPS", "GPSLatitude")[0] == "gps"
    assert scanner._classify_tag("IFD0", "Artist")[0] == "author"
