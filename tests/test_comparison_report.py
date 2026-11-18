"""Tests for before/after comparison and JSON/CSV/HTML report generation."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from PIL import Image

from modules.comparison import compare_scans
from modules.image_validator import ValidationResult
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner, MetadataTag, ScanResult
import config
from modules.report_generator import (
    _csv_safe,
    export_batch_csv,
    export_batch_html,
    export_batch_json,
    export_batch_report,
    export_metadata_csv,
    export_report,
    export_json_report,
    export_html_report,
)


def test_comparison_reports_removed_and_remaining(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    scanner = MetadataScanner()
    before = scanner.scan(jpeg_with_gps_and_date)
    out = temp_dir / "cleaned.jpg"
    assert MetadataRemover().clean(
        jpeg_with_gps_and_date, out, profile="maximum", overwrite_output=True
    ).success
    after = scanner.scan(out)

    comparison = compare_scans(before, after)
    assert comparison.before_total > comparison.after_total
    assert comparison.removed_count > 0
    assert comparison.sensitive_removed_count > 0
    assert comparison.sensitive_remaining_count == 0
    assert comparison.after_risk_score <= comparison.before_risk_score
    assert comparison.all_sensitive_removed is True
    assert comparison.introduced_count == 0
    assert "GPS:GPSLatitude" in comparison.removed_tags


def test_comparison_and_verifier_structural_classification_consistency() -> None:
    """comparison.py and metadata_verifier.py must use identical structural rules."""
    tag_orient = MetadataTag(name="Orientation", value=1, group="IFD0", category="informational", key="IFD0:Orientation")
    tag_comp_size = MetadataTag(name="ImageSize", value="64x64", group="Composite", category="informational", derived=True, key="Composite:ImageSize")
    tag_comp_gps = MetadataTag(name="GPSPosition", value="37.7749 -122.4194", group="Composite", category="gps", derived=True, key="Composite:GPSPosition")
    tag_iptc_orient = MetadataTag(name="Orientation", value="Landscape", group="IPTC", category="informational", key="IPTC:Orientation")
    tag_artist = MetadataTag(name="Artist", value="Alice", group="IFD0", category="author", key="IFD0:Artist")

    tags = {
        "IFD0:Orientation": tag_orient,
        "Composite:ImageSize": tag_comp_size,
        "Composite:GPSPosition": tag_comp_gps,
        "IPTC:Orientation": tag_iptc_orient,
        "IFD0:Artist": tag_artist,
    }

    dummy_path = Path("test.jpg")
    scan = ScanResult(
        file_path=dummy_path,
        validation=ValidationResult(file_path=dummy_path, is_valid=True),
        scanner_backend="exiftool",
        backend_version=config.EXIFTOOL_VERSION,
        filesystem_metadata={},
        image_metadata=tags,
        categories={},
        inspection_complete=True,
    )

    comparison = compare_scans(scan, scan)

    # Legitimate structural tags are classified as structural_remaining
    assert "IFD0:Orientation" in comparison.structural_remaining
    assert "Composite:ImageSize" in comparison.structural_remaining

    # Non-structural tags (including non-structural derived tags) must NOT be structural_remaining
    assert "Composite:GPSPosition" not in comparison.structural_remaining
    assert "Composite:GPSPosition" in comparison.remaining_tags
    assert "IPTC:Orientation" not in comparison.structural_remaining
    assert "IPTC:Orientation" in comparison.remaining_tags
    assert "IFD0:Artist" not in comparison.structural_remaining
    assert "IFD0:Artist" in comparison.remaining_tags

    # In metadata_verifier, residual non-structural tags follow the identical classification
    residual_tags = [
        key for key, t in scan.image_metadata.items()
        if not t.derived and not config.is_structural_tag(t.group, t.name)
    ]
    assert "IFD0:Orientation" not in residual_tags
    assert "IPTC:Orientation" in residual_tags
    assert "IFD0:Artist" in residual_tags


def test_json_report_redacts_sensitive_values(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    scan = MetadataScanner().scan(jpeg_with_gps_and_date)
    report_path = temp_dir / "redacted.json"
    saved = export_json_report(report_path, scan, redact=True)

    data = json.loads(saved.read_text(encoding="utf-8"))
    assert data["report"]["redacted"] is True
    assert data["redacted_report"] is True
    # F-08 allowlist: neither the path nor the filename may survive redaction.
    assert data["input_file"]["path"] == "[REDACTED]"
    assert data["input_file"]["filename"] == "[REDACTED]"
    assert jpeg_with_gps_and_date.name not in saved.read_text(encoding="utf-8")
    assert data["gps"]["latitude"] == "[REDACTED]"
    assert data["gps"]["google_maps_url"] is None

    tags = {f"{t['group']}:{t['name']}": t for t in data["metadata_scan"]["tags"]}
    assert tags["GPS:GPSLatitude"]["value"] == "[REDACTED]"
    assert tags["GPS:GPSLatitude"]["redacted"] is True
    # Structural tags are not sensitive and remain visible.
    assert tags["File:FileType"]["redacted"] is False


def test_json_report_unredacted_contains_values(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    scan = MetadataScanner().scan(jpeg_with_gps_and_date)
    report_path = temp_dir / "plain.json"
    export_json_report(report_path, scan, redact=False)
    data = json.loads(report_path.read_text(encoding="utf-8"))

    assert data["report"]["redacted"] is False
    assert isinstance(data["gps"]["latitude"], float)
    assert data["gps"]["google_maps_url"].startswith("https://www.google.com/maps")


def test_html_report_escapes_metadata_values(temp_dir: Path) -> None:
    path = temp_dir / "evil.jpg"
    img = Image.new("RGB", (16, 16), "white")
    exif = img.getexif()
    exif[0x013B] = "<script>alert('xss')</script>"
    img.save(path, "JPEG", exif=exif)

    scan = MetadataScanner().scan(path)
    report_path = temp_dir / "report.html"
    export_html_report(report_path, scan, redact=False)
    document = report_path.read_text(encoding="utf-8")

    assert "&lt;script&gt;" in document
    assert "<script>alert('xss')</script>" not in document
    assert document.startswith("<!DOCTYPE html>")
    assert "Methodology" in document


def test_csv_export_neutralises_formula_injection(temp_dir: Path) -> None:
    path = temp_dir / "formula.jpg"
    img = Image.new("RGB", (16, 16), "white")
    exif = img.getexif()
    exif[0x013B] = '=HYPERLINK("http://attacker.example","click")'
    img.save(path, "JPEG", exif=exif)

    scan = MetadataScanner().scan(path)
    out = temp_dir / "tags.csv"
    export_metadata_csv(out, scan, redact=False)

    with open(out, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    artist = next(row for row in rows if row["tag"] == "Artist")
    assert artist["value"].startswith("'=")


def test_csv_safe_preserves_negative_numbers_and_strips_controls() -> None:
    # Legitimate negative numeric coordinates and offsets must not be mangled
    assert _csv_safe("-122.4194") == "-122.4194"
    assert _csv_safe("-0.5") == "-0.5"
    assert _csv_safe("-5") == "-5"

    # Formula injection vectors must be single-quote prefixed
    assert _csv_safe("=SUM(A1:A10)") == "'=SUM(A1:A10)"
    assert _csv_safe("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert _csv_safe("@SUM(B1)") == "'@SUM(B1)"
    assert _csv_safe("-cmd|' /C calc'!A0") == "'-cmd|' /C calc'!A0"

    # Dangerous control characters must be stripped
    assert _csv_safe("line1\r\nline2") == "line1line2"
    assert _csv_safe("\t=1+1") == "'=1+1"


def test_csv_export_redacts_sensitive_values(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    scan = MetadataScanner().scan(jpeg_with_gps_and_date)
    out = temp_dir / "redacted.csv"
    export_metadata_csv(out, scan, redact=True)
    with open(out, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    gps_row = next(row for row in rows if row["tag"] in ("GPSLatitude", "GPSLongitude"))
    assert gps_row["value"] == "[REDACTED]"


def test_export_report_dispatch_and_errors(clean_jpeg: Path, temp_dir: Path) -> None:
    scan = MetadataScanner().scan(clean_jpeg)
    for fmt in ("json", "html", "csv"):
        path = export_report(temp_dir / f"r.{fmt}", fmt, scan=scan)
        assert path.exists()

    with pytest.raises(ValueError, match="Unsupported report format"):
        export_report(temp_dir / "r.xml", "xml", scan=scan)

    with pytest.raises(ValueError, match="Unsupported batch report format"):
        export_batch_report([], temp_dir / "b.xml", "xml")


def test_batch_exports_json_csv_html(temp_dir: Path) -> None:
    records = [
        {
            "file_name": "a.jpg",
            "validation": "VALID",
            "format": "JPEG",
            "original_size": 100,
            "cleaned_size": 80,
            "bytes_saved": 20,
            "privacy_risk": "HIGH",
            "risk_score": 40,
            "gps_detected": True,
            "author_detected": False,
            "date_detected": True,
            "removal_status": "COMPLETED",
            "verification_status": "PASS",
            "verification_outcome": "VERIFIED CLEAN",
            "output_path": "/tmp/a_clean.jpg",
            "notes": "",
        }
    ]
    summary = {"total": 1, "success": 1}

    json_path = export_batch_json(records, temp_dir / "b.json", summary)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["results"][0]["verification_outcome"] == "VERIFIED CLEAN"

    html_path = export_batch_html(records, temp_dir / "b.html", summary)
    document = html_path.read_text(encoding="utf-8")
    assert "Batch Summary" in document
    assert "VERIFIED CLEAN" in document

    csv_path = export_batch_csv(records, temp_dir / "b.csv")
    with open(csv_path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["verification_outcome"] == "VERIFIED CLEAN"
