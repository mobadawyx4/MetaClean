"""Redaction-by-default regression tests (F-08).

Policy under test: report exports are redacted unless the caller explicitly
passes ``redact=False``.  Redaction is an allowlist, so every metadata value
that is not an explicit container fact, every path/filename, and every
free-text preview is withheld.  A scrub pass additionally removes identifier
literals, e-mail addresses, phone numbers and home/temporary paths that appear
in fallback fields (warnings, limitations, narratives).

All fixtures are synthetic images written to pytest temporary directories.
"""

from __future__ import annotations

import csv
import inspect
import json
from pathlib import Path

import pytest
from PIL import Image

from modules.image_validator import ImageValidationError
from modules.json_encoder import JSONEncodingError
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner, MetadataTag
from modules.metadata_verifier import MetadataVerifier
from modules.report_generator import (
    _write_text_report,
    export_batch_csv,
    export_batch_html,
    export_batch_json,
    export_batch_report,
    export_html_report,
    export_json_report,
    export_metadata_csv,
    export_report,
)

PII_NAME = "Alice Example"
PII_EMAIL = "alice@example.com"
PII_PHONE = "+1 555 010 9999"
PII_SERIAL = "SN-SECRET-42"
PII_MODEL = "SecretCam 9000"


def _pii_image(path: Path) -> Path:
    """Synthetic JPEG carrying names, e-mail, phone, model and serial values."""
    image = Image.new("RGB", (32, 32), "white")
    exif = image.getexif()
    exif[0x010E] = f"Contact {PII_NAME} at {PII_EMAIL} or {PII_PHONE}"
    exif[0x013B] = PII_NAME
    exif[0x0131] = PII_MODEL
    exif[0x0110] = PII_SERIAL
    exif[0x8298] = f"(c) {PII_NAME}"
    image.save(path, "JPEG", exif=exif)
    return path


def _assert_no_pii(text: str, path: Path) -> None:
    markers = (
        PII_NAME,
        PII_EMAIL,
        PII_PHONE,
        PII_SERIAL,
        PII_MODEL,
        path.name,
        path.stem,
        str(path),
    )
    for marker in markers:
        assert marker not in text, f"redacted report leaked {marker!r}"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
def test_every_exporter_is_redacted_by_default() -> None:
    functions = (
        export_json_report,
        export_metadata_csv,
        export_html_report,
        export_report,
        export_batch_csv,
        export_batch_json,
        export_batch_html,
        export_batch_report,
    )
    for func in functions:
        default = inspect.signature(func).parameters["redact"].default
        assert default is True, f"{func.__name__} must default to redacted"


# ---------------------------------------------------------------------------
# Single-image reports
# ---------------------------------------------------------------------------
def test_json_report_is_redacted_by_default(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    out = tmp_path / "report.json"

    export_json_report(out, scan)

    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, path)

    data = json.loads(text)
    assert data["report"]["redacted"] is True
    assert data["redacted_report"] is True
    assert data["input_file"]["path"] == "[REDACTED]"
    assert data["input_file"]["filename"] == "[REDACTED]"

    tags = {tag["name"]: tag for tag in data["metadata_scan"]["tags"]}
    assert tags["Artist"]["value"] == "[REDACTED]"
    assert tags["Artist"]["redacted"] is True
    # Container facts remain available; they carry no personal information.
    if "FileType" in tags:
        assert tags["FileType"]["value"] != "[REDACTED]"
        assert tags["FileType"]["redacted"] is False

    # No privacy preview may survive by default.
    for item in data["privacy_risk_assessment"].get("assessed_tags", []):
        assert item["preview"] == "[REDACTED]"


def test_csv_report_is_redacted_by_default(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    out = tmp_path / "tags.csv"

    export_metadata_csv(out, scan)

    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, path)
    rows = list(csv.DictReader(text.splitlines()))
    assert rows
    assert all(row["file_name"] == "[REDACTED]" for row in rows)
    artist = next(row for row in rows if row["tag"] == "Artist")
    assert artist["value"] == "[REDACTED]"


def test_html_report_is_redacted_by_default(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    out = tmp_path / "report.html"

    export_html_report(out, scan)

    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, path)
    assert "REDACTED" in text


def test_verification_and_comparison_values_are_redacted(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    cleaned = tmp_path / "cleaned.jpg"
    scanner = MetadataScanner()

    assert MetadataRemover().clean(
        path, cleaned, categories=["all"], overwrite_output=True
    ).success
    cleaned_scan = scanner.scan(cleaned)
    verification = MetadataVerifier(scanner=scanner).verify(
        cleaned, original_image_path=path, profile="maximum"
    )

    out = tmp_path / "verify.json"
    export_json_report(out, cleaned_scan, verification=verification)

    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, path)

    comparison = json.loads(text)["verification"].get("comparison") or {}
    for change in comparison.get("changed_tags", []):
        assert change["before"] in ("[REDACTED]", None)
        assert change["after"] in ("[REDACTED]", None)


def test_free_text_fallback_fields_are_scrubbed(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    # Simulate fallback/diagnostic text that embeds identifiers.
    scan.warnings.append(f"Contact {PII_EMAIL} about {path}")
    scan.limitations.append(
        f"Could not cache {path.parent}/alice_private_photo.jpg; call {PII_PHONE}"
    )
    # Identifiers that never appear as metadata values, so only the free-text
    # patterns (not the literal scrubber) can remove them.
    scan.limitations.append(
        "Escalation contact: bob@other.example / +44 20 7946 0958; "
        "log at /home/alice/logs/report.log"
    )
    out = tmp_path / "fallback.json"

    export_json_report(out, scan)

    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, path)
    assert "bob@other.example" not in text
    assert "+44 20 7946 0958" not in text
    assert "/home/alice" not in text
    assert "[REDACTED-EMAIL]" in text
    assert "[REDACTED-PHONE]" in text
    assert "[REDACTED-PATH]" in text


def test_unredacted_export_is_an_explicit_opt_in(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    out = tmp_path / "plain.json"

    export_json_report(out, scan, redact=False)

    text = out.read_text(encoding="utf-8")
    assert PII_NAME in text
    assert json.loads(text)["report"]["redacted"] is False


# ---------------------------------------------------------------------------
# Batch reports
# ---------------------------------------------------------------------------
def _batch_records(path: Path) -> list[dict[str, object]]:
    return [
        {
            "file_name": "alice_private_photo.jpg",
            "validation": "VALID",
            "format": "JPEG",
            "original_size": 2048,
            "cleaned_size": 1024,
            "bytes_saved": 1024,
            "privacy_risk": "HIGH",
            "risk_score": 85,
            "gps_detected": True,
            "author_detected": True,
            "date_detected": True,
            "removal_status": "COMPLETED",
            "verification_status": "PASS",
            "verification_outcome": "VERIFIED CLEAN",
            "output_path": str(path / "alice_private_photo_clean.jpg"),
            "notes": f"duplicate of {path}/alice_private_photo.jpg",
        }
    ]


def test_batch_exports_are_redacted_by_default(tmp_path: Path) -> None:
    records = _batch_records(tmp_path)
    summary = {"total": 1, "operator": PII_EMAIL}

    json_out = export_batch_json(records, tmp_path / "b.json", summary)
    json_text = json_out.read_text(encoding="utf-8")
    _assert_no_pii(json_text, tmp_path / "alice_private_photo.jpg")
    assert PII_EMAIL not in json_text
    payload = json.loads(json_text)
    assert payload["report"]["redacted"] is True
    assert payload["results"][0]["file_name"] == "image_001"
    assert payload["results"][0]["output_path"] == "[REDACTED]"
    assert payload["results"][0]["notes"] == "[REDACTED]"
    assert payload["results"][0]["verification_outcome"] == "VERIFIED CLEAN"

    csv_out = export_batch_csv(records, tmp_path / "b.csv")
    csv_text = csv_out.read_text(encoding="utf-8")
    _assert_no_pii(csv_text, tmp_path / "alice_private_photo.jpg")
    assert list(csv.DictReader(csv_text.splitlines()))[0]["file_name"] == "image_001"

    html_out = export_batch_html(records, tmp_path / "b.html", summary)
    html_text = html_out.read_text(encoding="utf-8")
    _assert_no_pii(html_text, tmp_path / "alice_private_photo.jpg")
    assert PII_EMAIL not in html_text


def test_batch_unredacted_requires_explicit_flag(tmp_path: Path) -> None:
    records = _batch_records(tmp_path)
    out = export_batch_report(
        records, tmp_path / "b.csv", report_format="csv", redact=False
    )
    text = out.read_text(encoding="utf-8")
    assert "alice_private_photo.jpg" in text


def test_batch_record_fallback_fields_are_scrubbed(tmp_path: Path) -> None:
    records = _batch_records(tmp_path)
    # A field outside the current schema that echoes identifiers must still be
    # scrubbed; enum-like fields must survive untouched.
    records[0]["detail"] = (
        f"failed for alice_private_photo.jpg ({PII_EMAIL}) at "
        f"{tmp_path}/alice_private_photo.jpg"
    )

    out = export_batch_json(records, tmp_path / "b.json")
    text = out.read_text(encoding="utf-8")
    _assert_no_pii(text, tmp_path / "alice_private_photo.jpg")
    assert PII_EMAIL not in text

    payload = json.loads(text)
    row = payload["results"][0]
    assert row["format"] == "JPEG"
    assert row["verification_outcome"] == "VERIFIED CLEAN"
    assert "alice_private_photo" not in row["detail"]
    assert "[REDACTED]" in row["detail"]


# ---------------------------------------------------------------------------
# Export failure safety
# ---------------------------------------------------------------------------
def test_failed_json_export_preserves_existing_report(tmp_path: Path) -> None:
    path = _pii_image(tmp_path / "alice_private_photo.jpg")
    scan = MetadataScanner().scan(path)
    scan.image_metadata["XMP:Unsupported"] = MetadataTag(
        name="Unsupported", value=object(), group="XMP", category="xmp"
    )
    out = tmp_path / "existing.json"
    out.write_text("ORIGINAL REPORT", encoding="utf-8")

    with pytest.raises(JSONEncodingError, match="object"):
        export_json_report(out, scan, redact=False)

    assert out.read_text(encoding="utf-8") == "ORIGINAL REPORT"
    assert [
        p for p in tmp_path.iterdir() if p.name.startswith(".metaclean-report-")
    ] == []


def test_write_refuses_symlink_inserted_before_replace(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL", encoding="utf-8")
    link = tmp_path / "report.json"
    link.symlink_to(victim)

    with pytest.raises(ImageValidationError, match="symbolic link"):
        _write_text_report(link, "{\"report\": true}")

    assert victim.read_text(encoding="utf-8") == "ORIGINAL"
    assert link.is_symlink()
