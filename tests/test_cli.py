"""End-to-end CLI tests: exit codes, quiet/color output, reports."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=timeout,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_version_flag() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    assert "MetaClean 2.0.0" in result.stdout


def test_info_json_is_machine_readable() -> None:
    result = run_cli("info", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "MetaClean"
    assert payload["scan_modes"] == ["standard", "deep", "privacy", "full"]
    assert {p["key"] for p in payload["profiles"]} == {
        "basic", "location", "personal", "maximum", "custom"
    }
    assert len(payload["privacy_levels"]) == 5
    assert payload["exit_codes"]["0"].startswith("success")


def test_scan_quiet_has_no_stdout(clean_jpeg: Path) -> None:
    result = run_cli("scan", str(clean_jpeg), "-q")
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_scan_no_color(temp_dir: Path) -> None:
    image = temp_dir / "color.jpg"
    from PIL import Image
    Image.new("RGB", (16, 16), "red").save(image, "JPEG")

    result = run_cli("scan", str(image), "--no-color")
    assert result.returncode == 0
    assert "\033[" not in result.stdout


def test_scan_invalid_file_exits_2(temp_dir: Path) -> None:
    missing = temp_dir / "missing.jpg"
    result = run_cli("scan", str(missing))
    assert result.returncode == 2
    assert "validation failed" in result.stderr.lower()


def test_scan_fail_on_risk(jpeg_with_gps_and_date: Path) -> None:
    result = run_cli("scan", str(jpeg_with_gps_and_date), "--fail-on-risk", "-q")
    assert result.returncode == 1


def test_clean_verify_roundtrip(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    original_hash = _sha256(jpeg_with_gps_and_date)
    output = temp_dir / "cli_clean.jpg"

    clean = run_cli(
        "clean", str(jpeg_with_gps_and_date),
        "--profile", "maximum", "--output", str(output), "--yes", "-q",
    )
    assert clean.returncode == 0, clean.stderr
    assert output.exists()
    assert _sha256(jpeg_with_gps_and_date) == original_hash

    verify = run_cli(
        "verify", str(output),
        "--profile", "maximum", "--original", str(jpeg_with_gps_and_date), "-q",
    )
    assert verify.returncode == 0, verify.stderr


def test_clean_selective_reports_warning(jpeg_with_exif: Path, temp_dir: Path) -> None:
    output = temp_dir / "selective.jpg"
    result = run_cli(
        "clean", str(jpeg_with_exif),
        "--profile", "location", "--output", str(output), "--yes",
    )
    # Location profile leaves author data intact, so verification is partial.
    assert result.returncode == 1
    assert "PARTIALLY CLEANED" in result.stdout
    assert output.exists()


def test_report_defaults_to_redacted(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    output = temp_dir / "report.json"
    result = run_cli("report", str(jpeg_with_gps_and_date), "-o", str(output), "-q")
    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["report"]["redacted"] is True
    assert data["gps"]["latitude"] == "[REDACTED]"


def test_report_unredacted_opt_in_warns(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    output = temp_dir / "plain.json"
    result = run_cli(
        "report", str(jpeg_with_gps_and_date),
        "-o", str(output), "--no-redact", "--yes", "-q",
    )
    assert result.returncode == 0
    assert "unredacted sensitive" in result.stderr.lower()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["report"]["redacted"] is False
    assert isinstance(data["gps"]["latitude"], float)


def test_scan_html_report(temp_dir: Path) -> None:
    from PIL import Image
    image = temp_dir / "html.jpg"
    Image.new("RGB", (16, 16), "green").save(image, "JPEG")
    output = temp_dir / "scan.html"

    result = run_cli(
        "scan", str(image), "--report", str(output), "--format", "html", "-q"
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_batch_scan_only_json(temp_dir: Path) -> None:
    from PIL import Image
    in_dir = temp_dir / "batch"
    in_dir.mkdir()
    Image.new("RGB", (16, 16), "red").save(in_dir / "a.jpg", "JPEG")
    Image.new("RGB", (16, 16), "blue").save(in_dir / "b.jpg", "JPEG")
    report = temp_dir / "summary.json"

    result = run_cli(
        "batch", str(in_dir), "--scan-only", "--format", "json",
        "--report", str(report), "-q",
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["scan_only"] is True
    assert data["summary"]["total"] == 2
    assert len(data["results"]) == 2


def test_usage_error_exit_code() -> None:
    result = run_cli("this-command-does-not-exist")
    assert result.returncode == 3
    assert "error" in result.stderr.lower()


def test_help_exits_zero() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "info" in result.stdout
