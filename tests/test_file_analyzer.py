"""Tests for deep, non-trusted file/container analysis."""

from __future__ import annotations

from pathlib import Path

from PIL import Image

from modules.file_analyzer import FileAnalyzer, FindingKind
from modules.metadata_scanner import MetadataScanner


def test_clean_jpeg_structure(clean_jpeg: Path) -> None:
    analysis = FileAnalyzer().analyze(clean_jpeg)
    assert analysis.detected_format == "JPEG"
    assert analysis.mime_type == "image/jpeg"
    assert analysis.declared_extension == ".jpg"
    assert analysis.extension_matches is True
    assert analysis.end_marker_found is True
    assert analysis.trailing_data_bytes == 0
    assert analysis.bit_depth == 8
    assert analysis.color_model == "RGB"
    assert analysis.n_frames == 1
    assert analysis.confirmed_findings == []


def test_extension_mismatch_is_detected(temp_dir: Path) -> None:
    path = temp_dir / "actually_png.jpg"
    Image.new("RGB", (16, 16), "blue").save(path, format="PNG")

    analysis = FileAnalyzer().analyze(path)
    assert analysis.detected_format == "PNG"
    assert analysis.declared_extension == ".jpg"
    assert analysis.extension_matches is False
    codes = {finding.code for finding in analysis.confirmed_findings}
    assert "extension_mismatch" in codes
    mismatch = next(f for f in analysis.findings if f.code == "extension_mismatch")
    assert mismatch.kind == FindingKind.CONFIRMED
    assert "PNG" in mismatch.detail


def test_trailing_data_is_detected(clean_jpeg: Path, temp_dir: Path) -> None:
    path = temp_dir / "with_trailer.jpg"
    path.write_bytes(clean_jpeg.read_bytes() + b"\x50\x4b\x03\x04hidden-payload")

    analysis = FileAnalyzer().analyze(path)
    assert analysis.end_marker_found is True
    assert analysis.trailing_data_bytes > 0
    assert analysis.trailing_data_preview
    trailer = next(f for f in analysis.findings if f.code == "trailing_data_jpeg")
    assert trailer.kind == FindingKind.SUSPICIOUS
    # Evidence must be a hex preview, never interpreted as text.
    assert "hidden-payload" not in trailer.detail


def test_png_alpha_and_header_parsing(transparent_png: Path) -> None:
    analysis = FileAnalyzer().analyze(transparent_png)
    assert analysis.detected_format == "PNG"
    assert analysis.has_alpha is True
    assert analysis.bit_depth == 8
    assert analysis.color_model in ("Grayscale + alpha", "Truecolour + alpha")
    assert analysis.extension_matches is True


def test_webp_and_tiff_are_recognised(valid_webp: Path, valid_tiff: Path) -> None:
    webp = FileAnalyzer().analyze(valid_webp)
    assert webp.detected_format == "WEBP"
    assert webp.extension_matches is True

    tiff = FileAnalyzer().analyze(valid_tiff)
    assert tiff.detected_format == "TIFF"
    assert tiff.extension_matches is True


def test_unknown_container_is_confirmed(temp_dir: Path) -> None:
    path = temp_dir / "not_an_image.png"
    path.write_bytes(b"just some text bytes, definitely not an image")
    analysis = FileAnalyzer().analyze(path)
    assert analysis.detected_format is None
    assert analysis.extension_matches is False
    assert any(f.code == "unknown_container" for f in analysis.confirmed_findings)


def test_deep_scan_attaches_analysis(clean_jpeg: Path) -> None:
    scanner = MetadataScanner()
    standard = scanner.scan(clean_jpeg)
    assert standard.file_analysis is None

    deep = scanner.scan(clean_jpeg, mode="deep")
    assert deep.file_analysis is not None
    assert deep.file_analysis.detected_format == "JPEG"
    assert deep.mode == "deep"


def test_embedded_thumbnail_finding_is_reported_when_present(temp_dir: Path) -> None:
    path = temp_dir / "thumb.jpg"
    Image.new("RGB", (32, 32), "green").save(path, "JPEG")

    class _FakeTag:
        name = "ThumbnailImage"
        display_value = "(binary)"

    class _FakeScan:
        metadata_group_counts = {"EXIF": 1}
        image_metadata = {"IFD1:ThumbnailImage": _FakeTag()}
        warnings = []

    analysis = FileAnalyzer().analyze(path, scan=_FakeScan())
    assert analysis.embedded_thumbnail_tags == ["ThumbnailImage"]
    thumb = next(f for f in analysis.findings if f.code == "embedded_preview")
    assert thumb.kind == FindingKind.SUSPICIOUS


def test_bmp_structure_and_trailing_data(temp_dir: Path) -> None:
    path = temp_dir / "sample.bmp"
    Image.new("RGB", (16, 16), "red").save(path, "BMP")

    analysis = FileAnalyzer().analyze(path)
    assert analysis.detected_format == "BMP"
    assert analysis.end_marker_found is True
    assert analysis.trailing_data_bytes == 0

    # Append trailing bytes to BMP
    path_trailing = temp_dir / "trailing.bmp"
    path_trailing.write_bytes(path.read_bytes() + b"\xde\xad\xbe\xef")

    analysis_trailing = FileAnalyzer().analyze(path_trailing)
    assert analysis_trailing.end_marker_found is True
    assert analysis_trailing.trailing_data_bytes == 4
    assert any(f.code == "trailing_data_bmp" for f in analysis_trailing.findings)


def test_webp_trailing_data_and_size_mismatch(valid_webp: Path, temp_dir: Path) -> None:
    # Clean WEBP
    analysis = FileAnalyzer().analyze(valid_webp)
    assert analysis.detected_format == "WEBP"
    assert analysis.end_marker_found is True
    assert analysis.trailing_data_bytes == 0

    # WEBP with trailer
    path_trailing = temp_dir / "trailing.webp"
    path_trailing.write_bytes(valid_webp.read_bytes() + b"extra_trailer")
    analysis_trailing = FileAnalyzer().analyze(path_trailing)
    assert analysis_trailing.trailing_data_bytes == len(b"extra_trailer")
    assert any(f.code == "trailing_data_webp" for f in analysis_trailing.findings)

    # Truncated WEBP
    path_truncated = temp_dir / "truncated.webp"
    path_truncated.write_bytes(valid_webp.read_bytes()[:20])
    analysis_truncated = FileAnalyzer().analyze(path_truncated)
    assert any(f.code == "webp_size_mismatch" for f in analysis_truncated.findings)
