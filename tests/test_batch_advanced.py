"""Tests for batch safety features: scan-only, duplicates, symlinks, limits."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from PIL import Image

from modules.batch_processor import BatchProcessor, generate_collision_free_path
from modules.metadata_scanner import MetadataScanner
import config


def _make_image(path: Path, color: str = "red") -> None:
    Image.new("RGB", (24, 24), color).save(path, "JPEG")


def test_scan_only_writes_nothing(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    _make_image(in_dir / "a.jpg")
    _make_image(in_dir / "b.jpg", "blue")

    summary = BatchProcessor().process_batch(in_dir, scan_only=True)
    assert summary.scan_only is True
    assert summary.total_found == 2
    assert summary.success_count == 2
    assert summary.failure_count == 0
    assert all(result.output_path is None for result in summary.file_results)
    assert sorted(p.name for p in in_dir.iterdir()) == ["a.jpg", "b.jpg"]
    assert all(result.privacy_risk for result in summary.file_results)


def test_scan_only_needs_no_output_directory(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    _make_image(in_dir / "a.jpg")
    with pytest.raises(ValueError):
        BatchProcessor().process_batch(in_dir, output_dir=None, scan_only=False)


def test_duplicates_are_skipped_when_requested(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    _make_image(in_dir / "a.jpg", "green")
    (in_dir / "b.jpg").write_bytes((in_dir / "a.jpg").read_bytes())

    summary = BatchProcessor().process_batch(
        in_dir, out_dir, skip_duplicates=True, overwrite=True
    )
    assert summary.skipped_duplicates == 1
    assert len(summary.file_results) == 2
    skipped = [r for r in summary.file_results if r.skipped]
    assert len(skipped) == 1
    assert skipped[0].duplicate_of is not None


def test_symlinks_are_skipped_by_default(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    real = in_dir / "real.jpg"
    _make_image(real)
    link = in_dir / "link.jpg"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("Symlinks are not supported on this platform")

    summary = BatchProcessor().process_batch(in_dir, out_dir, overwrite=True)
    assert summary.skipped_symlinks >= 1
    names = [r.input_path.name for r in summary.file_results]
    assert names == ["real.jpg"]


def test_output_directory_is_excluded_from_recursive_discovery(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    out_dir = in_dir / "cleaned"
    (in_dir / "nested").mkdir(parents=True)
    _make_image(in_dir / "top.jpg")
    _make_image(in_dir / "nested" / "deep.jpg", "blue")

    processor = BatchProcessor()
    first = processor.process_batch(in_dir, out_dir, recursive=True, overwrite=True)
    assert first.total_found == 2
    assert (out_dir / "top.jpg").exists()

    second = processor.process_batch(in_dir, out_dir, recursive=True, overwrite=True)
    assert second.total_found == 2, "cleaned output must not be re-ingested as input"


def test_max_files_limit(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    for index in range(3):
        _make_image(in_dir / f"img{index}.jpg", ["red", "green", "blue"][index])

    summary = BatchProcessor().process_batch(
        in_dir, temp_dir / "out", max_files=2, overwrite=True
    )
    assert summary.total_found == 3
    assert summary.processed_count == 2
    assert len(summary.file_results) == 2


def test_batch_profile_cleaning(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    target = in_dir / "gps.jpg"
    target.write_bytes(jpeg_with_gps_and_date.read_bytes())

    summary = BatchProcessor().process_batch(
        in_dir, out_dir, profile="basic", overwrite=True
    )
    assert summary.failure_count == 0
    cleaned = out_dir / "gps.jpg"
    assert cleaned.exists()

    rescan = MetadataScanner().scan(cleaned)
    assert rescan.categories["gps"].detected is False
    assert rescan.categories["date"].detected is True
    assert summary.file_results[0].verification_outcome in (
        "VERIFIED CLEAN",
        "PARTIALLY CLEANED",
    )


def test_batch_isolates_corrupted_files(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    _make_image(in_dir / "good.jpg")
    (in_dir / "bad.jpg").write_bytes(b"\xff\xd8\xffnot-a-real-jpeg")

    summary = BatchProcessor().process_batch(in_dir, out_dir, overwrite=True)
    assert summary.total_found == 2
    assert summary.success_count == 1
    assert summary.failure_count == 1
    assert (out_dir / "good.jpg").exists()
    assert not (out_dir / "bad.jpg").exists()


# ---------------------------------------------------------------------------
# F-15: accurate batch counters and collision detection
# ---------------------------------------------------------------------------
def test_processed_equals_success_plus_failure(temp_dir: Path) -> None:
    """Every discovered file must land in exactly one of success/failure."""
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    _make_image(in_dir / "good.jpg")
    (in_dir / "bad.jpg").write_bytes(b"\xff\xd8\xffnot-a-real-jpeg")
    summary = BatchProcessor().process_batch(in_dir, out_dir, overwrite=True)
    assert summary.processed_count == summary.success_count + summary.failure_count
    assert summary.processed_count == summary.total_found
    assert summary.failure_count == 1
    assert summary.success_count == 1


def test_collision_free_path_increments(temp_dir: Path) -> None:
    out_dir = temp_dir / "out"
    out_dir.mkdir()
    (out_dir / "a.jpg").write_bytes(b"first")
    first = generate_collision_free_path(out_dir, "a.jpg")
    assert first.name == "a_1.jpg"
    first.write_bytes(b"second")
    second = generate_collision_free_path(out_dir, "a.jpg")
    assert second.name == "a_2.jpg"


def test_max_files_rejects_non_positive(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    _make_image(in_dir / "a.jpg")
    with pytest.raises(ValueError, match="positive integer"):
        BatchProcessor().process_batch(in_dir, temp_dir / "out", max_files=0, overwrite=True)
    with pytest.raises(ValueError, match="positive integer"):
        BatchProcessor().process_batch(in_dir, temp_dir / "out", max_files=-5, overwrite=True)


def test_max_files_rejects_above_ceiling(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    _make_image(in_dir / "a.jpg")
    with pytest.raises(ValueError, match="hard ceiling"):
        BatchProcessor().process_batch(
            in_dir, temp_dir / "out", max_files=config.MAX_BATCH_FILES_CEILING + 1,
            overwrite=True,
        )


def test_max_files_ceiling_is_respected(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    in_dir.mkdir()
    for index in range(5):
        _make_image(in_dir / f"img{index}.jpg", ["red", "green", "blue", "yellow", "black"][index])
    summary = BatchProcessor().process_batch(
        in_dir, temp_dir / "out", max_files=config.MAX_BATCH_FILES_CEILING, overwrite=True
    )
    assert summary.processed_count == 5
