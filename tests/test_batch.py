"""Automated unit and integration tests for batch_processor module.
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from PIL import Image

from modules.batch_processor import BatchProcessor, generate_collision_free_path
from modules.metadata_verifier import VerificationStatus
from modules.report_generator import export_batch_csv


def test_batch_process_mixed_valid_and_invalid(temp_dir: Path) -> None:
    """Verifies batch processing continues when encountering corrupted files."""
    in_dir = temp_dir / "input_images"
    out_dir = temp_dir / "cleaned_output"
    in_dir.mkdir()
    out_dir.mkdir()

    # 1. Valid image 1
    im1 = Image.new("RGB", (32, 32), "green")
    im1.save(in_dir / "img1.jpg", "JPEG")

    # 2. Corrupted file
    with open(in_dir / "corrupted.jpg", "wb") as f:
        f.write(b"\xff\xd8\xffCORRUPT_BYTES_TRUNCATED")

    # 3. Valid image 2
    im2 = Image.new("RGBA", (32, 32), (0, 0, 255, 128))
    im2.save(in_dir / "img2.png", "PNG")

    processor = BatchProcessor()
    summary = processor.process_batch(
        input_dir=in_dir,
        output_dir=out_dir,
        categories="all",
        overwrite=True,
    )

    assert summary.total_found == 3
    assert summary.success_count == 2
    assert summary.failure_count == 1
    assert summary.pass_count >= 1

    # Check output directory
    assert (out_dir / "img1.jpg").exists()
    assert (out_dir / "img2.png").exists()
    assert not (out_dir / "corrupted.jpg").exists()


def test_batch_filename_collision_avoidance(temp_dir: Path) -> None:
    """Verifies that filename collisions generate non-destructive suffixes."""
    dest_dir = temp_dir / "dest"
    dest_dir.mkdir()

    # Create an existing file
    (dest_dir / "photo.jpg").write_text("existing")

    # Generate collision-free path
    free_path1 = generate_collision_free_path(dest_dir, "photo.jpg")
    assert free_path1.name == "photo_1.jpg"

    # Create photo_1.jpg and check next
    free_path1.write_text("existing 2")
    free_path2 = generate_collision_free_path(dest_dir, "photo.jpg")
    assert free_path2.name == "photo_2.jpg"


def test_batch_summary_csv_export(temp_dir: Path) -> None:
    """Verifies CSV batch summary generation."""
    records = [
        {
            "file_name": "pic1.jpg",
            "validation": "VALID",
            "format": "JPEG",
            "original_size": 2048,
            "cleaned_size": 1024,
            "bytes_saved": 1024,
            "privacy_risk": "HIGH",
            "risk_score": 85,
            "gps_detected": True,
            "author_detected": False,
            "date_detected": True,
            "removal_status": "COMPLETED",
            "verification_status": "PASS",
            "output_path": str(temp_dir / "cleaned" / "pic1.jpg"),
            "notes": "",
        }
    ]

    csv_out = temp_dir / "batch_report.csv"
    export_batch_csv(records, csv_out)

    assert csv_out.exists()
    with open(csv_out, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["file_name"] == "pic1.jpg"
        assert rows[0]["verification_status"] == "PASS"
        assert rows[0]["gps_detected"] == "True"


def test_batch_preserves_original_files(temp_dir: Path) -> None:
    """Verifies that all files in the batch input directory remain unchanged."""
    in_dir = temp_dir / "src"
    out_dir = temp_dir / "dst"
    in_dir.mkdir()
    out_dir.mkdir()

    img_path = in_dir / "test.jpg"
    im = Image.new("RGB", (20, 20), "red")
    im.save(img_path, "JPEG")
    orig_mtime = img_path.stat().st_mtime_ns
    orig_size = img_path.stat().st_size

    processor = BatchProcessor()
    processor.process_batch(in_dir, out_dir, categories="all", overwrite=True)

    # Re-verify original file attributes
    assert img_path.exists()
    assert img_path.stat().st_size == orig_size
    assert img_path.stat().st_mtime_ns == orig_mtime
