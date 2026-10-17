"""Automated unit and integration tests for metadata_verifier module.
"""

from __future__ import annotations

from pathlib import Path

from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationStatus


def test_verify_clean_image_passes(clean_jpeg: Path) -> None:
    """Verifies that an image without metadata returns PASS."""
    verifier = MetadataVerifier()
    rep = verifier.verify(clean_jpeg, targeted_categories=["all"])

    assert rep.status == VerificationStatus.PASS
    assert len(rep.remaining_targeted_tags) == 0
    assert all(c.status == VerificationStatus.PASS for c in rep.category_checks)


def test_verify_uncleaned_image_fails_or_warns(jpeg_with_gps_and_date: Path) -> None:
    """Verifies that an image retaining targeted GPS metadata fails full verification."""
    verifier = MetadataVerifier()
    rep = verifier.verify(jpeg_with_gps_and_date, targeted_categories=["all"])

    assert rep.status in (VerificationStatus.FAIL, VerificationStatus.WARNING)
    assert len(rep.remaining_targeted_tags) > 0
    gps_check = next((c for c in rep.category_checks if c.category == "gps"), None)
    assert gps_check is not None
    assert gps_check.status != VerificationStatus.PASS


def test_verify_selective_removal(jpeg_with_gps_and_date: Path, temp_dir: Path) -> None:
    """Verifies targeted category check when only GPS was removed."""
    cleaned_file = temp_dir / "gps_only_cleaned.jpg"
    remover = MetadataRemover()
    rem_res = remover.clean(
        input_path=jpeg_with_gps_and_date,
        output_path=cleaned_file,
        categories=["gps"],
        overwrite_output=True,
    )
    assert rem_res.success is True

    verifier = MetadataVerifier()
    # Verify ONLY gps: targeted GPS passed, but overall warns because unselected date remains
    rep = verifier.verify(cleaned_file, targeted_categories=["gps"])
    gps_check = next((c for c in rep.category_checks if c.category == "gps"), None)
    assert gps_check is not None
    assert gps_check.status == VerificationStatus.PASS
    assert rep.status == VerificationStatus.WARNING
    assert "unselected sensitive tags remain" in rep.summary_message

    # Now verify when both GPS and Date are targeted: both pass, and overall PASS
    rem_res2 = remover.clean(
        input_path=jpeg_with_gps_and_date,
        output_path=temp_dir / "all_sensitive_cleaned.jpg",
        categories=["gps", "date"],
        overwrite_output=True,
    )
    rep2 = verifier.verify(temp_dir / "all_sensitive_cleaned.jpg", targeted_categories=["gps", "date"])
    assert rep2.status == VerificationStatus.PASS


def test_verify_nonexistent_file(temp_dir: Path) -> None:
    """Verifies verification on missing file returns FAIL."""
    verifier = MetadataVerifier()
    rep = verifier.verify(temp_dir / "missing.jpg")
    assert rep.status == VerificationStatus.FAIL


def test_verify_corrupted_file(corrupted_image: Path) -> None:
    """Verifies verification on corrupted file returns FAIL."""
    verifier = MetadataVerifier()
    rep = verifier.verify(corrupted_image)
    assert rep.status == VerificationStatus.FAIL


def test_verify_incomplete_when_backend_limited(clean_jpeg: Path) -> None:
    """Verifies status is INCOMPLETE when ExifTool is unavailable and full check cannot inspect IPTC/XMP."""
    scanner = MetadataScanner(exiftool_path=None)
    scanner.exiftool_available = False

    verifier = MetadataVerifier(scanner=scanner)
    rep = verifier.verify(clean_jpeg, targeted_categories=["all"])

    # When ExifTool is unavailable, verification must report INCOMPLETE
    assert rep.status == VerificationStatus.INCOMPLETE
    assert any("incomplete" in lim.lower() or "pillow" in lim.lower() for lim in rep.limitations)
