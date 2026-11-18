"""Automated unit and integration tests for metadata_verifier module.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

import config
from modules.exiftool_backend import ExifToolReadResult
from modules.image_validator import ValidationResult
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner, MetadataTag, ScanResult
from modules.metadata_verifier import (
    MetadataVerifier,
    VerificationOutcome,
    VerificationStatus,
)


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
def test_pass_summary_does_not_claim_all_metadata_was_removed(
    clean_jpeg: Path,
) -> None:
    """PASS confirms targeted checks, not complete metadata removal."""
    verifier = MetadataVerifier()
    rep = verifier.verify(clean_jpeg, targeted_categories=["all"])

    assert rep.status == VerificationStatus.PASS
    assert "targeted metadata categories" in rep.summary_message.lower()
    assert "does not guarantee" in rep.summary_message.lower()


# ---------------------------------------------------------------------------
# Gate 0 — outcome invariants (F-01) and fail-closed inspection (F-02)
# ---------------------------------------------------------------------------
def _scan_result(*, inspection_complete: bool = True) -> ScanResult:
    """Builds a minimal valid ScanResult for direct outcome-decision tests."""
    target = Path("subject.jpg")
    return ScanResult(
        file_path=target,
        validation=ValidationResult(file_path=target, is_valid=True),
        scanner_backend="exiftool",
        backend_version=config.EXIFTOOL_VERSION,
        filesystem_metadata={},
        image_metadata={},
        categories={},
        inspection_complete=inspection_complete,
    )


@pytest.mark.parametrize("is_full_clean", [False, True])
def test_outcome_rejects_remaining_targeted_tags(is_full_clean: bool) -> None:
    """Any remaining targeted tag must block a VERIFIED CLEAN outcome."""
    tag = MetadataTag(
        name="Software",
        value="TopSecretEditor 9.9",
        group="IFD0",
        category="software",
    )

    outcome, reason = MetadataVerifier()._decide_outcome(
        scan=_scan_result(),
        active_targets=["software"],
        is_full_clean=is_full_clean,
        remaining_targeted_tags=[tag],
        remaining_sensitive=[],
        residual_metadata_tags=[],
        comparison=None,
    )

    assert outcome == VerificationOutcome.SENSITIVE_DATA_REMAINS
    assert reason


@pytest.mark.parametrize("is_full_clean", [False, True])
def test_outcome_allows_verified_clean_without_remaining_targeted_tags(
    is_full_clean: bool,
) -> None:
    """With no targeted tags left, a complete inspection may certify clean."""
    outcome, _ = MetadataVerifier()._decide_outcome(
        scan=_scan_result(),
        active_targets=["software"],
        is_full_clean=is_full_clean,
        remaining_targeted_tags=[],
        remaining_sensitive=[],
        residual_metadata_tags=[],
        comparison=None,
    )

    assert outcome == VerificationOutcome.VERIFIED_CLEAN


def test_outcome_fails_closed_when_inspection_incomplete() -> None:
    """An incomplete inspection must never be certified clean."""
    outcome, reason = MetadataVerifier()._decide_outcome(
        scan=_scan_result(inspection_complete=False),
        active_targets=["software"],
        is_full_clean=True,
        remaining_targeted_tags=[],
        remaining_sensitive=[],
        residual_metadata_tags=[],
        comparison=None,
    )

    assert outcome == VerificationOutcome.VERIFICATION_FAILED
    assert "inspection" in reason.lower() or "certif" in reason.lower()


def _backend_failure_scanner(monkeypatch: pytest.MonkeyPatch) -> MetadataScanner:
    """Creates a scanner whose ExifTool read fails while writes stay possible."""
    scanner = MetadataScanner(exiftool_path="exiftool")

    def _fail(*args: object, **kwargs: object) -> ExifToolReadResult:
        return ExifToolReadResult(ok=False, errors=["simulated metadata read failure"])

    monkeypatch.setattr(scanner.backend, "read_tags", _fail)
    return scanner


def test_scan_marks_inspection_incomplete_on_backend_read_failure(
    clean_jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed backend read must be recorded as an incomplete inspection."""
    scanner = _backend_failure_scanner(monkeypatch)

    scan = scanner.scan(clean_jpeg)

    assert scan.scanner_backend == "exiftool"
    assert scan.inspection_complete is False
    assert scan.image_metadata == {}
    assert scan.limitations


def test_verification_fails_closed_on_backend_read_failure(
    clean_jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verification must not report clean when the backend read failed."""
    scanner = _backend_failure_scanner(monkeypatch)

    rep = MetadataVerifier(scanner=scanner).verify(
        clean_jpeg, targeted_categories=["all"]
    )

    assert rep.outcome == VerificationOutcome.VERIFICATION_FAILED
    assert rep.status != VerificationStatus.PASS
    assert rep.outcome_reason
    assert any("did not complete" in lim.lower() for lim in rep.limitations)


@pytest.mark.skipif(
    not config.EXIFTOOL_AVAILABLE,
    reason="ExifTool is required to classify the targeted Software tag.",
)
def test_selective_verification_not_clean_with_low_risk_remnant(
    temp_dir: Path,
) -> None:
    """A LOW-risk targeted tag left in place must not yield VERIFIED CLEAN."""
    image_path = temp_dir / "software_only.jpg"
    image = Image.new("RGB", (32, 32), "white")
    exif = image.getexif()
    exif[0x0131] = "TopSecretEditor 9.9"  # Software
    image.save(image_path, "JPEG", exif=exif)

    rep = MetadataVerifier().verify(image_path, targeted_categories=["software"])

    assert [tag.name for tag in rep.remaining_targeted_tags] == ["Software"]
    assert rep.outcome == VerificationOutcome.SENSITIVE_DATA_REMAINS
