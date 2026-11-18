"""Filesystem safety regression tests (F-06 symlinks, F-07 validate-before-replace).

The policy under test:

* A symbolic link in the final path component is refused for scan, clean and
  verify inputs, and for clean destinations.  Intermediate directory symlinks
  are resolved once (system directories are often symlinked).
* The destination is only replaced after the staged working copy has passed
  structural validation, and the destination/temporary identities are
  re-checked immediately before the atomic replace.
* Every failure path leaves the input, a pre-existing destination, and any
  unrelated file untouched.  Cleanup only removes the temporary file that this
  process created.

Tests use only temporary directories and synthetic images.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from PIL import Image

from modules.batch_processor import BatchProcessor
from modules.exiftool_backend import ExifToolResult
from modules.image_validator import ImageValidationError, file_identity
from modules.metadata_remover import MetadataRemover, RemovalError
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationOutcome
from modules.report_generator import export_json_report


def _symlink(target: Path | str, link: Path) -> None:
    """Creates a symlink or skips the test on platforms without support."""
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("Symbolic links are not supported on this platform")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _temp_files(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.startswith(".metaclean-")]


def _truncated_write(path, args, timeout=None) -> ExifToolResult:
    """Simulates a backend that reports success but leaves invalid output."""
    Path(path).write_bytes(b"\xff\xd8\xff\xe0truncated")
    return ExifToolResult(ok=True, returncode=0, stdout="1 image files updated")


def _failing_write(path, args, timeout=None) -> ExifToolResult:
    return ExifToolResult(ok=False, returncode=2, stderr="simulated ExifTool failure")


# ---------------------------------------------------------------------------
# F-06: symlink inputs are refused by every entry point
# ---------------------------------------------------------------------------
def test_symlink_input_refused_by_clean(clean_jpeg: Path, temp_dir: Path) -> None:
    link = temp_dir / "input_link.jpg"
    _symlink(clean_jpeg, link)
    output = temp_dir / "out.jpg"

    result = MetadataRemover().clean(
        input_path=link,
        output_path=output,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("symbolic link" in error.lower() for error in result.errors)
    assert not output.exists()
    assert clean_jpeg.exists()


def test_symlink_input_refused_by_scan(clean_jpeg: Path, temp_dir: Path) -> None:
    link = temp_dir / "scan_link.jpg"
    _symlink(clean_jpeg, link)

    scan = MetadataScanner().scan(link)

    assert scan.validation.is_valid is False
    assert any("symbolic link" in error.lower() for error in scan.validation.errors)


def test_symlink_input_refused_by_verify(clean_jpeg: Path, temp_dir: Path) -> None:
    link = temp_dir / "verify_link.jpg"
    _symlink(clean_jpeg, link)
    before = _sha256(clean_jpeg)

    report = MetadataVerifier().verify(link, profile="maximum")

    assert report.outcome == VerificationOutcome.VERIFICATION_FAILED
    assert "symbolic" in report.summary_message.lower()
    assert _sha256(clean_jpeg) == before


# ---------------------------------------------------------------------------
# F-06: symlink destinations are refused and their targets preserved
# ---------------------------------------------------------------------------
def test_symlink_output_refused_and_target_preserved(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    victim = temp_dir / "victim.txt"
    victim.write_bytes(b"original victim content")
    link = temp_dir / "output_link.jpg"
    _symlink(victim, link)

    result = MetadataRemover().clean(
        input_path=clean_jpeg,
        output_path=link,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("symbolic link" in error.lower() for error in result.errors)
    assert victim.read_bytes() == b"original victim content"
    assert link.is_symlink()


def test_dangling_symlink_output_refused(clean_jpeg: Path, temp_dir: Path) -> None:
    missing = temp_dir / "not_created.jpg"
    link = temp_dir / "dangling.jpg"
    _symlink(missing, link)

    result = MetadataRemover().clean(
        input_path=clean_jpeg,
        output_path=link,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("symbolic link" in error.lower() for error in result.errors)
    assert not missing.exists()
    assert link.is_symlink()


def test_batch_refuses_symlink_input_directory(temp_dir: Path) -> None:
    real_in = temp_dir / "input"
    real_in.mkdir()
    Image.new("RGB", (24, 24), "red").save(real_in / "a.jpg", "JPEG")
    link_in = temp_dir / "input_link"
    _symlink(real_in, link_in)

    with pytest.raises(ImageValidationError, match="symbolic link"):
        BatchProcessor().process_batch(link_in, scan_only=True)


def test_batch_refuses_symlink_output_directory(temp_dir: Path) -> None:
    in_dir = temp_dir / "input"
    real_out = temp_dir / "real_out"
    in_dir.mkdir()
    real_out.mkdir()
    Image.new("RGB", (24, 24), "red").save(in_dir / "a.jpg", "JPEG")
    link_out = temp_dir / "out_link"
    _symlink(real_out, link_out)

    with pytest.raises(ImageValidationError, match="symbolic link"):
        BatchProcessor().process_batch(in_dir, link_out)


def test_batch_follow_symlinks_is_explicit_opt_in(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    in_dir = temp_dir / "input"
    out_dir = temp_dir / "out"
    in_dir.mkdir()
    real = in_dir / "real.jpg"
    real.write_bytes(clean_jpeg.read_bytes())
    link = in_dir / "linked.jpg"
    _symlink(real, link)
    before = _sha256(real)

    summary = BatchProcessor().process_batch(in_dir, out_dir, overwrite=True)

    assert summary.skipped_symlinks >= 1
    assert [r.input_path.name for r in summary.file_results] == ["real.jpg"]

    followed = BatchProcessor().process_batch(
        in_dir, out_dir, overwrite=True, follow_symlinks=True
    )
    assert followed.failure_count == 0
    assert sorted(r.input_path.name for r in followed.file_results) == [
        "linked.jpg",
        "real.jpg",
    ]
    assert (out_dir / "linked.jpg").exists()
    assert _sha256(real) == before, "the symlink target must never be written"


# ---------------------------------------------------------------------------
# F-07: invalid or failed working copies never replace the destination
# ---------------------------------------------------------------------------
def test_truncated_temp_does_not_replace_existing_destination(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"pre-existing destination")
    remover = MetadataRemover()
    monkeypatch.setattr(remover.backend, "write", _truncated_write)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("readability validation" in error for error in result.errors)
    assert destination.read_bytes() == b"pre-existing destination"
    assert _temp_files(temp_dir) == []


def test_backend_failure_does_not_replace_existing_destination(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"pre-existing destination")
    input_before = _sha256(clean_jpeg)
    remover = MetadataRemover()
    monkeypatch.setattr(remover.backend, "write", _failing_write)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("simulated ExifTool failure" in error for error in result.errors)
    assert destination.read_bytes() == b"pre-existing destination"
    assert _sha256(clean_jpeg) == input_before
    assert _temp_files(temp_dir) == []


def test_backend_failure_creates_no_new_output(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "never_created.jpg"
    remover = MetadataRemover()
    monkeypatch.setattr(remover.backend, "write", _failing_write)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert not destination.exists()
    assert _temp_files(temp_dir) == []


def test_dimension_mismatch_does_not_replace_existing_destination(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"pre-existing destination")

    def different_dimensions(path, args, timeout=None) -> ExifToolResult:
        Image.new("RGB", (16, 16), (0, 0, 0)).save(path, "JPEG", quality=90)
        return ExifToolResult(ok=True, returncode=0, stdout="1 image files updated")

    remover = MetadataRemover()
    monkeypatch.setattr(remover.backend, "write", different_dimensions)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("do not match input dimensions" in error for error in result.errors)
    assert destination.read_bytes() == b"pre-existing destination"


def test_verification_failure_does_not_modify_source(
    jpeg_with_gps_and_date: Path, temp_dir: Path
) -> None:
    """Verification is read-only: a failed verification cannot alter the input."""
    before = _sha256(jpeg_with_gps_and_date)
    output = temp_dir / "out.jpg"

    result = MetadataRemover().clean(
        input_path=jpeg_with_gps_and_date,
        output_path=output,
        categories=["all"],
        overwrite_output=True,
    )
    assert result.success is True

    # Verify the uncleaned original as if it were the cleaned output.  The
    # metadata is still present, so verification must not report a clean file.
    report = MetadataVerifier().verify(
        jpeg_with_gps_and_date, profile="maximum"
    )
    assert report.outcome != VerificationOutcome.VERIFIED_CLEAN
    assert _sha256(jpeg_with_gps_and_date) == before


def test_pillow_fallback_failure_preserves_existing_destination(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"pre-existing destination")
    remover = MetadataRemover()
    remover.exiftool_available = False
    remover.exiftool_path = None

    def failing_fallback(src, dest_path, categories, val_res):
        Path(dest_path).write_bytes(b"\xff\xd8\xff\xe0broken")
        return False, ["simulated fallback failure"], []

    monkeypatch.setattr(remover, "_clean_with_pillow_fallback", failing_fallback)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("simulated fallback failure" in error for error in result.errors)
    assert destination.read_bytes() == b"pre-existing destination"
    assert _temp_files(temp_dir) == []


def test_pillow_fallback_output_is_validated_before_install(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"pre-existing destination")
    remover = MetadataRemover()
    remover.exiftool_available = False
    remover.exiftool_path = None

    def truncated_fallback(src, dest_path, categories, val_res):
        Path(dest_path).write_bytes(b"\xff\xd8\xff\xe0broken")
        return True, [], []

    monkeypatch.setattr(remover, "_clean_with_pillow_fallback", truncated_fallback)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("readability validation" in error for error in result.errors)
    assert destination.read_bytes() == b"pre-existing destination"


def test_report_output_symlink_is_refused(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    victim = temp_dir / "victim.txt"
    victim.write_bytes(b"original victim content")
    link = temp_dir / "report.json"
    _symlink(victim, link)
    scan = MetadataScanner().scan(clean_jpeg)

    with pytest.raises(ImageValidationError, match="symbolic link"):
        export_json_report(link, scan)

    assert victim.read_bytes() == b"original victim content"
    assert link.is_symlink()


# ---------------------------------------------------------------------------
# F-06/F-07: same-file aliases and race attempts
# ---------------------------------------------------------------------------
def test_relative_alias_of_input_is_refused(clean_jpeg: Path, temp_dir: Path) -> None:
    aliased = temp_dir / "." / clean_jpeg.name

    result = MetadataRemover().clean(
        input_path=clean_jpeg,
        output_path=aliased,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("identical to the original input" in error for error in result.errors)


def test_parent_traversal_alias_of_input_is_refused(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    nested = temp_dir / "nested"
    nested.mkdir()
    aliased = nested / ".." / clean_jpeg.name

    result = MetadataRemover().clean(
        input_path=clean_jpeg,
        output_path=aliased,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("identical to the original input" in error for error in result.errors)


def test_hardlink_alias_of_input_is_refused(clean_jpeg: Path, temp_dir: Path) -> None:
    alias = temp_dir / "hardlink.jpg"
    try:
        os.link(clean_jpeg, alias)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("Hard links are not supported on this platform")

    result = MetadataRemover().clean(
        input_path=clean_jpeg,
        output_path=alias,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("identical to the original input" in error for error in result.errors)
    assert alias.exists()


def test_destination_swapped_for_symlink_during_cleaning_is_refused(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink planted after the entry check must not redirect replacement."""
    victim = temp_dir / "victim.txt"
    victim.write_bytes(b"victim content")
    destination = temp_dir / "out.jpg"
    remover = MetadataRemover()
    original_validate = remover._validate_working_copy

    def validate_then_swap(temp_path, val_res, errors) -> bool:
        valid = original_validate(temp_path, val_res, errors)
        if not os.path.lexists(destination):
            _symlink(victim, destination)
        return valid

    monkeypatch.setattr(remover, "_validate_working_copy", validate_then_swap)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("symbolic link" in error.lower() for error in result.errors)
    assert victim.read_bytes() == b"victim content"
    assert destination.is_symlink()
    assert _temp_files(temp_dir) == []


def test_destination_replaced_with_different_file_is_refused(
    clean_jpeg: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replacing the destination path with another inode must abort the install."""
    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"original destination")
    remover = MetadataRemover()
    original_validate = remover._validate_working_copy

    def validate_then_replace(temp_path, val_res, errors) -> bool:
        valid = original_validate(temp_path, val_res, errors)
        intruder = temp_dir / "intruder.bin"
        intruder.write_bytes(b"intruder destination")
        os.replace(intruder, destination)
        return valid

    monkeypatch.setattr(remover, "_validate_working_copy", validate_then_replace)

    result = remover.clean(
        input_path=clean_jpeg,
        output_path=destination,
        categories=["all"],
        overwrite_output=True,
    )

    assert result.success is False
    assert any("changed during cleaning" in error for error in result.errors)
    assert destination.read_bytes() == b"intruder destination"


def test_install_guard_rejects_replaced_working_copy(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    remover = MetadataRemover()
    staged = temp_dir / ".metaclean-staged.jpg"
    staged.write_bytes(clean_jpeg.read_bytes())
    staged_identity = file_identity(staged)
    assert staged_identity is not None

    destination = temp_dir / "out.jpg"
    destination.write_bytes(b"existing destination")
    destination_identity = file_identity(destination)

    # Swap the staged file for a different entry (rename keeps the other inode).
    replacement = temp_dir / "replacement.bin"
    replacement.write_bytes(b"swapped content")
    os.replace(replacement, staged)
    swapped_identity = file_identity(staged)

    with pytest.raises(RemovalError, match="temporary output was replaced"):
        remover._install_validated_output(
            temp_path=staged,
            temp_identity=staged_identity,
            out_p=destination,
            dest_identity=destination_identity,
            parent_identity=file_identity(temp_dir),
            overwrite_output=True,
        )

    assert destination.read_bytes() == b"existing destination"
    assert file_identity(staged) == swapped_identity


def test_cleanup_does_not_delete_a_file_moved_into_the_temp_name(
    temp_dir: Path,
) -> None:
    staged = temp_dir / ".metaclean-orphan.jpg"
    staged.write_bytes(b"first file")
    original_identity = file_identity(staged)

    unrelated = temp_dir / "unrelated.bin"
    unrelated.write_bytes(b"unrelated file")
    os.replace(unrelated, staged)

    MetadataRemover._discard_temp(staged, original_identity)

    assert staged.exists()
    assert staged.read_bytes() == b"unrelated file"


def test_output_and_report_file_permissions(
    clean_jpeg: Path, temp_dir: Path
) -> None:
    """Cleaned images and exported reports must have restricted file permissions (0o600 on POSIX)."""
    if os.name != "posix":
        pytest.skip("POSIX permissions test")

    out_image = temp_dir / "clean_secure.jpg"
    removal = MetadataRemover().clean(clean_jpeg, out_image, overwrite_output=True)
    assert removal.success
    mode_img = out_image.stat().st_mode & 0o777
    assert mode_img == 0o600

    scan = MetadataScanner().scan(clean_jpeg)
    report_file = temp_dir / "report.json"
    export_json_report(report_file, scan)
    assert report_file.exists()
    mode_rep = report_file.stat().st_mode & 0o777
    assert mode_rep == 0o600
