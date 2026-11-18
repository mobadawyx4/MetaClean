"""Batch image processing engine for MetaClean.

Iterates over directories of images, sanitizes or scans metadata individually
with error isolation, prevents destination collisions, verifies every output,
and compiles batch audit summaries.

Safety behaviour:
* Symbolic links are skipped unless ``follow_symlinks`` is explicitly enabled,
  so a link cannot pull files from outside the selected directory into a batch.
* The output directory is excluded from recursive discovery, preventing a batch
  from cleaning its own outputs.
* Duplicate files can be skipped by SHA-256 content hash.
* One failed file never terminates the batch.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import config
from modules.image_validator import safe_resolve_path
from modules.metadata_remover import MetadataRemover, RemovalResult
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import (
    MetadataVerifier,
    VerificationOutcome,
    VerificationReport,
    VerificationStatus,
)
from modules.report_generator import export_batch_csv, export_json_report
from modules.sanitizer_profiles import get_profile, resolve_profile


@dataclass
class BatchFileResult:
    """Outcome of processing an individual file within a batch."""

    input_path: Path
    output_path: Optional[Path] = None
    success: bool = False
    validation_status: str = "PENDING"
    format_name: str = "UNKNOWN"
    original_size: int = 0
    cleaned_size: int = 0
    privacy_risk: str = "UNKNOWN"
    risk_score: int = 0
    gps_detected: bool = False
    author_detected: bool = False
    date_detected: bool = False
    removal_status: str = "PENDING"
    verification_status: str = "PENDING"
    verification_outcome: str = "PENDING"
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    tags_count: int = 0
    sensitive_count: int = 0
    scan_mode: str = "standard"
    duplicate_of: Optional[Path] = None
    is_symlink: bool = False
    skipped: bool = False


@dataclass
class BatchSummary:
    """Overall statistics for a completed batch operation."""

    total_found: int = 0
    processed_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    pass_count: int = 0
    warning_count: int = 0
    incomplete_count: int = 0
    total_bytes_saved: int = 0
    file_results: List[BatchFileResult] = field(default_factory=list)
    skipped_duplicates: int = 0
    skipped_symlinks: int = 0
    verified_clean_count: int = 0
    partially_cleaned_count: int = 0
    sensitive_remaining_count: int = 0
    verification_failed_count: int = 0
    total_tags: int = 0
    total_sensitive_tags: int = 0
    scan_only: bool = False


def generate_collision_free_path(dest_dir: Path, original_filename: str) -> Path:
    """Computes a collision-free target filepath in dest_dir."""
    base_stem = Path(original_filename).stem
    suffix = Path(original_filename).suffix
    candidate = dest_dir / f"{base_stem}{suffix}"

    counter = 1
    while candidate.exists():
        candidate = dest_dir / f"{base_stem}_{counter}{suffix}"
        counter += 1

    return candidate


def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class BatchProcessor:
    """Manages batch scanning, metadata stripping, and verification."""

    def __init__(
        self,
        scanner: Optional[MetadataScanner] = None,
        remover: Optional[MetadataRemover] = None,
        verifier: Optional[MetadataVerifier] = None,
    ) -> None:
        self.scanner = scanner or MetadataScanner()
        self.remover = remover or MetadataRemover()
        self.verifier = verifier or MetadataVerifier(scanner=self.scanner)

    # ------------------------------------------------------------------
    def discover_images(
        self,
        input_dir: Path,
        recursive: bool = False,
        exclude_dirs: Optional[Set[Path]] = None,
        follow_symlinks: bool = False,
        warnings: Optional[List[str]] = None,
    ) -> List[Path]:
        """Finds supported image files, skipping symlinks and excluded directories."""
        exclude_dirs = {p.resolve() for p in (exclude_dirs or set())}
        candidates: List[Path] = []
        warnings = warnings if warnings is not None else []

        if recursive:
            for root, dirnames, filenames in os.walk(input_dir, followlinks=follow_symlinks):
                root_path = Path(root)
                if root_path.resolve() in exclude_dirs:
                    dirnames[:] = []
                    continue
                # Never descend into the output directory.
                dirnames[:] = [
                    d for d in dirnames
                    if (root_path / d).resolve() not in exclude_dirs
                ]
                for name in filenames:
                    candidate = root_path / name
                    if candidate.suffix.lower() not in config.SUPPORTED_EXTENSIONS:
                        continue
                    if candidate.is_symlink() and not follow_symlinks:
                        warnings.append(f"Skipped symbolic link: {candidate}")
                        continue
                    if candidate.is_file():
                        candidates.append(candidate)
        else:
            try:
                entries = list(input_dir.iterdir())
            except OSError as exc:
                warnings.append(f"Could not list input directory: {exc}")
                entries = []
            for candidate in entries:
                if candidate.suffix.lower() not in config.SUPPORTED_EXTENSIONS:
                    continue
                if candidate.is_symlink() and not follow_symlinks:
                    warnings.append(f"Skipped symbolic link: {candidate}")
                    continue
                if candidate.is_file():
                    candidates.append(candidate)

        return sorted(candidates)

    # ------------------------------------------------------------------
    def process_batch(
        self,
        input_dir: str | Path,
        output_dir: Optional[str | Path] = None,
        categories: Optional[List[str] | str] = None,
        overwrite: bool = False,
        recursive: bool = False,
        progress_callback: Optional[Callable[[BatchFileResult, int, int], None]] = None,
        scan_only: bool = False,
        skip_duplicates: bool = False,
        follow_symlinks: bool = False,
        scan_mode: str = "standard",
        profile: Optional[str] = None,
        max_files: Optional[int] = None,
    ) -> BatchSummary:
        """Processes (or scans) supported images in ``input_dir``.

        Failures are isolated per file so a corrupted image does not interrupt
        the batch.
        """
        in_dir = safe_resolve_path(
            input_dir, must_exist=True, allow_dir=True, role="input directory"
        )
        if not in_dir.is_dir():
            raise NotADirectoryError(f"Input path is not a directory: {in_dir}")

        if not scan_only and output_dir is None:
            raise ValueError("An output directory is required unless scan_only=True.")

        out_dir: Optional[Path] = None
        if not scan_only and output_dir is not None:
            out_dir = safe_resolve_path(
                output_dir, must_exist=False, allow_dir=True, role="output directory"
            )
            if out_dir == in_dir.resolve():
                raise ValueError(
                    "The output directory must differ from the input directory; "
                    "MetaClean never writes cleaned files into the source root."
                )
            out_dir.mkdir(parents=True, exist_ok=True)

        if scan_mode not in config.SCAN_MODES:
            scan_mode = "standard"

        category_list: Optional[List[str]] = None
        if profile and not scan_only:
            try:
                _, category_list = resolve_profile(profile, categories)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc

        discovery_warnings: List[str] = []
        image_files = self.discover_images(
            in_dir,
            recursive=recursive,
            exclude_dirs={out_dir} if out_dir else set(),
            follow_symlinks=follow_symlinks,
            warnings=discovery_warnings,
        )
        summary = BatchSummary(total_found=len(image_files), scan_only=scan_only)
        summary.skipped_symlinks = len(discovery_warnings)

        limit = max_files if max_files is not None else config.MAX_BATCH_FILES
        # F-19: an explicit --max-files request is clamped to a hard ceiling so a
        # typo cannot turn into an effective "unlimited" batch, and a non-positive
        # value is rejected instead of silently slicing from the tail of the list.
        if max_files is not None:
            if max_files <= 0:
                raise ValueError(
                    f"--max-files must be a positive integer, got {max_files}."
                )
            if max_files > config.MAX_BATCH_FILES_CEILING:
                raise ValueError(
                    f"--max-files {max_files} exceeds the hard ceiling of "
                    f"{config.MAX_BATCH_FILES_CEILING}."
                )
        if len(image_files) > limit:
            discovery_warnings.append(
                f"Batch limited to {limit} files (found {len(image_files)}). "
                "Use --max-files to raise the limit."
            )
            image_files = image_files[:limit]

        seen_hashes: Dict[str, Path] = {}

        for idx, img_path in enumerate(image_files, 1):
            res = BatchFileResult(input_path=img_path, scan_mode=scan_mode)
            res.is_symlink = img_path.is_symlink()

            # Following a symlink is only possible via the explicit
            # ``follow_symlinks`` opt-in.  The scanner and remover still refuse
            # symlink inputs, so process the resolved real target while keeping
            # the link path for reporting.
            read_path = img_path
            if follow_symlinks and img_path.is_symlink():
                try:
                    read_path = img_path.resolve(strict=True)
                except OSError:
                    read_path = img_path  # the scanner reports the broken link

            try:
                # Duplicate detection (opt-in because it reads the whole file).
                if skip_duplicates:
                    try:
                        file_hash = _sha256(read_path)
                        if file_hash in seen_hashes:
                            res.skipped = True
                            res.duplicate_of = seen_hashes[file_hash]
                            res.verification_status = "SKIPPED"
                            res.verification_outcome = "SKIPPED (DUPLICATE)"
                            summary.skipped_duplicates += 1
                            summary.file_results.append(res)
                            if progress_callback:
                                progress_callback(res, idx, len(image_files))
                            continue
                        seen_hashes[file_hash] = img_path
                    except OSError as exc:
                        res.warnings.append(f"Duplicate check failed: {exc}")

                # 1. Validation and scan.
                scan = self.scanner.scan(read_path, mode=scan_mode)
                res.format_name = scan.validation.format_name or "UNKNOWN"
                res.original_size = scan.validation.file_size
                res.tags_count = scan.total_embedded_tags

                if not scan.validation.is_valid:
                    res.validation_status = "INVALID"
                    res.error_message = "; ".join(scan.validation.errors)
                    res.removal_status = "SKIPPED"
                    res.verification_status = "FAIL"
                    res.verification_outcome = "VERIFICATION FAILED"
                    summary.failure_count += 1
                    summary.verification_failed_count += 1
                    summary.processed_count += 1
                    summary.file_results.append(res)
                    if progress_callback:
                        progress_callback(res, idx, len(image_files))
                    continue

                res.validation_status = "VALID"

                if scan.privacy_report:
                    res.privacy_risk = scan.privacy_report.overall_risk.value
                    res.risk_score = scan.privacy_report.risk_score
                    res.sensitive_count = scan.privacy_report.sensitive_count
                    res.gps_detected = scan.privacy_report.gps_detected
                    res.author_detected = scan.privacy_report.personal_information_detected
                    res.date_detected = scan.privacy_report.timestamps_detected
                summary.total_tags += res.tags_count
                summary.total_sensitive_tags += res.sensitive_count

                # 2. Scan-only batches stop here.
                if scan_only:
                    res.success = True
                    res.removal_status = "NOT_REQUESTED"
                    res.verification_status = "N/A"
                    res.verification_outcome = "SCAN ONLY"
                    summary.success_count += 1
                    summary.processed_count += 1
                    summary.file_results.append(res)
                    if progress_callback:
                        progress_callback(res, idx, len(image_files))
                    continue

                assert out_dir is not None
                # 3. Destination selection.
                if overwrite:
                    dest_file = out_dir / img_path.name
                else:
                    dest_file = generate_collision_free_path(out_dir, img_path.name)
                res.output_path = dest_file

                # 4. Metadata removal.
                removal = self.remover.clean(
                    input_path=read_path,
                    output_path=dest_file,
                    categories=category_list if category_list is not None else categories,
                    overwrite_output=overwrite,
                    profile=profile,
                )
                res.cleaned_size = removal.cleaned_size
                res.warnings.extend(removal.warnings)

                if not removal.success:
                    res.removal_status = "FAILED"
                    res.error_message = "; ".join(removal.errors)
                    res.verification_status = "FAIL"
                    res.verification_outcome = "VERIFICATION FAILED"
                    summary.failure_count += 1
                    summary.verification_failed_count += 1
                    summary.processed_count += 1
                    summary.file_results.append(res)
                    if progress_callback:
                        progress_callback(res, idx, len(image_files))
                    continue

                res.removal_status = "COMPLETED"

                # 5. Independent verification.
                verification = self.verifier.verify(
                    image_path=dest_file,
                    targeted_categories=(
                        category_list if category_list is not None else categories or ["all"]
                    ),
                    original_image_path=read_path,
                    profile=profile,
                )
                res.verification_status = verification.status.value
                res.verification_outcome = verification.outcome.value
                res.warnings.extend(verification.limitations)

                if verification.status == VerificationStatus.PASS:
                    summary.pass_count += 1
                    summary.success_count += 1
                    res.success = True
                elif verification.status == VerificationStatus.WARNING:
                    summary.warning_count += 1
                    summary.success_count += 1
                    res.success = True
                elif verification.status == VerificationStatus.INCOMPLETE:
                    summary.incomplete_count += 1
                    summary.failure_count += 1
                else:
                    summary.failure_count += 1

                if verification.outcome == VerificationOutcome.VERIFIED_CLEAN:
                    summary.verified_clean_count += 1
                elif verification.outcome == VerificationOutcome.PARTIALLY_CLEANED:
                    summary.partially_cleaned_count += 1
                elif verification.outcome == VerificationOutcome.SENSITIVE_DATA_REMAINS:
                    summary.sensitive_remaining_count += 1
                else:
                    summary.verification_failed_count += 1

                summary.total_bytes_saved += max(0, res.original_size - res.cleaned_size)

            except Exception as exc:
                res.removal_status = "ERROR"
                res.verification_status = "FAIL"
                res.verification_outcome = "VERIFICATION FAILED"
                res.error_message = f"Unexpected processing error: {exc}"
                summary.failure_count += 1
                summary.verification_failed_count += 1

            summary.processed_count += 1
            summary.file_results.append(res)

            if progress_callback:
                progress_callback(res, idx, len(image_files))

        if discovery_warnings:
            summary.file_results[0].warnings.extend(discovery_warnings) if summary.file_results else None

        return summary
