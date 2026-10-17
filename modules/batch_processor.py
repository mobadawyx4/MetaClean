"""Batch image processing engine for MetaClean.

Iterates over directories of images, sanitizes metadata individually with error
isolation, prevents destination collisions, verifies every output, and compiles
batch audit summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import config
from modules.image_validator import safe_resolve_path, validate_image
from modules.metadata_remover import MetadataRemover, RemovalResult
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationReport, VerificationStatus
from modules.report_generator import export_batch_csv, export_json_report


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
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


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

    def discover_images(self, input_dir: Path, recursive: bool = False) -> List[Path]:
        """Finds all supported image files in the target directory."""
        candidates: List[Path] = []
        pattern = "**/*" if recursive else "*"
        for p in input_dir.glob(pattern):
            if p.is_file() and p.suffix.lower() in config.SUPPORTED_EXTENSIONS:
                candidates.append(p)
        return sorted(candidates)

    def process_batch(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        categories: Optional[List[str] | str] = None,
        overwrite: bool = False,
        recursive: bool = False,
        progress_callback: Optional[Callable[[BatchFileResult, int, int], None]] = None,
    ) -> BatchSummary:
        """Processes all supported images in input_dir and saves cleaned files to output_dir.

        Isolates failures so a corrupted file does not interrupt the entire batch.
        """
        in_dir = safe_resolve_path(input_dir, must_exist=True, allow_dir=True)
        if not in_dir.is_dir():
            raise NotADirectoryError(f"Input path is not a directory: {in_dir}")

        out_dir = Path(output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        image_files = self.discover_images(in_dir, recursive=recursive)
        summary = BatchSummary(total_found=len(image_files))

        for idx, img_path in enumerate(image_files, 1):
            res = BatchFileResult(input_path=img_path)

            try:
                # 1. Validation & Pre-scan
                scan = self.scanner.scan(img_path)
                res.format_name = scan.validation.format_name or "UNKNOWN"
                res.original_size = scan.validation.file_size

                if not scan.validation.is_valid:
                    res.validation_status = "INVALID"
                    res.error_message = "; ".join(scan.validation.errors)
                    res.removal_status = "SKIPPED"
                    res.verification_status = "FAIL"
                    summary.failure_count += 1
                    summary.file_results.append(res)
                    if progress_callback:
                        progress_callback(res, idx, len(image_files))
                    continue

                res.validation_status = "VALID"

                # Privacy metrics
                if scan.privacy_report:
                    res.privacy_risk = scan.privacy_report.overall_risk.value
                    res.risk_score = scan.privacy_report.risk_score
                    res.gps_detected = any(
                        i.category == "gps" for i in scan.privacy_report.items
                    )
                    res.author_detected = any(
                        i.category == "author" for i in scan.privacy_report.items
                    )
                    res.date_detected = any(
                        i.category == "date" for i in scan.privacy_report.items
                    )

                # Determine destination file path
                if overwrite:
                    dest_file = out_dir / img_path.name
                else:
                    dest_file = generate_collision_free_path(out_dir, img_path.name)
                res.output_path = dest_file

                # 2. Metadata Removal
                removal = self.remover.clean(
                    input_path=img_path,
                    output_path=dest_file,
                    categories=categories,
                    overwrite_output=overwrite,
                )

                res.cleaned_size = removal.cleaned_size
                res.warnings.extend(removal.warnings)

                if not removal.success:
                    res.removal_status = "FAILED"
                    res.error_message = "; ".join(removal.errors)
                    res.verification_status = "FAIL"
                    summary.failure_count += 1
                    summary.file_results.append(res)
                    if progress_callback:
                        progress_callback(res, idx, len(image_files))
                    continue

                res.removal_status = "COMPLETED"

                # 3. Independent Verification
                verification = self.verifier.verify(
                    image_path=dest_file,
                    targeted_categories=categories or ["all"],
                    original_image_path=img_path,
                )

                res.verification_status = verification.status.value
                if verification.status == VerificationStatus.PASS:
                    res.success = True
                    summary.pass_count += 1
                    summary.success_count += 1
                elif verification.status == VerificationStatus.WARNING:
                    res.success = True
                    summary.warning_count += 1
                    summary.success_count += 1
                elif verification.status == VerificationStatus.INCOMPLETE:
                    summary.incomplete_count += 1
                else:
                    summary.failure_count += 1

                saved = max(0, res.original_size - res.cleaned_size)
                summary.total_bytes_saved += saved

            except Exception as e:
                res.removal_status = "ERROR"
                res.verification_status = "FAIL"
                res.error_message = f"Unexpected processing error: {e}"
                summary.failure_count += 1

            summary.processed_count += 1
            summary.file_results.append(res)

            if progress_callback:
                progress_callback(res, idx, len(image_files))

        return summary
