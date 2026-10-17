"""Comprehensive report generation module for MetaClean.

Exports detailed JSON audit reports for individual files and CSV summaries
for batch operations, maintaining privacy by sanitizing sensitive raw values.
"""

from __future__ import annotations

import csv
import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from modules.metadata_remover import RemovalResult
from modules.metadata_scanner import ScanResult
from modules.metadata_verifier import VerificationReport


def build_file_report_dict(
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
) -> Dict[str, Any]:
    """Assembles a structured dictionary representing the full security audit."""
    # Build detected categories summary
    detected_cats: Dict[str, Any] = {}
    for cat_name, cat_summary in scan.categories.items():
        detected_cats[cat_name] = {
            "detected": cat_summary.detected,
            "tag_count": len(cat_summary.tags),
            "tag_names": [t.name for t in cat_summary.tags],
        }

    # Privacy risk breakdown
    privacy_info: Dict[str, Any] = {}
    if scan.privacy_report:
        pr = scan.privacy_report
        privacy_info = {
            "overall_risk": pr.overall_risk.value,
            "risk_score": pr.risk_score,
            "summary_narrative": pr.summary_narrative,
            "high_risk_count": pr.high_risk_count,
            "medium_risk_count": pr.medium_risk_count,
            "low_risk_count": pr.low_risk_count,
            "informational_count": pr.info_count,
            "recommendations": pr.recommendations,
            "assessed_tags": [
                {
                    "tag": item.tag_name,
                    "category": item.category,
                    "risk_level": item.risk_level.value,
                    "preview": item.value_preview,
                    "explanation": item.explanation,
                }
                for item in pr.items
            ],
        }

    # Removed fields determination
    removed_tags: List[str] = []
    if removal:
        removed_tags = list(removal.categories_removed)
    elif verification and verification.targeted_categories:
        # If verification passed for a category, that category was successfully removed
        for check in verification.category_checks:
            if check.status.value == "PASS":
                removed_tags.append(check.category)

    # Remaining fields
    remaining_tags = [t.name for t in scan.image_metadata.values()]

    # Verification block
    verification_info: Dict[str, Any] = {}
    if verification:
        verification_info = {
            "status": verification.status.value,
            "summary": verification.summary_message,
            "targeted_categories": verification.targeted_categories,
            "remaining_targeted_tags_count": len(verification.remaining_targeted_tags),
            "category_checks": [
                {
                    "category": c.category,
                    "status": c.status.value,
                    "message": c.message,
                }
                for c in verification.category_checks
            ],
        }

    # Collect all warnings and limitations
    all_warnings: List[str] = list(scan.validation.warnings)
    all_limitations: List[str] = list(scan.limitations)
    if removal:
        all_warnings.extend(removal.warnings)
    if verification:
        all_limitations.extend(verification.limitations)

    return {
        "metaclean_version": config.APP_VERSION,
        "report_generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_file": {
            "path": str(scan.file_path),
            "filename": scan.file_path.name,
            "is_valid_image": scan.validation.is_valid,
            "format": scan.validation.format_name,
            "file_size_bytes": scan.validation.file_size,
            "dimensions": scan.validation.dimensions,
            "has_transparency": scan.validation.has_transparency,
            "is_animated": scan.validation.is_animated,
        },
        "filesystem_attributes": scan.filesystem_metadata,
        "metadata_scan": {
            "backend": scan.scanner_backend,
            "backend_version": scan.backend_version,
            "inspected_fields_count": scan.total_embedded_tags,
            "detected_categories": detected_cats,
        },
        "privacy_risk_assessment": privacy_info,
        "removal_summary": {
            "executed": removal is not None,
            "method": removal.method_used if removal else None,
            "requested_categories": removal.categories_requested if removal else [],
            "removed_categories": removed_tags,
            "output_path": str(removal.output_path) if removal else None,
            "bytes_saved": removal.bytes_saved if removal else 0,
        },
        "remaining_fields": remaining_tags,
        "verification": verification_info,
        "warnings": sorted(list(set(all_warnings))),
        "limitations": sorted(list(set(all_limitations))),
    }


def export_json_report(
    output_path: Path | str,
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
) -> Path:
    """Writes a comprehensive JSON report to the specified file path."""
    data = build_file_report_dict(scan, removal, verification)
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return out_p


def export_batch_csv(records: List[Dict[str, Any]], output_path: Path | str) -> Path:
    """Exports batch processing summary records to a CSV file."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "file_name",
        "validation",
        "format",
        "original_size",
        "cleaned_size",
        "bytes_saved",
        "privacy_risk",
        "risk_score",
        "gps_detected",
        "author_detected",
        "date_detected",
        "removal_status",
        "verification_status",
        "output_path",
        "notes",
    ]

    with open(out_p, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for rec in records:
            writer.writerow({
                "file_name": rec.get("file_name", ""),
                "validation": rec.get("validation", ""),
                "format": rec.get("format", ""),
                "original_size": rec.get("original_size", 0),
                "cleaned_size": rec.get("cleaned_size", 0),
                "bytes_saved": rec.get("bytes_saved", 0),
                "privacy_risk": rec.get("privacy_risk", ""),
                "risk_score": rec.get("risk_score", 0),
                "gps_detected": rec.get("gps_detected", False),
                "author_detected": rec.get("author_detected", False),
                "date_detected": rec.get("date_detected", False),
                "removal_status": rec.get("removal_status", ""),
                "verification_status": rec.get("verification_status", ""),
                "output_path": rec.get("output_path", ""),
                "notes": rec.get("notes", ""),
            })

    return out_p
