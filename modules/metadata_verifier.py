"""Independent metadata verification engine.

Audits cleaned images to guarantee targeted metadata fields were truly eliminated.
Evaluates remaining tags, sensitive privacy remnants, tool limitations, and produces
definitive compliance statuses (PASS, WARNING, INCOMPLETE, FAIL).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

import config
from modules.image_validator import ValidationResult, safe_resolve_path, validate_image
from modules.metadata_scanner import MetadataScanner, MetadataTag, ScanResult
from modules.privacy_analyzer import PrivacyReport, RiskAssessmentItem, RiskLevel


class VerificationStatus(str, Enum):
    """Rigorous verification status outcomes."""
    PASS = "PASS"
    WARNING = "WARNING"
    INCOMPLETE = "INCOMPLETE"
    FAIL = "FAIL"


@dataclass
class CategoryCheckResult:
    """Audit result for a specific metadata category."""
    category: str
    is_targeted: bool
    status: VerificationStatus
    found_tags: List[str] = field(default_factory=list)
    message: str = ""


@dataclass
class VerificationReport:
    """Comprehensive post-cleaning or independent audit report."""
    target_image: Path
    status: VerificationStatus
    targeted_categories: List[str]
    scanned_tags_count: int
    remaining_targeted_tags: List[MetadataTag] = field(default_factory=list)
    remaining_sensitive_tags: List[RiskAssessmentItem] = field(default_factory=list)
    category_checks: List[CategoryCheckResult] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    summary_message: str = ""
    scan_result: Optional[ScanResult] = None


class MetadataVerifier:
    """Performs rigorous, independent verification of image metadata removal."""

    def __init__(self, scanner: Optional[MetadataScanner] = None) -> None:
        self.scanner = scanner or MetadataScanner()

    def verify(
        self,
        image_path: str | Path,
        targeted_categories: Optional[List[str] | str] = None,
        original_image_path: Optional[str | Path] = None,
    ) -> VerificationReport:
        """Independently verifies an image file.

        Args:
            image_path: Path to the image to verify.
            targeted_categories: List of categories expected to be removed (e.g. ['all'] or ['gps', 'device']).
            original_image_path: Optional path to the original uncleaned image for comparative diffing.

        Returns:
            VerificationReport with PASS, WARNING, INCOMPLETE, or FAIL status.
        """
        # Resolve path safely
        try:
            resolved_target = safe_resolve_path(image_path, must_exist=True)
        except Exception as e:
            return VerificationReport(
                target_image=Path(image_path),
                status=VerificationStatus.FAIL,
                targeted_categories=[],
                scanned_tags_count=0,
                summary_message=f"Verification failed: Target file cannot be accessed ({e})."
            )

        # Validate image format and integrity
        val_res = validate_image(resolved_target)
        if not val_res.is_valid:
            return VerificationReport(
                target_image=resolved_target,
                status=VerificationStatus.FAIL,
                targeted_categories=[],
                scanned_tags_count=0,
                summary_message=f"Verification failed: Invalid image ({'; '.join(val_res.errors)})."
            )

        # Normalize targeted categories
        if targeted_categories is None or targeted_categories == "all" or targeted_categories == ["all"]:
            active_targets = [c for c in config.METADATA_CATEGORIES if c != "all"]
            is_full_clean = True
        elif isinstance(targeted_categories, str):
            active_targets = [c.strip().lower() for c in targeted_categories.split(",") if c.strip()]
            is_full_clean = "all" in active_targets
            if is_full_clean:
                active_targets = [c for c in config.METADATA_CATEGORIES if c != "all"]
        else:
            active_targets = [c.lower() for c in targeted_categories]
            is_full_clean = "all" in active_targets
            if is_full_clean:
                active_targets = [c for c in config.METADATA_CATEGORIES if c != "all"]

        # Run independent scan
        scan = self.scanner.scan(resolved_target)
        total_embedded = scan.total_embedded_tags

        # Collect limitations
        limitations: List[str] = list(scan.limitations)
        if scan.scanner_backend == "pillow_fallback":
            limitations.append(
                "Verification engine running on Pillow fallback; cannot definitively verify IPTC/XMP structures."
            )

        remaining_targeted_tags: List[MetadataTag] = []
        category_checks: List[CategoryCheckResult] = []

        # Check each category
        for cat in active_targets:
            cat_summary = scan.categories.get(cat)
            detected_tags = cat_summary.tags if cat_summary else []
            tag_names = [t.name for t in detected_tags]

            if tag_names:
                remaining_targeted_tags.extend(detected_tags)
                category_checks.append(
                    CategoryCheckResult(
                        category=cat,
                        is_targeted=True,
                        status=VerificationStatus.FAIL if is_full_clean else VerificationStatus.WARNING,
                        found_tags=tag_names,
                        message=f"FAILED: Found {len(tag_names)} tags belonging to targeted category '{cat}'."
                    )
                )
            else:
                category_checks.append(
                    CategoryCheckResult(
                        category=cat,
                        is_targeted=True,
                        status=VerificationStatus.PASS,
                        found_tags=[],
                        message=f"PASSED: No metadata detected for category '{cat}'."
                    )
                )

        # Identify any remaining high/medium risk items from privacy report
        remaining_sensitive: List[RiskAssessmentItem] = []
        if scan.privacy_report:
            for item in scan.privacy_report.items:
                if item.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
                    remaining_sensitive.append(item)

        # Determine Final Overall Status
        if len(remaining_targeted_tags) > 0:
            if is_full_clean:
                # In full clean mode, finding GPS or author is an outright FAIL
                has_high = any(
                    "gps" in t.name.lower() or "artist" in t.name.lower() or "author" in t.name.lower()
                    for t in remaining_targeted_tags
                )
                status = VerificationStatus.FAIL if has_high else VerificationStatus.WARNING
                summary = (
                    f"Targeted metadata removal check failed: {len(remaining_targeted_tags)} "
                    f"targeted metadata tags remain in the image."
                )
            else:
                status = VerificationStatus.WARNING
                summary = (
                    f"Selective verification warning: {len(remaining_targeted_tags)} "
                    f"tags from targeted categories were detected."
                )
        elif limitations and scan.scanner_backend == "pillow_fallback":
            # If ExifTool was unavailable, we cannot guarantee full inspection
            status = VerificationStatus.INCOMPLETE
            summary = (
                "Verification INCOMPLETE: Available scanning tools cannot inspect all metadata categories "
                "(ExifTool missing). Basic EXIF tags passed, but IPTC/XMP cannot be verified."
            )
        elif len(remaining_sensitive) > 0 and not is_full_clean:
            status = VerificationStatus.WARNING
            summary = (
                f"Verification WARNING: Targeted categories passed, but {len(remaining_sensitive)} "
                f"unselected sensitive tags remain in the file."
            )
        else:
            status = VerificationStatus.PASS
            summary = "Verification PASS: All defined verification checks passed. No targeted metadata detected."

        return VerificationReport(
            target_image=resolved_target,
            status=status,
            targeted_categories=active_targets,
            scanned_tags_count=total_embedded,
            remaining_targeted_tags=remaining_targeted_tags,
            remaining_sensitive_tags=remaining_sensitive,
            category_checks=category_checks,
            limitations=limitations,
            summary_message=summary,
            scan_result=scan,
        )
