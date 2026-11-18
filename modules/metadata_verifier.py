"""Independent metadata verification engine.

The verifier re-opens the cleaned file with an independent scan and compares it
to the original.  It never infers success from an ExifTool exit code.

Two layers are exposed:

* ``VerificationStatus`` (PASS/WARNING/INCOMPLETE/FAIL) - the original,
  category-oriented status used by earlier releases and existing tests.
* ``VerificationOutcome`` (VERIFIED CLEAN / PARTIALLY CLEANED /
  SENSITIVE DATA REMAINS / VERIFICATION FAILED) - the explicit, profile-aware
  result shown by the CLI and reports.

"VERIFIED CLEAN" means:
  * full-clean profile: no non-structural metadata tag remains; or
  * selective profile: no sensitive (MEDIUM or higher) finding remains in the
    targeted categories, no sensitive finding was newly introduced, and the
    verifier could inspect the relevant metadata blocks.
It does **not** mean that steganography, pixel content, or invisible data has
been ruled out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from modules.comparison import ComparisonResult, compare_scans
from modules.image_validator import safe_resolve_path, validate_image
from modules.metadata_scanner import MetadataScanner, MetadataTag, ScanResult
from modules.privacy_analyzer import RiskAssessmentItem, RiskLevel
from modules.sanitizer_profiles import get_profile


class VerificationStatus(str, Enum):
    """Legacy category-oriented verification status."""

    PASS = "PASS"
    WARNING = "WARNING"
    INCOMPLETE = "INCOMPLETE"
    FAIL = "FAIL"


class VerificationOutcome(str, Enum):
    """Explicit, profile-aware verification outcome."""

    VERIFIED_CLEAN = "VERIFIED CLEAN"
    PARTIALLY_CLEANED = "PARTIALLY CLEANED"
    SENSITIVE_DATA_REMAINS = "SENSITIVE DATA REMAINS"
    VERIFICATION_FAILED = "VERIFICATION FAILED"


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
    outcome: VerificationOutcome = VerificationOutcome.VERIFICATION_FAILED
    outcome_reason: str = ""
    profile: Optional[str] = None
    comparison: Optional[ComparisonResult] = None
    residual_metadata_tags: List[str] = field(default_factory=list)
    original_image: Optional[Path] = None


class MetadataVerifier:
    """Performs rigorous, independent verification of metadata removal."""

    def __init__(self, scanner: Optional[MetadataScanner] = None) -> None:
        self.scanner = scanner or MetadataScanner()

    # ------------------------------------------------------------------
    def _normalize_targets(
        self,
        targeted_categories: Optional[List[str] | str],
        profile: Optional[str],
    ) -> tuple[List[str], bool, Optional[str]]:
        prof = get_profile(profile) if profile else None
        if prof is not None:
            if prof.key == "maximum":
                return [c for c in config.METADATA_CATEGORIES if c != "all"], True, prof.key
            if prof.key == "custom":
                # For custom, verification targets come from the category list.
                pass
            elif prof.categories:
                return list(prof.categories), False, prof.key

        if targeted_categories is None or targeted_categories == "all" or targeted_categories == ["all"]:
            return [c for c in config.METADATA_CATEGORIES if c != "all"], True, prof.key if prof else None
        if isinstance(targeted_categories, str):
            active = [c.strip().lower() for c in targeted_categories.split(",") if c.strip()]
        else:
            active = [str(c).lower() for c in targeted_categories]
        is_full = "all" in active
        if is_full:
            active = [c for c in config.METADATA_CATEGORIES if c != "all"]
        return active, is_full, prof.key if prof else None

    # ------------------------------------------------------------------
    def verify(
        self,
        image_path: str | Path,
        targeted_categories: Optional[List[str] | str] = None,
        original_image_path: Optional[str | Path] = None,
        profile: Optional[str] = None,
        scan_mode: str = "standard",
    ) -> VerificationReport:
        """Independently verifies an image file.

        Args:
            scan_mode: Extraction depth for the verification scan; deeper modes
                reduce the chance that an exotic metadata block is missed.
        """
        try:
            resolved_target = safe_resolve_path(image_path, must_exist=True)
        except Exception as exc:
            return VerificationReport(
                target_image=Path(image_path),
                status=VerificationStatus.FAIL,
                targeted_categories=[],
                scanned_tags_count=0,
                summary_message=f"Verification failed: target file cannot be accessed ({exc}).",
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                outcome_reason=f"The target file could not be accessed: {exc}",
            )

        val_res = validate_image(resolved_target)
        if not val_res.is_valid:
            return VerificationReport(
                target_image=resolved_target,
                status=VerificationStatus.FAIL,
                targeted_categories=[],
                scanned_tags_count=0,
                summary_message=f"Verification failed: invalid image ({'; '.join(val_res.errors)}).",
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                outcome_reason="The target is not a readable, supported image.",
            )

        active_targets, is_full_clean, profile_key = self._normalize_targets(
            targeted_categories, profile
        )

        scan = self.scanner.scan(resolved_target, mode=scan_mode)
        total_embedded = scan.total_embedded_tags

        limitations: List[str] = list(scan.limitations)
        if scan.scanner_backend == "pillow_fallback":
            limitations.append(
                "Verification engine running on the Pillow fallback; IPTC/XMP/MakerNotes cannot be "
                "definitively verified."
            )
        if not scan.inspection_complete:
            limitations.append(
                "Metadata inspection did not complete; the file cannot be certified as clean."
            )

        remaining_targeted_tags: List[MetadataTag] = []
        category_checks: List[CategoryCheckResult] = []

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
                        message=f"Found {len(tag_names)} tag(s) belonging to targeted category '{cat}'.",
                    )
                )
            else:
                category_checks.append(
                    CategoryCheckResult(
                        category=cat,
                        is_targeted=True,
                        status=VerificationStatus.PASS,
                        found_tags=[],
                        message=f"No metadata detected for category '{cat}'.",
                    )
                )

        remaining_sensitive: List[RiskAssessmentItem] = []
        if scan.privacy_report:
            for item in scan.privacy_report.items:
                if item.risk_level.priority >= RiskLevel.MEDIUM.priority:
                    remaining_sensitive.append(item)

        # Residual non-structural metadata (used to define a full clean).
        residual_metadata_tags: List[str] = []
        for key, tag in scan.image_metadata.items():
            if tag.derived:
                continue
            if config.is_structural_tag(tag.group, tag.name):
                continue
            residual_metadata_tags.append(key)

        # ------------------------------------------------------------------
        # Legacy status (kept stable for report compatibility)
        # ------------------------------------------------------------------
        if remaining_targeted_tags:
            if is_full_clean:
                has_high = any(
                    any(k in t.name.lower() for k in ("gps", "artist", "author", "latitude", "longitude"))
                    for t in remaining_targeted_tags
                )
                status = VerificationStatus.FAIL if has_high else VerificationStatus.WARNING
                summary = (
                    f"Targeted metadata removal check failed: {len(remaining_targeted_tags)} "
                    "targeted metadata tags remain in the image."
                )
            else:
                status = VerificationStatus.WARNING
                summary = (
                    f"Selective verification warning: {len(remaining_targeted_tags)} "
                    "tags from targeted categories were detected."
                )
        elif limitations and scan.scanner_backend == "pillow_fallback":
            status = VerificationStatus.INCOMPLETE
            summary = (
                "Verification INCOMPLETE: Available scanning tools cannot inspect all metadata categories "
                "(ExifTool missing). Basic EXIF tags passed, but IPTC/XMP cannot be verified."
            )
        elif not scan.inspection_complete:
            status = VerificationStatus.INCOMPLETE
            summary = (
                "Verification INCOMPLETE: metadata inspection did not complete, so cleanliness "
                "cannot be certified."
            )
        elif len(remaining_sensitive) > 0 and not is_full_clean:
            status = VerificationStatus.WARNING
            summary = (
                f"Verification WARNING: Targeted categories passed, but {len(remaining_sensitive)} "
                "unselected sensitive tags remain in the file."
            )
        else:
            status = VerificationStatus.PASS
            summary = (
                "Verification PASS: All targeted metadata categories passed verification. "
                "This does not guarantee that every metadata field has been removed."
            )

        # ------------------------------------------------------------------
        # Explicit outcome + before/after comparison
        # ------------------------------------------------------------------
        comparison: Optional[ComparisonResult] = None
        original_path: Optional[Path] = None
        if original_image_path:
            try:
                original_path = safe_resolve_path(original_image_path, must_exist=True)
                original_scan = self.scanner.scan(original_path, mode=scan_mode)
                if original_scan.validation.is_valid:
                    comparison = compare_scans(original_scan, scan)
                else:
                    limitations.append("Original image could not be scanned; before/after comparison unavailable.")
            except Exception as exc:
                limitations.append(f"Before/after comparison failed: {exc}")

        outcome, reason = self._decide_outcome(
            scan=scan,
            active_targets=active_targets,
            is_full_clean=is_full_clean,
            remaining_targeted_tags=remaining_targeted_tags,
            remaining_sensitive=remaining_sensitive,
            residual_metadata_tags=residual_metadata_tags,
            comparison=comparison,
        )

        if outcome == VerificationOutcome.SENSITIVE_DATA_REMAINS:
            summary = (
                f"{summary} Outcome: SENSITIVE DATA REMAINS — {len(remaining_sensitive)} "
                "sensitive tag(s) were detected after cleaning. Do not publish this file without further cleaning."
            )
        elif outcome == VerificationOutcome.PARTIALLY_CLEANED:
            summary = (
                f"{summary} Outcome: PARTIALLY CLEANED — targeted categories were removed, but "
                "residual or unselected sensitive metadata remains."
            )
        elif outcome == VerificationOutcome.VERIFIED_CLEAN:
            summary = (
                f"{summary} Outcome: VERIFIED CLEAN — no residual sensitive metadata was detected in the "
                "inspected structures for the selected profile. This does not guarantee removal of "
                "steganographic or non-metadata content."
            )

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
            outcome=outcome,
            outcome_reason=reason,
            profile=profile_key,
            comparison=comparison,
            residual_metadata_tags=residual_metadata_tags,
            original_image=original_path,
        )

    # ------------------------------------------------------------------
    def _decide_outcome(
        self,
        *,
        scan: ScanResult,
        active_targets: List[str],
        is_full_clean: bool,
        remaining_targeted_tags: List[MetadataTag],
        remaining_sensitive: List[RiskAssessmentItem],
        residual_metadata_tags: List[str],
        comparison: Optional[ComparisonResult],
    ) -> tuple[VerificationOutcome, str]:
        # Cannot verify with a backend that cannot inspect the relevant structures.
        if scan.scanner_backend == "pillow_fallback" or not scan.validation.is_valid:
            return (
                VerificationOutcome.VERIFICATION_FAILED,
                "The available scanning backend cannot fully inspect the file, so a clean result "
                "cannot be certified. Install ExifTool and re-run verification.",
            )

        # A failed or partial backend read means cleanliness cannot be certified.
        if not scan.inspection_complete:
            return (
                VerificationOutcome.VERIFICATION_FAILED,
                "Metadata inspection did not complete, so this file cannot be certified as clean. "
                "Re-run verification and ensure the file is readable.",
            )

        # Map sensitive findings back to categories via the tag key.
        targeted_sensitive = []
        for item in remaining_sensitive:
            tag = scan.image_metadata.get(item.tag_key)
            if tag is not None:
                if tag.category in active_targets:
                    targeted_sensitive.append(item)
            elif item.category in active_targets:
                targeted_sensitive.append(item)

        if targeted_sensitive or remaining_targeted_tags:
            return (
                VerificationOutcome.SENSITIVE_DATA_REMAINS,
                "At least one targeted category still contains detectable metadata after cleaning.",
            )

        if is_full_clean and residual_metadata_tags:
            if remaining_sensitive:
                return (
                    VerificationOutcome.SENSITIVE_DATA_REMAINS,
                    "Non-structural metadata remains after a full-clean request.",
                )
            return (
                VerificationOutcome.PARTIALLY_CLEANED,
                "Some non-structural metadata remains, but no sensitive finding was detected.",
            )

        if not is_full_clean and remaining_sensitive:
            return (
                VerificationOutcome.PARTIALLY_CLEANED,
                "Targeted categories are clean, but sensitive metadata from unselected categories remains.",
            )

        if comparison and (comparison.introduced_tags or comparison.changed_tags):
            # Newly introduced non-structural tags mean the "before" state was not faithfully preserved.
            if comparison.introduced_tags:
                return (
                    VerificationOutcome.PARTIALLY_CLEANED,
                    "Cleaning introduced new non-structural metadata tags; review the output.",
                )

        return (
            VerificationOutcome.VERIFIED_CLEAN,
            "No residual sensitive metadata was detected in the inspected structures for the selected profile.",
        )
