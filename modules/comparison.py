"""Before/after metadata comparison.

Compares two independent scans (original vs cleaned) and reports removed,
remaining, changed, and newly introduced tags, plus which sensitive findings
were removed or survived.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import config
from modules.metadata_scanner import MetadataTag, ScanResult
from modules.privacy_analyzer import RiskAssessmentItem, RiskLevel


@dataclass
class ChangedTag:
    key: str
    before: str
    after: str


@dataclass
class ComparisonResult:
    before_total: int = 0
    after_total: int = 0
    removed_tags: List[str] = field(default_factory=list)
    remaining_tags: List[str] = field(default_factory=list)
    changed_tags: List[ChangedTag] = field(default_factory=list)
    introduced_tags: List[str] = field(default_factory=list)
    structural_remaining: List[str] = field(default_factory=list)
    sensitive_removed: List[RiskAssessmentItem] = field(default_factory=list)
    sensitive_remaining: List[RiskAssessmentItem] = field(default_factory=list)
    before_risk_score: int = 0
    after_risk_score: int = 0
    before_risk_level: str = ""
    after_risk_level: str = ""

    @property
    def removed_count(self) -> int:
        return len(self.removed_tags)

    @property
    def remaining_count(self) -> int:
        return len(self.remaining_tags)

    @property
    def introduced_count(self) -> int:
        return len(self.introduced_tags)

    @property
    def sensitive_removed_count(self) -> int:
        return len(self.sensitive_removed)

    @property
    def sensitive_remaining_count(self) -> int:
        return len(self.sensitive_remaining)

    @property
    def all_sensitive_removed(self) -> bool:
        return not self.sensitive_remaining


def _value_text(tag: MetadataTag) -> str:
    value = tag.display_value if tag.display_value is not None else tag.value
    return str(value).strip()


def _sensitive_by_key(scan: ScanResult) -> Dict[str, RiskAssessmentItem]:
    result: Dict[str, RiskAssessmentItem] = {}
    report = scan.privacy_report
    if not report:
        return result
    for item in report.items:
        if item.risk_level.priority >= RiskLevel.MEDIUM.priority:
            result[item.tag_key] = item
    return result


def compare_scans(before: ScanResult, after: ScanResult) -> ComparisonResult:
    """Builds a structural diff between an original and a cleaned scan."""
    before_tags: Dict[str, MetadataTag] = before.image_metadata
    after_tags: Dict[str, MetadataTag] = after.image_metadata

    result = ComparisonResult(
        before_total=before.total_embedded_tags,
        after_total=after.total_embedded_tags,
        before_risk_score=before.privacy_report.risk_score if before.privacy_report else 0,
        after_risk_score=after.privacy_report.risk_score if after.privacy_report else 0,
        before_risk_level=before.privacy_report.overall_risk.value if before.privacy_report else "",
        after_risk_level=after.privacy_report.overall_risk.value if after.privacy_report else "",
    )

    before_keys = set(before_tags)
    after_keys = set(after_tags)
    before_sensitive = _sensitive_by_key(before)
    after_sensitive = _sensitive_by_key(after)

    for key in sorted(before_keys - after_keys):
        result.removed_tags.append(key)
        if key in before_sensitive:
            result.sensitive_removed.append(before_sensitive[key])

    for key in sorted(before_keys & after_keys):
        before_tag = before_tags[key]
        after_tag = after_tags[key]
        if _value_text(before_tag) != _value_text(after_tag):
            result.changed_tags.append(
                ChangedTag(key=key, before=_value_text(before_tag), after=_value_text(after_tag))
            )
        if config.is_structural_tag(after_tag.group, after_tag.name):
            result.structural_remaining.append(key)
        else:
            result.remaining_tags.append(key)
        if key in after_sensitive:
            result.sensitive_remaining.append(after_sensitive[key])

    for key in sorted(after_keys - before_keys):
        tag = after_tags[key]
        # ExifTool recomputes structural/composite tags; these are not new metadata.
        if config.is_structural_tag(tag.group, tag.name):
            continue
        result.introduced_tags.append(key)

    # Sensitive tags that survived but changed value are still remaining.
    for key in after_keys - before_keys:
        if key in after_sensitive and key not in {i.tag_key for i in result.sensitive_remaining}:
            result.sensitive_remaining.append(after_sensitive[key])

    return result


def comparison_to_dict(comparison: ComparisonResult) -> Dict[str, object]:
    return {
        "before_total_tags": comparison.before_total,
        "after_total_tags": comparison.after_total,
        "removed_tags": comparison.removed_tags,
        "remaining_tags": comparison.remaining_tags,
        "changed_tags": [
            {"tag": c.key, "before": c.before, "after": c.after}
            for c in comparison.changed_tags
        ],
        "introduced_tags": comparison.introduced_tags,
        "structural_remaining": comparison.structural_remaining,
        "removed_count": comparison.removed_count,
        "remaining_count": comparison.remaining_count,
        "introduced_count": comparison.introduced_count,
        "sensitive_tags_removed": [
            {"tag": i.tag_name, "key": i.tag_key, "risk": i.risk_level.value}
            for i in comparison.sensitive_removed
        ],
        "sensitive_tags_remaining": [
            {"tag": i.tag_name, "key": i.tag_key, "risk": i.risk_level.value}
            for i in comparison.sensitive_remaining
        ],
        "sensitive_removed_count": comparison.sensitive_removed_count,
        "sensitive_remaining_count": comparison.sensitive_remaining_count,
        "risk_score_before": comparison.before_risk_score,
        "risk_score_after": comparison.after_risk_score,
        "risk_level_before": comparison.before_risk_level,
        "risk_level_after": comparison.after_risk_level,
    }
