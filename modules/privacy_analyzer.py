"""Transparent rule-based privacy risk analyzer for image metadata.

Evaluates metadata tags, classifies exposure into HIGH, MEDIUM, LOW, or
INFORMATIONAL risk tiers, and provides clear explanations for each classification.
Modularly designed with an extensible base class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import config


class RiskLevel(str, Enum):
    """Privacy risk classifications."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def priority(self) -> int:
        levels = {
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFORMATIONAL: 1,
        }
        return levels[self]


@dataclass
class RiskAssessmentItem:
    """Evaluation result for an individual metadata tag."""
    tag_name: str
    category: str
    risk_level: RiskLevel
    value_preview: str
    explanation: str
    group: Optional[str] = None


@dataclass
class PrivacyReport:
    """Comprehensive privacy evaluation of an image's metadata."""
    overall_risk: RiskLevel
    risk_score: int  # 0 to 100
    items: List[RiskAssessmentItem] = field(default_factory=list)
    summary_narrative: str = ""
    recommendations: List[str] = field(default_factory=list)

    @property
    def high_risk_count(self) -> int:
        return sum(1 for item in self.items if item.risk_level == RiskLevel.HIGH)

    @property
    def medium_risk_count(self) -> int:
        return sum(1 for item in self.items if item.risk_level == RiskLevel.MEDIUM)

    @property
    def low_risk_count(self) -> int:
        return sum(1 for item in self.items if item.risk_level == RiskLevel.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for item in self.items if item.risk_level == RiskLevel.INFORMATIONAL)


class BasePrivacyAnalyzer:
    """Abstract interface allowing alternative or future AI-assisted privacy engines."""

    def analyze(self, metadata: Dict[str, Any]) -> PrivacyReport:
        raise NotImplementedError


class RuleBasedPrivacyAnalyzer(BasePrivacyAnalyzer):
    """Transparent, deterministic rule-based privacy risk evaluator."""

    # Explicit explanations mapped to metadata concepts
    EXPLANATIONS = {
        "gps": (
            "Exposes precise geographical coordinates (latitude, longitude, altitude) "
            "where the image was captured. Enables physical stalking, residence profiling, "
            "and pattern-of-life surveillance."
        ),
        "author": (
            "Exposes personal identity, creator names, usernames, copyright owner, "
            "or contact information directly linking the image to an individual."
        ),
        "timestamp": (
            "Exposes exact capture time and timezone offsets. Can correlate a user's "
            "physical presence at specific dates/times or undermine anonymity."
        ),
        "device": (
            "Exposes hardware make, model, lens details, or serial numbers. Serial numbers "
            "form persistent hardware fingerprints that link different photos to the same device."
        ),
        "comments": (
            "Contains user-written comments, descriptions, or software notes that may "
            "contain sensitive notes, system paths, or personal context."
        ),
        "thumbnail": (
            "Embedded preview/thumbnail may retain uncropped original content or image "
            "data even if the main image was cropped or edited."
        ),
        "technical": (
            "Technical exposure and camera settings (ISO, focal length, shutter speed). "
            "Generally low privacy sensitivity, though unique lens profiles may assist fingerprinting."
        ),
        "informational": (
            "Non-sensitive image dimensions, pixel bit depth, and compression structure."
        ),
    }

    def __init__(self, rules: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.rules = rules or config.RISK_RULES

    def _sanitize_value_preview(self, tag_name: str, value: Any) -> str:
        """Sanitizes metadata value for presentation."""
        val_str = str(value).strip()
        tag_lower = tag_name.lower()

        # For serial numbers, mask middle characters if very long
        if "serial" in tag_lower and len(val_str) > 8:
            return f"{val_str[:3]}****{val_str[-3:]}"

        # Truncate overly long binary or base64 strings
        if len(val_str) > 80:
            return f"{val_str[:77]}..."

        return val_str

    def evaluate_tag(self, tag_name: str, value: Any, group: Optional[str] = None) -> RiskAssessmentItem:
        """Assesses the privacy risk of a single metadata tag."""
        tag_lower = tag_name.lower()
        group_lower = (group or "").lower()
        val_preview = self._sanitize_value_preview(tag_name, value)

        # 1. Check INFORMATIONAL rules first (geometry, sampling, encoding)
        if tag_lower in ("ycbcrpositioning", "ycbcrsubsampling", "orientation", "colorspace", "exifversion", "flashpixversion", "interopversion") or any(
            p in tag_lower for p in config.RISK_RULES["INFORMATIONAL"]["patterns"]
        ):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="informational",
                risk_level=RiskLevel.INFORMATIONAL,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["informational"],
                group=group,
            )

        # 2. Check LOW risk rules (camera exposure settings, lighting, optics)
        if tag_lower in (
            "exposuretime", "lightsource", "fnumber", "aperture", "iso", "shutterspeed",
            "focallength", "whitebalance", "flash", "meteringmode", "exposureprogram",
            "exposurecompensation", "maxaperturevalue", "scenetype", "scenecapturetype",
            "sensingmethod", "digitalzoomratio", "gaincontrol", "contrast", "saturation", "sharpness"
        ) or any(p in tag_lower for p in config.RISK_RULES["LOW"]["patterns"]):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="technical",
                risk_level=RiskLevel.LOW,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["technical"],
                group=group,
            )

        # 3. Check HIGH risk rules (Location / Identity)
        if group_lower == "gps" or tag_lower.startswith("gps") or any(p in tag_lower for p in ("latitude", "longitude", "altitude", "coordinates", "gpsposition")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="gps",
                risk_level=RiskLevel.HIGH,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["gps"],
                group=group,
            )

        if any(p in tag_lower for p in ("artist", "creator", "by-line", "author", "ownername", "creatorcontactinfo")) or (tag_lower in ("credit", "source", "owner")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="author",
                risk_level=RiskLevel.HIGH,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["author"],
                group=group,
            )

        # 4. Check MEDIUM risk rules
        if any(p in tag_lower for p in ("datetime", "createdate", "modifydate", "timestamp", "subsectime", "offsettime", "historywhen", "digitalcreation")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="date",
                risk_level=RiskLevel.MEDIUM,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["timestamp"],
                group=group,
            )

        if any(p in tag_lower for p in ("make", "model", "serial", "lens", "software", "firmware", "device", "hostcomputer")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="device",
                risk_level=RiskLevel.MEDIUM,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["device"],
                group=group,
            )

        if any(p in tag_lower for p in ("comment", "description", "note", "headline", "caption", "xpcomment")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="comments",
                risk_level=RiskLevel.MEDIUM,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["comments"],
                group=group,
            )

        if any(p in tag_lower for p in ("copyright", "rights", "usageterms", "webstatement")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="copyright",
                risk_level=RiskLevel.MEDIUM,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["author"],
                group=group,
            )

        if any(p in tag_lower for p in ("thumb", "preview", "thumbnail")):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="thumbnail",
                risk_level=RiskLevel.MEDIUM,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["thumbnail"],
                group=group,
            )

        # Check INFORMATIONAL rules
        if any(p in tag_lower for p in config.RISK_RULES["INFORMATIONAL"]["patterns"]):
            return RiskAssessmentItem(
                tag_name=tag_name,
                category="informational",
                risk_level=RiskLevel.INFORMATIONAL,
                value_preview=val_preview,
                explanation=self.EXPLANATIONS["informational"],
                group=group,
            )

        # Fallback for unrecognized technical metadata
        return RiskAssessmentItem(
            tag_name=tag_name,
            category="other",
            risk_level=RiskLevel.LOW,
            value_preview=val_preview,
            explanation="General image metadata tag. Low privacy sensitivity under standard threat models.",
            group=group,
        )

    def analyze(self, metadata: Dict[str, Any]) -> PrivacyReport:
        """Analyzes a dictionary of metadata tags and generates a PrivacyReport.

        Args:
            metadata: Dict where keys are tag names (or 'Group:TagName') and values are tag values.

        Returns:
            PrivacyReport containing overall rating, score, items, and recommendations.
        """
        items: List[RiskAssessmentItem] = []

        for full_key, value in metadata.items():
            if ":" in full_key:
                group, tag_name = full_key.split(":", 1)
            else:
                group = None
                tag_name = full_key

            # Skip pure filesystem attributes from privacy risk analysis of the image itself
            if group in ("System", "system"):
                continue

            if group in ("File", "file") and any(
                k in tag_name.lower()
                for k in ("filename", "directory", "filesize", "filemodifydate", "fileaccessdate", "filecreatedate", "filepermissions")
            ):
                continue

            # Skip ExifTool version marker
            if tag_name.lower() in ("exiftoolversion", "sourcefile"):
                continue

            item = self.evaluate_tag(tag_name, value, group=group)
            items.append(item)

        high_count = sum(1 for i in items if i.risk_level == RiskLevel.HIGH)
        med_count = sum(1 for i in items if i.risk_level == RiskLevel.MEDIUM)
        low_count = sum(1 for i in items if i.risk_level == RiskLevel.LOW)

        # Determine overall risk
        if high_count > 0:
            overall_risk = RiskLevel.HIGH
            # Calculate score 70 - 100
            risk_score = min(100, 70 + (high_count * 10) + (med_count * 2))
        elif med_count > 0:
            overall_risk = RiskLevel.MEDIUM
            # Calculate score 35 - 69
            risk_score = min(69, 35 + (med_count * 5) + (low_count * 1))
        elif low_count > 0:
            overall_risk = RiskLevel.LOW
            risk_score = min(34, 10 + (low_count * 2))
        else:
            overall_risk = RiskLevel.INFORMATIONAL
            risk_score = 0

        # Construct narrative and recommendations
        recommendations: List[str] = []
        if overall_risk == RiskLevel.HIGH:
            narrative = (
                f"CRITICAL PRIVACY RISK: Image contains {high_count} high-risk identifying tags "
                f"(such as geographic coordinates or author identity). Sharing this file publicly "
                f"risks exposing the subject's exact physical location and identity."
            )
            recommendations.append("Execute full metadata sanitization (`clean --remove all`) before sharing.")
            recommendations.append("Strip GPS coordinates immediately to protect physical safety.")
        elif overall_risk == RiskLevel.MEDIUM:
            narrative = (
                f"MODERATE PRIVACY RISK: Detected {med_count} medium-risk tags (timestamps, device models, "
                f"or serial numbers). These fields enable behavioral profiling and device tracking."
            )
            recommendations.append("Sanitize timestamps and device serial numbers prior to distribution.")
        elif overall_risk == RiskLevel.LOW:
            narrative = (
                f"LOW PRIVACY RISK: Detected {low_count} low-risk technical camera settings. "
                f"No direct personal identifiers or GPS coordinates were found."
            )
            recommendations.append("Metadata cleaning is optional, but recommended for complete operational security.")
        else:
            narrative = "NO METADATA THREAT DETECTED: Image contains no detectable privacy-sensitive metadata."
            recommendations.append("File is safe to publish from a metadata privacy standpoint.")

        return PrivacyReport(
            overall_risk=overall_risk,
            risk_score=risk_score,
            items=items,
            summary_narrative=narrative,
            recommendations=recommendations,
        )
