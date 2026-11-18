"""Transparent rule-based privacy risk analyzer for image metadata.

The engine classifies each embedded tag into one of five sensitivity levels,
records a human-readable explanation and a recommended action, and combines the
findings into an explainable privacy score.

The scoring model is a deliberately simple additive heuristic. It is documented
in ``docs/METHODOLOGY.md`` and is **not** presented as a scientifically
validated risk metric.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from modules.metadata_types import tag_group, tag_is_derived, tag_name_of, tag_value_of


class RiskLevel(str, Enum):
    """Privacy sensitivity classifications, ordered from lowest to highest."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def priority(self) -> int:
        return {
            RiskLevel.INFORMATIONAL: 1,
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 4,
            RiskLevel.CRITICAL: 5,
        }[self]

    @property
    def label(self) -> str:
        return {
            RiskLevel.INFORMATIONAL: "Informational",
            RiskLevel.LOW: "Low Risk",
            RiskLevel.MEDIUM: "Medium Risk",
            RiskLevel.HIGH: "High Risk",
            RiskLevel.CRITICAL: "Critical Privacy Exposure",
        }[self]


@dataclass
class RiskAssessmentItem:
    """Evaluation result for an individual metadata tag."""

    tag_name: str
    category: str
    risk_level: RiskLevel
    value_preview: str
    explanation: str
    group: Optional[str] = None
    recommendation: str = ""
    tag_key: str = ""

    @property
    def is_sensitive(self) -> bool:
        return self.risk_level.priority >= RiskLevel.MEDIUM.priority


@dataclass
class ScoreComponent:
    """One line of the documented risk score calculation."""

    level: str
    count: int
    weight_per_tag: int
    raw_contribution: int
    capped_contribution: int


@dataclass
class CategoryRisk:
    """Aggregated risk view for one semantic category."""

    category: str
    count: int
    max_level: RiskLevel
    contribution: int
    examples: List[str] = field(default_factory=list)


@dataclass
class PrivacyReport:
    """Comprehensive privacy evaluation of an image's metadata."""

    overall_risk: RiskLevel
    risk_score: int  # 0 to 100
    items: List[RiskAssessmentItem] = field(default_factory=list)
    summary_narrative: str = ""
    recommendations: List[str] = field(default_factory=list)
    score_components: List[ScoreComponent] = field(default_factory=list)
    score_explanation: str = ""
    category_breakdown: List[CategoryRisk] = field(default_factory=list)
    gps_detected: bool = False
    gps_altitude_detected: bool = False
    gps_location_text_detected: bool = False
    device_identifiers_detected: bool = False
    personal_information_detected: bool = False
    timestamps_detected: bool = False
    thumbnails_detected: bool = False
    mode: str = "standard"

    @property
    def critical_count(self) -> int:
        return sum(1 for item in self.items if item.risk_level == RiskLevel.CRITICAL)

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

    @property
    def sensitive_count(self) -> int:
        return sum(1 for item in self.items if item.is_sensitive)

    @property
    def top_findings(self) -> List[RiskAssessmentItem]:
        return sorted(self.items, key=lambda i: i.risk_level.priority, reverse=True)[:5]


# ----------------------------------------------------------------------
# Rule data
# ----------------------------------------------------------------------
EXPLANATIONS: Dict[str, str] = {
    "gps_coordinates": (
        "Contains precise geographic coordinates where the image was captured. "
        "This can expose a home, workplace, or travel pattern and enables physical "
        "stalking, residence profiling, and pattern-of-life analysis."
    ),
    "gps_other": (
        "Contains supporting location data such as altitude, direction, or GPS "
        "timestamps that can corroborate or refine a location."
    ),
    "contact": (
        "Contains contact details such as an email address, phone number, or postal "
        "address. This directly identifies and allows contacting the person."
    ),
    "author": (
        "Contains a personal name, creator, artist, or owner field that links the "
        "image to an individual and can deanonymise an otherwise anonymous post."
    ),
    "serial": (
        "Contains a hardware serial number or similar unique device identifier. "
        "Serial numbers form a persistent fingerprint that links separate images "
        "to the same physical device and therefore the same owner."
    ),
    "identifier": (
        "Contains a unique document or image identifier. Such identifiers can be "
        "correlated across files, services, and editing sessions."
    ),
    "thumbnail": (
        "Contains an embedded thumbnail or preview image. Previews can retain the "
        "uncropped original scene or content removed from the visible image."
    ),
    "timestamp": (
        "Contains an exact capture or modification timestamp. Timestamps reveal "
        "activity patterns and can be correlated with other records."
    ),
    "device": (
        "Contains camera make, model, lens, firmware, or hosting-computer details. "
        "This helps fingerprint the device and narrow down the user population."
    ),
    "software": (
        "Contains information about the software or editing environment used. "
        "This can reveal workflow, operating environment, or software fingerprints."
    ),
    "comments": (
        "Contains free-text comments, descriptions, keywords, or notes that may "
        "include personal context, internal names, or identifiers."
    ),
    "copyright": (
        "Contains copyright, credit, or usage terms. These often include a person "
        "or organisation name and can be personally identifying."
    ),
    "technical": (
        "Describes exposure and optical settings. Low direct privacy impact, but "
        "unusual combinations can contribute to device fingerprinting."
    ),
    "informational": (
        "Describes image geometry, colour, compression, or container structure. "
        "No direct personal privacy impact."
    ),
    "other": (
        "General metadata tag with no specific personal-identifier rule. Treated "
        "as low risk under the project's threat model."
    ),
}

RECOMMENDATIONS: Dict[str, str] = {
    "gps_coordinates": "Remove GPS metadata before sharing (profile: location or maximum).",
    "gps_other": "Remove GPS metadata to avoid corroborating a location.",
    "contact": "Remove contact information and review the file before any public upload.",
    "author": "Remove author/creator fields if the image should be anonymous.",
    "serial": "Remove device serial numbers; they uniquely identify the hardware.",
    "identifier": "Remove unique document identifiers to prevent cross-file correlation.",
    "thumbnail": "Strip embedded thumbnails and previews; they may show removed content.",
    "timestamp": "Remove timestamps if capture time is sensitive.",
    "device": "Remove camera make/model/lens data to reduce device fingerprinting.",
    "software": "Remove software fields only if the editing environment is sensitive.",
    "comments": "Review and remove free-text comments and descriptions.",
    "copyright": "Keep copyright only if required; otherwise remove ownership names.",
    "technical": "Usually safe to retain; remove with the maximum profile if unsure.",
    "informational": "No action required.",
    "other": "Review manually if the tag name suggests personal context.",
}

# Technical exposure settings: low risk.
_TECHNICAL_TAGS = {
    "exposuretime", "lightsource", "fnumber", "aperture", "iso", "shutterspeed",
    "focallength", "whitebalance", "flash", "meteringmode", "exposureprogram",
    "exposurecompensation", "maxaperturevalue", "scenetype", "scenecapturetype",
    "sensingmethod", "digitalzoomratio", "gaincontrol", "contrast", "saturation",
    "sharpness", "subjectdistance", "subjectarea", "subjectlocation",
    "focalplanexresolution", "focalplaneyresolution", "focalplaneresolutionunit",
    "exposuremode", "customrendered", "brightnessvalue", "exposureindex",
    "recommendedexposureindex", "filesource", "scenecontrol",
    "compositeimagesize", "shutterspeedvalue", "aperturevalue", "lightvalue",
}

# Informational structural tags.
_INFO_TAGS = {
    "imagesize", "imagewidth", "imageheight", "megapixels", "bitspersample",
    "bitdepth", "colorcomponents", "componentsconfiguration", "compression",
    "photometricinterpretation", "samplesperpixel", "planarconfiguration",
    "ycbcrsubsampling", "ycbcrpositioning", "colorspace", "exifversion",
    "flashpixversion", "interopversion", "exifbyteorder", "encodingprocess",
    "jfifversion", "resolutionunit", "xresolution", "yresolution",
    "currentiptcdigest", "orientation", "rotation", "imageformat",
    "applicationrecordversion", "profiledescription", "profilecopyright",
    "profilecreator", "profileclass", "profileversion", "profilecmmsflags",
    "profileconnectionspace", "profilecolorspace", "profilefile",
    "profilehasseequence", "profilehasnamedcolors", "profileisembedded",
    "platform", "mediawhitepoint", "devicemanufacturer",
    "devicemodel", "deviceattributes", "renderingintent",
    "filetype", "filetypeextension", "mimetype", "jpegqualityestimate",
    "jpegdigest", "jpegimagelength", "thumbnaillength", "thumbnailoffset",
    "filename", "directory", "filesize",
}

_CONTACT_TAGS = {
    "contact", "creatorcontactinfo", "copyrightowner", "email", "emailaddress",
    "phone", "phonenumber", "telephone", "address", "postaladdress",
}
_CONTACT_PREFIXES = ("ciadr", "iacontact", "creatorcontact")

_IDENTIFIER_TAGS = {
    "documentid", "instanceid", "originaldocumentid", "versionid", "imageuniqueid",
    "uniqueid", "photoidentifier", "xmpinstanceid", "xmporiginaldocumentid",
}
_IDENTIFIER_SUBSTRINGS = ("uniqueid", "documentid", "instanceid", "originaldocumentid", "versionid")

_SERIAL_SUBSTRINGS = ("serialnumber", "serial", "internalserial", "bodyserial", "lensserial")

# Textual location names that corroborate a GPS fix even without coordinates.
_LOCATION_NAMES = {
    "location", "sublocation", "sub-location", "locationname", "city", "city2",
    "state", "province-state", "country", "countrycode",
    "country-primarylocationcode", "country-primarylocationname",
    "contentlocationcode", "contentlocationname", "geography",
}

_PERSONAL_TAGS = {
    "artist", "creator", "byline", "by-line", "author", "ownername", "captionwriter",
    "credit", "owner", "source",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\w.])(?:\+?\d[\d\s().\-]{7,}\d)(?![\w.])")


def value_looks_like_contact(value: Any) -> bool:
    """Returns True when a free-text value contains an email or phone number."""
    text = str(value or "")
    if _EMAIL_RE.search(text):
        return True
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) >= 9:
            return True
    return False


class BasePrivacyAnalyzer:
    """Interface allowing alternative privacy engines to be plugged in."""

    def analyze(self, metadata: Dict[str, Any]) -> PrivacyReport:
        raise NotImplementedError


class RuleBasedPrivacyAnalyzer(BasePrivacyAnalyzer):
    """Transparent, deterministic rule-based privacy risk evaluator."""

    # Documented additive scoring parameters.
    LEVEL_WEIGHTS: Dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 35,
        RiskLevel.HIGH: 18,
        RiskLevel.MEDIUM: 7,
        RiskLevel.LOW: 2,
        RiskLevel.INFORMATIONAL: 0,
    }
    LEVEL_CAPS: Dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 70,
        RiskLevel.HIGH: 45,
        RiskLevel.MEDIUM: 21,
        RiskLevel.LOW: 6,
        RiskLevel.INFORMATIONAL: 0,
    }

    EXPLANATIONS = EXPLANATIONS
    RECOMMENDATIONS = RECOMMENDATIONS

    def __init__(self, rules: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        # ``rules`` is accepted for backwards compatibility with older callers.
        self.rules = rules

    # ------------------------------------------------------------------
    # Presentation helpers
    # ------------------------------------------------------------------
    def _sanitize_value_preview(self, tag_name: str, value: Any) -> str:
        """Sanitizes a metadata value for terminal/log presentation."""
        val_str = str(value).strip()
        tag_lower = tag_name.lower()

        # Mask any email address embedded in free text (comments, descriptions).
        if _EMAIL_RE.search(val_str):
            val_str = _EMAIL_RE.sub(
                lambda m: f"{m.group(0)[:1]}***@{m.group(0).split('@', 1)[1]}",
                val_str,
            )

        # Mask phone numbers embedded in free text.  A short prefix is kept so
        # the field can still be recognised as a contact value, but the full
        # digits are never exposed.  Ordinary short numeric strings (ISO 100,
        # exposure ratios) are left untouched because they are not phone numbers.
        if _PHONE_RE.search(val_str):
            def _mask_phone(match: "re.Match[str]") -> str:
                candidate = match.group(0)
                digits = re.sub(r"\D", "", candidate)
                if len(digits) < 9:
                    return candidate
                return candidate[:3] + "***" + candidate[-2:]
            val_str = _PHONE_RE.sub(_mask_phone, val_str)

        if "serial" in tag_lower and len(val_str) > 8:
            return f"{val_str[:3]}****{val_str[-3:]}"

        if "contact" in tag_lower and len(val_str) > 12:
            return val_str[:4] + "***"

        if len(val_str) > 80:
            return f"{val_str[:77]}..."

        return val_str

    def _item(
        self,
        tag_name: str,
        value: Any,
        level: RiskLevel,
        category: str,
        explanation_key: str,
        group: Optional[str] = None,
        tag_key: str = "",
        extra_note: str = "",
    ) -> RiskAssessmentItem:
        explanation = EXPLANATIONS[explanation_key]
        if extra_note:
            explanation = f"{explanation} {extra_note}"
        return RiskAssessmentItem(
            tag_name=tag_name,
            category=category,
            risk_level=level,
            value_preview=self._sanitize_value_preview(tag_name, value),
            explanation=explanation,
            group=group,
            recommendation=RECOMMENDATIONS[explanation_key],
            tag_key=tag_key or (f"{group}:{tag_name}" if group else tag_name),
        )

    # ------------------------------------------------------------------
    # Core tag assessment
    # ------------------------------------------------------------------
    def evaluate_tag(
        self,
        tag_name: str,
        value: Any,
        group: Optional[str] = None,
        category: Optional[str] = None,
    ) -> RiskAssessmentItem:
        """Assesses the privacy risk of a single metadata tag."""
        tag_lower = tag_name.lower().replace(" ", "")
        group_lower = (group or "").lower()
        value_is_empty = value is None or str(value).strip() == ""

        # ICC profiles are colour management, not personal metadata.
        if "icc" in group_lower:
            return self._item(tag_name, value, RiskLevel.INFORMATIONAL, "informational", "informational", group)

        # MakerNotes: serials/lenses are identifying, other entries are device state.
        if "makernote" in group_lower:
            if any(k in tag_lower for k in _SERIAL_SUBSTRINGS):
                return self._item(tag_name, value, RiskLevel.HIGH, "device", "serial", group)
            if value_is_empty:
                return self._item(tag_name, value, RiskLevel.INFORMATIONAL, "informational", "informational", group)
            return self._item(tag_name, value, RiskLevel.LOW, "makernotes", "technical", group)

        # GPS: coordinates are critical, supporting location fields are sensitive.
        if (
            category == "gps"
            or group_lower == "gps"
            or tag_lower.startswith("gps")
            or any(k in tag_lower for k in ("latitude", "longitude", "gpsposition"))
            or (tag_lower in _LOCATION_NAMES and "creator" not in tag_lower)
        ):
            if "ref" in tag_lower:
                return self._item(tag_name, value, RiskLevel.INFORMATIONAL, "gps", "informational", group)
            if any(k in tag_lower for k in ("latitude", "longitude", "position")):
                return self._item(tag_name, value, RiskLevel.CRITICAL, "gps", "gps_coordinates", group)
            if "altitude" in tag_lower:
                return self._item(tag_name, value, RiskLevel.HIGH, "gps", "gps_other", group)
            if any(k in tag_lower for k in ("datestamp", "timestamp", "time")):
                return self._item(tag_name, value, RiskLevel.MEDIUM, "gps", "gps_other", group)
            return self._item(tag_name, value, RiskLevel.LOW, "gps", "gps_other", group)

        # Software fields must be matched before the generic "creator" rule.
        if tag_lower in {
            "software", "creatortool", "processingsoftware", "xmptoolkit",
            "historysoftwareagent", "previewapplication",
        }:
            return self._item(tag_name, value, RiskLevel.LOW, "software", "software", group)

        # Contact details are direct identifiers.
        if tag_lower in _CONTACT_TAGS or any(tag_lower.startswith(p) for p in _CONTACT_PREFIXES):
            return self._item(tag_name, value, RiskLevel.CRITICAL, "author", "contact", group)

        # Free-text values containing an email/phone escalate to critical.
        if (
            any(k in tag_lower for k in ("comment", "description", "caption", "note", "headline", "keywords", "subject"))
            and not value_is_empty
            and value_looks_like_contact(value)
        ):
            return self._item(
                tag_name, value, RiskLevel.CRITICAL, "comments", "contact", group,
                extra_note="The free-text value appears to contain an email address or phone number.",
            )

        # Serial numbers / unique identifiers.
        if any(k in tag_lower for k in _SERIAL_SUBSTRINGS):
            return self._item(tag_name, value, RiskLevel.HIGH, "device", "serial", group)
        if tag_lower in _IDENTIFIER_TAGS or any(k in tag_lower for k in _IDENTIFIER_SUBSTRINGS):
            return self._item(tag_name, value, RiskLevel.HIGH, "identifiers", "identifier", group)

        # Thumbnails / previews.
        if tag_lower in {"thumbnailimage", "previewimage", "otherimage", "jpgfromraw", "previewtiff", "previewpdf"}:
            return self._item(tag_name, value, RiskLevel.HIGH, "thumbnail", "thumbnail", group)
        if "thumbnail" in tag_lower:
            return self._item(tag_name, value, RiskLevel.INFORMATIONAL, "informational", "informational", group)

        # Personal names and creator fields.
        if tag_lower in _PERSONAL_TAGS or any(
            k in tag_lower for k in ("artist", "creator", "by-line", "byline", "author", "ownername", "creatorcontactinfo")
        ):
            return self._item(tag_name, value, RiskLevel.HIGH, "author", "author", group)

        # Copyright / rights.
        if any(k in tag_lower for k in ("copyright", "rights", "usageterms", "webstatement")):
            return self._item(tag_name, value, RiskLevel.MEDIUM, "copyright", "copyright", group)

        # Informational and technical tags (checked before broad keyword matches).
        if tag_lower in _INFO_TAGS or tag_lower.startswith("profile"):
            return self._item(tag_name, value, RiskLevel.INFORMATIONAL, "informational", "informational", group)
        if tag_lower in _TECHNICAL_TAGS:
            return self._item(tag_name, value, RiskLevel.LOW, "technical", "technical", group)

        # Comments / descriptions / keywords.
        if any(k in tag_lower for k in ("comment", "description", "note", "headline", "caption", "xpcomment", "keywords", "subject")):
            return self._item(tag_name, value, RiskLevel.MEDIUM, "comments", "comments", group)

        # Timestamps.
        if any(
            k in tag_lower
            for k in ("datetime", "createdate", "modifydate", "timestamp", "subsectime",
                      "offsettime", "historywhen", "digitalcreation", "datecreated", "datemodified")
        ):
            return self._item(tag_name, value, RiskLevel.MEDIUM, "date", "timestamp", group)

        # Device identity.
        if any(k in tag_lower for k in ("make", "model", "lens", "firmware", "device", "hostcomputer")):
            return self._item(tag_name, value, RiskLevel.MEDIUM, "device", "device", group)

        return self._item(tag_name, value, RiskLevel.LOW, "other", "other", group)

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------
    def _score(self, items: List[RiskAssessmentItem]) -> tuple[int, List[ScoreComponent]]:
        components: List[ScoreComponent] = []
        total = 0
        for level in (
            RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
            RiskLevel.LOW, RiskLevel.INFORMATIONAL,
        ):
            count = sum(1 for i in items if i.risk_level == level)
            weight = self.LEVEL_WEIGHTS[level]
            cap = self.LEVEL_CAPS[level]
            raw = count * weight
            contribution = min(raw, cap)
            total += contribution
            components.append(
                ScoreComponent(
                    level=level.label,
                    count=count,
                    weight_per_tag=weight,
                    raw_contribution=raw,
                    capped_contribution=contribution,
                )
            )
        return min(100, total), components

    def _category_breakdown(self, items: List[RiskAssessmentItem]) -> List[CategoryRisk]:
        buckets: Dict[str, List[RiskAssessmentItem]] = {}
        for item in items:
            buckets.setdefault(item.category, []).append(item)

        breakdown: List[CategoryRisk] = []
        for category, cat_items in buckets.items():
            max_level = max((i.risk_level for i in cat_items), key=lambda l: l.priority)
            contribution = sum(self.LEVEL_WEIGHTS[i.risk_level] for i in cat_items)
            breakdown.append(
                CategoryRisk(
                    category=category,
                    count=len(cat_items),
                    max_level=max_level,
                    contribution=min(100, contribution),
                    examples=[i.tag_name for i in cat_items[:5]],
                )
            )
        breakdown.sort(key=lambda c: (-c.max_level.priority, -c.count))
        return breakdown

    def _narrative(
        self,
        items: List[RiskAssessmentItem],
        overall: RiskLevel,
        gps: bool,
        device_ids: bool,
        personal: bool,
        timestamps: bool,
        thumbnails: bool,
    ) -> str:
        if not items:
            return "No embedded metadata was detected by the available inspection backend."
        lead = {
            RiskLevel.CRITICAL: "CRITICAL PRIVACY EXPOSURE",
            RiskLevel.HIGH: "HIGH PRIVACY RISK",
            RiskLevel.MEDIUM: "MODERATE PRIVACY RISK",
            RiskLevel.LOW: "LOW PRIVACY RISK",
            RiskLevel.INFORMATIONAL: "INFORMATIONAL ONLY",
        }[overall]
        parts: List[str] = [f"{lead}: {len(items)} metadata tags assessed."]
        if gps:
            parts.append(
                "Precise GPS coordinates are present; publishing this file can reveal where it was taken."
            )
        if personal:
            parts.append("Personally identifying author/creator or contact fields are present.")
        if device_ids:
            parts.append("Device serial or unique identifier fields are present and can link photos to one device.")
        if timestamps:
            parts.append("Capture timestamps are present and can reveal activity patterns.")
        if thumbnails:
            parts.append("Embedded thumbnails/previews are present and may retain removed content.")
        if overall in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
            parts.append("Sanitize the file before sharing it publicly.")
        return " ".join(parts)

    def analyze_tags(self, tags: Iterable[Any], mode: str = "standard") -> PrivacyReport:
        """Analyzes scanner tag objects and produces a PrivacyReport."""
        items: List[RiskAssessmentItem] = []
        for tag in tags:
            if tag_is_derived(tag):
                continue  # Composite values duplicate real tags
            name = tag_name_of(tag)
            group = tag_group(tag)
            value = tag_value_of(tag)
            if getattr(tag, "extraction_status", "extracted") == "empty":
                continue  # present-but-empty is not an exposure
            item = self.evaluate_tag(
                name, value, group=group, category=getattr(tag, "category", None)
            )
            item.tag_key = getattr(tag, "key", item.tag_key) or item.tag_key
            items.append(item)

        if not items:
            return PrivacyReport(
                overall_risk=RiskLevel.INFORMATIONAL,
                risk_score=0,
                items=[],
                summary_narrative=self._narrative([], RiskLevel.INFORMATIONAL, False, False, False, False, False),
                recommendations=["No metadata sanitization is required based on this scan."],
                score_components=self._score([])[1],
                score_explanation=self._score_explanation([]),
                mode=mode,
            )

        overall = max((i.risk_level for i in items), key=lambda l: l.priority)
        score, components = self._score(items)

        gps = any(i.category == "gps" for i in items)
        # Altitude and textual location fields corroborate a GPS fix even when
        # the latitude/longitude pair is absent, so they get their own flag.
        gps_altitude = any(
            "altitude" in i.tag_name.lower()
            for i in items
        )
        gps_location_text = any(
            i.tag_name.lower() in _LOCATION_NAMES for i in items
        )
        # Personal information covers author/creator identity *and* direct
        # contact details (e-mail, phone, postal address), including contact
        # data that surfaced inside a free-text comment field.
        personal = any(
            i.category == "author"
            or (i.risk_level == RiskLevel.CRITICAL and "contact" in i.explanation.lower())
            for i in items
        )
        device_ids = any(
            i.category in ("device", "identifiers") and i.risk_level.priority >= RiskLevel.HIGH.priority
            for i in items
        )
        timestamps = any(i.category == "date" for i in items)
        thumbnails = any(i.category == "thumbnail" for i in items)

        recommendations: List[str] = []
        for cat in ("gps", "author", "device", "identifiers", "thumbnail", "date", "comments", "copyright", "software"):
            if any(i.category == cat for i in items):
                first = next(i for i in items if i.category == cat)
                if first.recommendation not in recommendations:
                    recommendations.append(first.recommendation)
        if overall.priority >= RiskLevel.HIGH.priority:
            recommendations.append(
                "Use `clean --profile maximum` for full metadata removal, then verify the output independently."
            )
        recommendations.append(
            "Treat scores as a heuristic guide, not a guarantee; verify the cleaned file before publishing."
        )

        return PrivacyReport(
            overall_risk=overall,
            risk_score=score,
            items=items,
            summary_narrative=self._narrative(
                items, overall, gps, device_ids, personal, timestamps, thumbnails
            ),
            recommendations=recommendations,
            score_components=components,
            score_explanation=self._score_explanation(components),
            category_breakdown=self._category_breakdown(items),
            gps_detected=gps,
            gps_altitude_detected=gps_altitude,
            gps_location_text_detected=gps_location_text,
            device_identifiers_detected=device_ids,
            personal_information_detected=personal,
            timestamps_detected=timestamps,
            thumbnails_detected=thumbnails,
            mode=mode,
        )

    def _score_explanation(self, components: List[ScoreComponent]) -> str:
        parts = []
        for comp in components:
            if comp.count:
                parts.append(
                    f"{comp.count} x {comp.level} x {comp.weight_per_tag} = {comp.raw_contribution} "
                    f"(capped at {comp.capped_contribution})"
                )
        formula = " + ".join(parts) if parts else "no scored tags"
        return (
            f"Heuristic score = min(100, {formula}). "
            "Weights and category caps are fixed constants in privacy_analyzer.py; "
            "the score is an explanatory heuristic, not a validated security metric."
        )

    def analyze(self, metadata: Dict[str, Any]) -> PrivacyReport:
        """Backwards-compatible analysis of a ``{group:tag: value}`` mapping."""
        items: List[RiskAssessmentItem] = []
        for full_key, value in metadata.items():
            if ":" in full_key:
                group, tag_name = full_key.split(":", 1)
            else:
                group, tag_name = None, full_key
            if group == "Composite":
                continue
            if group in ("System", "File", "ExifTool"):
                continue
            items.append(self.evaluate_tag(tag_name, value, group=group))

        overall = max((i.risk_level for i in items), key=lambda l: l.priority) if items else RiskLevel.INFORMATIONAL
        score, components = self._score(items)
        return PrivacyReport(
            overall_risk=overall,
            risk_score=score,
            items=items,
            summary_narrative=self._narrative(
                items,
                overall,
                any(i.category == "gps" for i in items),
                any(i.category in ("device", "identifiers") and i.risk_level.priority >= 4 for i in items),
                any(
                    i.category == "author"
                    or (i.risk_level == RiskLevel.CRITICAL and "contact" in i.explanation.lower())
                    for i in items
                ),
                any(i.category == "date" for i in items),
                any(i.category == "thumbnail" for i in items),
            ),
            recommendations=[],
            score_components=components,
            score_explanation=self._score_explanation(components),
            category_breakdown=self._category_breakdown(items),
            gps_detected=any(i.category == "gps" for i in items),
            gps_altitude_detected=any("altitude" in i.tag_name.lower() for i in items),
            gps_location_text_detected=any(i.tag_name.lower() in _LOCATION_NAMES for i in items),
            device_identifiers_detected=any(i.category in ("device", "identifiers") for i in items),
            personal_information_detected=any(i.category == "author" for i in items),
            timestamps_detected=any(i.category == "date" for i in items),
            thumbnails_detected=any(i.category == "thumbnail" for i in items),
        )
