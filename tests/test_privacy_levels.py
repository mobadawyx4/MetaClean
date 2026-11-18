"""Tests for the five-level privacy taxonomy, scoring and PII handling."""

from __future__ import annotations

from modules.metadata_scanner import MetadataTag
from modules.privacy_analyzer import (
    PrivacyReport,
    RiskLevel,
    RuleBasedPrivacyAnalyzer,
    value_looks_like_contact,
)


def test_five_levels_are_ordered() -> None:
    levels = [
        RiskLevel.INFORMATIONAL,
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ]
    priorities = [level.priority for level in levels]
    assert priorities == sorted(priorities)
    assert len(set(priorities)) == 5


def test_tag_classification_matrix() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    cases = [
        ("GPSLatitude", "37.7749", "GPS", RiskLevel.CRITICAL),
        ("GPSLongitudeRef", "W", "GPS", RiskLevel.INFORMATIONAL),
        ("GPSAltitude", "15 m", "GPS", RiskLevel.HIGH),
        ("EmailAddress", "alice@example.com", "IPTC", RiskLevel.CRITICAL),
        ("CreatorContactInfo", "Alice", "XMP-dc", RiskLevel.CRITICAL),
        ("SerialNumber", "SN12345678", "ExifIFD", RiskLevel.HIGH),
        ("DocumentID", "uuid-1234", "XMP-xmpMM", RiskLevel.HIGH),
        ("ThumbnailImage", "(binary)", "IFD1", RiskLevel.HIGH),
        ("Artist", "Alice", "IFD0", RiskLevel.HIGH),
        ("Copyright", "2026 Alice", "IFD0", RiskLevel.MEDIUM),
        ("Software", "GIMP 2.10", "IFD0", RiskLevel.LOW),
        ("ISO", 100, "ExifIFD", RiskLevel.LOW),
        ("ExposureTime", "1/250", "ExifIFD", RiskLevel.LOW),
        ("ImageWidth", 1920, "File", RiskLevel.INFORMATIONAL),
        ("ProfileDescription", "sRGB", "ICC_Profile", RiskLevel.INFORMATIONAL),
        ("SomeVendorField", "value", "MakerNotes", RiskLevel.LOW),
        ("UnmappedField", "value", "Other", RiskLevel.LOW),
    ]
    for tag_name, value, group, expected in cases:
        item = analyzer.evaluate_tag(tag_name, value, group=group)
        assert item.risk_level == expected, f"{group}:{tag_name} -> {item.risk_level}"


def test_comment_with_email_escalates_and_is_masked() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    item = analyzer.evaluate_tag(
        "ImageDescription", "Contact me at alice@example.com for licensing", group="IFD0"
    )
    assert item.risk_level == RiskLevel.CRITICAL
    assert "alice@example.com" not in item.value_preview
    assert "a***@example.com" in item.value_preview


def test_contact_detection_helper() -> None:
    assert value_looks_like_contact("reach me: bob@corp.example")
    assert value_looks_like_contact("call +1 (555) 123-4567")
    assert not value_looks_like_contact("a plain description with no contact data")
    # Short numeric strings must not be mistaken for phone numbers.
    assert not value_looks_like_contact("ISO 100")


def test_serial_and_contact_previews_are_masked() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    serial = analyzer.evaluate_tag("SerialNumber", "SN1234567890", group="ExifIFD")
    assert "****" in serial.value_preview
    contact = analyzer.evaluate_tag("Contact", "alice@example.com", group="IPTC")
    assert "alice@example.com" not in contact.value_preview


def _tag(group: str, name: str, value: object, category: str) -> MetadataTag:
    return MetadataTag(
        name=name, value=value, group=group, category=category, key=f"{group}:{name}"
    )


def test_analyze_tags_aggregates_and_ignores_derived() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    tags = [
        _tag("GPS", "GPSLatitude", "37.7749", "gps"),
        _tag("GPS", "GPSLongitude", "-122.4194", "gps"),
        _tag("IFD0", "Artist", "Alice", "author"),
        _tag("ExifIFD", "ISO", 100, "exif"),
        _tag("Composite", "GPSPosition", "37.7749 -122.4194", "gps"),
    ]
    tags[-1].derived = True

    report = analyzer.analyze_tags(tags)
    assert isinstance(report, PrivacyReport)
    assert report.overall_risk == RiskLevel.CRITICAL
    assert 0 <= report.risk_score <= 100
    assert report.critical_count == 2
    assert report.items, "derived tags must not eliminate real findings"
    assert all(item.tag_name != "GPSPosition" for item in report.items)
    assert report.gps_detected is True
    assert report.personal_information_detected is True
    assert sum(comp.count for comp in report.score_components) == len(report.items)
    assert "heuristic" in report.score_explanation.lower()
    assert report.category_breakdown
    assert report.recommendations


def test_empty_tags_report_is_informational() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    report = analyzer.analyze_tags([])
    assert report.overall_risk == RiskLevel.INFORMATIONAL
    assert report.risk_score == 0
    assert report.sensitive_count == 0
    assert "no embedded metadata" in report.summary_narrative.lower()


def test_empty_values_are_not_exposures() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    empty = _tag("IFD0", "Artist", "", "author")
    report = analyzer.analyze_tags([empty])
    assert report.overall_risk == RiskLevel.INFORMATIONAL
    assert report.sensitive_count == 0


def test_critical_contribution_is_capped() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    tags = [
        _tag("GPS", f"GPSLatitude{i}", "1.0", "gps")
        for i in range(20)
    ]
    report = analyzer.analyze_tags(tags)
    assert report.risk_score == analyzer.LEVEL_CAPS[RiskLevel.CRITICAL] == 70
    assert 0 <= report.risk_score <= 100
    assert report.overall_risk == RiskLevel.CRITICAL
    critical_component = next(
        c for c in report.score_components if c.level == RiskLevel.CRITICAL.label
    )
    assert critical_component.raw_contribution == 700
    assert critical_component.capped_contribution == 70


def test_legacy_analyze_skips_system_groups() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    report = analyzer.analyze(
        {
            "System:FileName": "photo.jpg",
            "File:FileSize": "1234",
            "ExifTool:ExifToolVersion": "12.76",
            "IFD0:Artist": "Alice",
        }
    )
    assert len(report.items) == 1
    assert report.items[0].tag_name == "Artist"
    assert report.overall_risk == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# F-12: phone numbers must be masked in free-text previews
# ---------------------------------------------------------------------------
def test_phone_in_free_text_is_masked() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    item = analyzer.evaluate_tag(
        "ImageDescription", "Call me at +1 (555) 123-4567 for details", group="IFD0"
    )
    assert item.risk_level == RiskLevel.CRITICAL
    preview = item.value_preview
    assert "+1 (555) 123-4567" not in preview
    assert "555" not in preview
    assert "***" in preview
    assert preview.startswith("Call me at")


def test_phone_in_contact_tag_is_masked() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    item = analyzer.evaluate_tag("Contact", "+44 20 7946 0958", group="IPTC")
    assert item.risk_level == RiskLevel.CRITICAL
    assert "+44 20 7946 0958" not in item.value_preview
    assert "***" in item.value_preview


def test_plain_numbers_are_not_masked_as_phones() -> None:
    """ISO, exposure and other short numeric strings must survive unchanged."""
    analyzer = RuleBasedPrivacyAnalyzer()
    for value in ("ISO 100", "1/250", "2.8", "50 mm", "Baseline DCT, Huffman coding"):
        item = analyzer.evaluate_tag("ISO", value, group="ExifIFD")
        assert value in item.value_preview, f"{value!r} was wrongly masked: {item.value_preview!r}"


def test_email_and_phone_coexist_in_one_preview() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    item = analyzer.evaluate_tag(
        "UserComment",
        "Email alice@example.com or call +1 555 010 9999",
        group="IFD0",
    )
    assert "alice@example.com" not in item.value_preview
    assert "+1 555 010 9999" not in item.value_preview
    assert "***@example.com" in item.value_preview
    assert "***" in item.value_preview


# ---------------------------------------------------------------------------
# F-13: personal_information_detected reflects contact data, not just names
# ---------------------------------------------------------------------------
def _tag(group: str, name: str, value: object, category: str) -> MetadataTag:
    return MetadataTag(
        name=name, value=value, group=group, category=category, key=f"{group}:{name}"
    )


def test_personal_information_detected_for_phone_only() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("IFD0", "ImageDescription", "call +1 (555) 123-4567", "comments"),
    ])
    assert report.personal_information_detected is True


def test_personal_information_detected_for_email_only() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("IFD0", "ImageDescription", "reach alice@example.com", "comments"),
    ])
    assert report.personal_information_detected is True


def test_personal_information_detected_for_postal_address() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("IPTC", "Contact", "1600 Amphitheatre Parkway, Mountain View", "author"),
    ])
    assert report.personal_information_detected is True


def test_personal_information_not_detected_when_absent() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("ExifIFD", "ISO", 100, "exif"),
        _tag("IFD0", "Software", "Editor 1.0", "software"),
        _tag("File", "FileType", "JPEG", "informational"),
    ])
    assert report.personal_information_detected is False
    assert report.gps_detected is False
    assert report.device_identifiers_detected is False
    assert report.timestamps_detected is False
    assert report.thumbnails_detected is False


# ---------------------------------------------------------------------------
# F-14: GPS altitude and textual location privacy indicators
# ---------------------------------------------------------------------------
def test_gps_altitude_detected_flag() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("GPS", "GPSAltitude", "15 m", "gps"),
    ])
    assert report.gps_detected is True
    assert report.gps_altitude_detected is True


def test_gps_location_text_detected_flag() -> None:
    """Textual location fields are classified as gps by the scanner, so the
    privacy report must expose a dedicated gps_location_text_detected flag."""
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("IPTC", "City", "Springfield", "gps"),
    ])
    assert report.gps_detected is True
    assert report.gps_location_text_detected is True
    assert report.gps_altitude_detected is False


def test_gps_latitude_only_flags() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("GPS", "GPSLatitude", "37.7749", "gps"),
    ])
    assert report.gps_detected is True
    assert report.gps_altitude_detected is False
    assert report.gps_location_text_detected is False


def test_legacy_analyze_gps_flags() -> None:
    analyzer = RuleBasedPrivacyAnalyzer()
    report = analyzer.analyze({
        "GPS:GPSAltitude": "100 m",
        "IPTC:City": "Springfield",
    })
    assert report.gps_detected is True
    assert report.gps_altitude_detected is True
    assert report.gps_location_text_detected is True


def test_gps_flags_absent_without_location() -> None:
    report = RuleBasedPrivacyAnalyzer().analyze_tags([
        _tag("ExifIFD", "ISO", 100, "exif"),
    ])
    assert report.gps_detected is False
    assert report.gps_altitude_detected is False
    assert report.gps_location_text_detected is False
