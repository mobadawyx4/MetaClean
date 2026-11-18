"""Category-coverage tests for selective metadata detection and removal (F-04/F-05/F-11).

These tests tie the three representations of a metadata category together:

1. ``config.METADATA_CATEGORIES[category]["tags"]`` - the documented contract of
   which tag names a category is expected to cover.
2. ``MetadataScanner._classify_tag`` - the detector that assigns a scanned tag to
   a category.
3. ``config.METADATA_CATEGORIES[category]["exiftool_args"]`` - the arguments the
   remover actually passes to ExifTool.

The category definitions used to drift apart: tags were documented in one
category but classified into another, and some arguments named tags ExifTool
does not accept (``PreviewApplication``, ``PreviewTIFF``, ``PreviewPDF``) or
misclassified tags (``StateOrProvince``).  The tests below make that class of
bug fail loudly.

Group names used here are the first-level groups ExifTool emits with ``-G1``
(``IFD0``, ``ExifIFD``, ``GPS``, ``IPTC``, ``XMP-dc``, ...).
"""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import config
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationOutcome

pytestmark = pytest.mark.skipif(
    not config.EXIFTOOL_AVAILABLE,
    reason="Category detection/removal is implemented for the ExifTool path.",
)

# Categories exercised against the synthetic fixture.  ``exif``/``iptc``/``xmp``
# are container blocks rather than privacy themes and are covered by ``maximum``.
TARGETED_CATEGORIES = (
    "gps",
    "date",
    "device",
    "author",
    "copyright",
    "comments",
    "software",
    "identifiers",
    "thumbnail",
)

# A control category that must survive each selective clean.  Chosen so no
# documented overlap can legitimately remove it.
CONTROL_CATEGORY = {
    "gps": "author",
    "date": "comments",
    "device": "author",
    "author": "date",
    "copyright": "device",
    "comments": "gps",
    "software": "comments",
    "identifiers": "gps",
    "thumbnail": "gps",
}

# Groups that can legitimately carry each documented tag.  The classifier is
# name-driven for these tags, so classification must not depend on the group.
REPRESENTATIVE_GROUPS = (
    "IFD0",
    "ExifIFD",
    "IPTC",
    "XMP-dc",
    "XMP-exif",
    "XMP-iptcCore",
    "XMP-photoshop",
    "XMP-xmp",
    "XMP-xmpMM",
    "XMP-exifEX",
    "XMP-xmpRights",
)

# Documented intentional overlap: these device-category tags describe the
# editing software that touched the file, so the classifier files them under
# ``software`` while the removal args still cover them via ``-*Software*``.
ALLOWED_CATEGORY_ALIASES = {
    ("device", "Software"): "software",
    ("device", "ProcessingSoftware"): "software",
}

_INVALID_ARG_MARKERS = (
    "is not defined",
    "not writable",
    "doesn't exist",
    "isn't writable",
)


def _documented_tags(category: str) -> list[str]:
    definition = config.METADATA_CATEGORIES[category]
    return [str(tag) for tag in definition.get("tags", [])]  # type: ignore[union-attr]


def _removal_args(category: str) -> list[str]:
    definition = config.METADATA_CATEGORIES[category]
    return [str(arg) for arg in definition.get("exiftool_args", [])]  # type: ignore[union-attr]


def _exiftool_writable_tags() -> list[tuple[str, str]]:
    """Returns ``(group, tag)`` for every writable tag ExifTool knows."""
    result = subprocess.run(
        ["exiftool", "-listx", "-s"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    root = ET.fromstring(result.stdout)
    tags: list[tuple[str, str]] = []
    for table in root.iter("table"):
        group = table.get("g1") or table.get("g0") or ""
        for tag in table.iter("tag"):
            if tag.get("writable") == "true":
                tags.append((group, tag.get("name", "")))
    return tags


def _argument_matches_tag(argument: str, group: str, tag: str) -> bool:
    """Approximates ExifTool's unqualified/group-qualified deletion matching."""
    spec = argument[1:] if argument.startswith("-") else argument
    if spec.endswith("="):
        spec = spec[:-1]
    if not spec:
        return False
    if ":" in spec:
        argument_group, pattern = spec.split(":", 1)
        if argument_group.lower() != group.lower():
            return False
        if pattern.lower() == "all":
            return True
    else:
        pattern = spec
    return fnmatch.fnmatch(tag.lower(), pattern.lower())


# ---------------------------------------------------------------------------
# Contract: documented tags, detector, and removal arguments agree
# ---------------------------------------------------------------------------
def test_every_documented_tag_is_classified_into_its_category() -> None:
    """Every tag a category claims must be detected as that category.

    This is the core property that was broken before the audit: for example
    ``StateOrProvince`` was documented as a location tag but classified as
    ``xmp``, and ``OwnerName`` was documented as an author tag but could fall
    through to a container fallback.
    """
    scanner = MetadataScanner()
    mismatches: list[str] = []

    for category in config.METADATA_CATEGORIES:
        if category == "all":
            continue
        for tag in _documented_tags(category):
            if "*" in tag:
                # Wildcard contracts (``*EXIF*``) describe whole blocks.
                continue
            expected = ALLOWED_CATEGORY_ALIASES.get((category, tag), category)
            observed = {
                scanner._classify_tag(group, tag)[0] for group in REPRESENTATIVE_GROUPS
            }
            if observed != {expected}:
                mismatches.append(
                    f"{category}:{tag} expected {expected}, classified as {sorted(observed)}"
                )

    assert not mismatches, "Category/tag/classifier drift:\n" + "\n".join(mismatches)


def test_every_writable_exiftool_tag_is_covered_by_its_category_arguments() -> None:
    """Every writable tag the classifier targets must match that category's args.

    This is broader than the documented-tag test: it walks ExifTool's own tag
    database (``-listx``), derives the category with the real classifier, and
    checks the category's wildcard/qualified arguments against the tag.  A new
    ExifTool release that introduces a tag such as ``Canon:TimeStamp`` therefore
    fails here until the category arguments cover it.
    """
    scanner = MetadataScanner()
    uncovered: list[str] = []

    for group, tag in _exiftool_writable_tags():
        category, _ = scanner._classify_tag(group, tag)
        if category not in TARGETED_CATEGORIES:
            continue
        arguments = _removal_args(category)
        if not any(_argument_matches_tag(arg, group, tag) for arg in arguments):
            uncovered.append(f"{category}: {group}:{tag}")

    assert not uncovered, (
        f"{len(uncovered)} writable tags are detected but not covered by their "
        "category's removal arguments:\n" + "\n".join(sorted(uncovered)[:80])
    )


def test_category_overlaps_are_only_the_documented_ones() -> None:
    """A tag may appear in several categories only when the overlap is documented."""
    owners: dict[str, set[str]] = {}
    for category in config.METADATA_CATEGORIES:
        if category == "all":
            continue
        for tag in _documented_tags(category):
            if "*" in tag:
                continue
            owners.setdefault(tag, set()).add(category)

    allowed_pairs = {
        frozenset({source, target})
        for (source, _tag), target in ALLOWED_CATEGORY_ALIASES.items()
    }
    undocumented = [
        f"{tag}: {sorted(categories)}"
        for tag, categories in owners.items()
        if len(categories) > 1 and frozenset(categories) not in allowed_pairs
    ]

    assert not undocumented, "Undocumented category overlap:\n" + "\n".join(undocumented)


def test_every_targeted_category_defines_detection_and_removal_contracts() -> None:
    for category in TARGETED_CATEGORIES:
        assert category in config.METADATA_CATEGORIES
        assert _documented_tags(category), f"{category} documents no tags"
        assert _removal_args(category), f"{category} defines no removal arguments"


def test_software_tags_are_the_documented_device_alias() -> None:
    """Guard the one intentional overlap so it cannot spread silently."""
    scanner = MetadataScanner()

    assert scanner._classify_tag("IFD0", "Software")[0] == "software"
    assert scanner._classify_tag("ExifIFD", "ProcessingSoftware")[0] == "software"
    # The removal contract still covers them because it uses ``-*Software*``.
    assert any("Software" in arg for arg in _removal_args("device"))


# ---------------------------------------------------------------------------
# Structural metadata must never be treated as removable privacy metadata
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "tag",
    [
        "Orientation",
        "ColorSpace",
        "ExifVersion",
        "FlashpixVersion",
        "InteropVersion",
        "ComponentsConfiguration",
        "SubjectLocation",
        "SubjectArea",
        "SubjectDistance",
        "SubjectDistanceRange",
    ],
)
def test_structural_and_composition_tags_are_informational(tag: str) -> None:
    assert MetadataScanner()._classify_tag("ExifIFD", tag)[0] == "informational"


def test_structural_allowlist_does_not_intersect_removal_categories() -> None:
    removable = set(TARGETED_CATEGORIES) | {"makernotes"}
    conflicting = {
        tag
        for tag in config.STRUCTURAL_TAG_ALLOWLIST
        if any(tag in _documented_tags(category) for category in removable)
    }
    assert not conflicting, f"Structural allowlist also targeted for removal: {sorted(conflicting)}"


@pytest.mark.parametrize(
    ("group", "tag_name"),
    [
        ("IFD0", "Orientation"),
        ("ExifIFD", "ColorSpace"),
        ("ExifIFD", "ExifVersion"),
        ("File", "ImageWidth"),
        ("File", "MIMEType"),
        ("JFIF", "JFIFVersion"),
        ("PNG", "BitDepth"),
        ("PNG", "Filter"),
        ("RIFF", "VP8Version"),
        ("Composite", "ImageSize"),
        ("Composite", "Megapixels"),
        ("ICC_Profile", "ProfileDescription"),
    ],
)
def test_is_structural_tag_positive_legitimate_tags(group: str, tag_name: str) -> None:
    """Legitimate container, encoding, and decoder geometry tags are structural."""
    assert config.is_structural_tag(group, tag_name) is True


@pytest.mark.parametrize(
    ("group", "tag_name"),
    [
        ("IPTC", "Orientation"),
        ("XMP", "Compression"),
        ("XMP-dc", "Compression"),
        ("GPS", "ResolutionUnit"),
        ("MakerNotes", "ColorSpace"),
        ("CustomGroup", "ImageWidth"),
        ("File", "Comment"),
        ("PNG", "Description"),
        ("PNG", "Author"),
        ("", "Orientation"),
        ("IFD0", ""),
        ("", ""),
    ],
)
def test_is_structural_tag_negative_unrelated_groups(group: str, tag_name: str) -> None:
    """Structural tag names in unrelated or custom metadata groups must be rejected."""
    assert config.is_structural_tag(group, tag_name) is False


@pytest.mark.parametrize(
    ("category", "group", "tag_name"),
    [
        # GPS
        ("gps", "GPS", "GPSLatitude"),
        ("gps", "GPS", "GPSLongitude"),
        ("gps", "Composite", "GPSPosition"),
        ("gps", "IFD0", "GPSInfo"),
        ("gps", "ICC_Profile", "GPSLatitude"),
        # Author
        ("author", "IFD0", "Artist"),
        ("author", "IPTC", "By-line"),
        ("author", "PNG", "Author"),
        ("author", "ICC_Profile", "ProfileCreator"),
        # Date
        ("date", "ExifIFD", "DateTimeOriginal"),
        ("date", "IFD0", "ModifyDate"),
        ("date", "PNG", "CreationTime"),
        ("date", "ICC_Profile", "ProfileDateTime"),
        # Software
        ("software", "IFD0", "Software"),
        ("software", "PNG", "Software"),
        ("software", "ICC_Profile", "Software"),
        # Identifiers
        ("identifiers", "ExifIFD", "SerialNumber"),
        ("identifiers", "IFD0", "ImageUniqueID"),
        ("identifiers", "ICC_Profile", "DeviceSerial"),
    ],
)
def test_sensitive_categories_never_exempted_as_structural(
    category: str, group: str, tag_name: str
) -> None:
    """GPS, Author, Date, Software, and Identifiers metadata must never be structural."""
    assert config.is_structural_tag(group, tag_name) is False


def test_geotiff_model_tags_are_not_camera_hardware() -> None:
    """``Make``/``Model`` are exact matches so GeoTIFF georeferencing survives."""
    scanner = MetadataScanner()

    assert scanner._classify_tag("IFD0", "Model")[0] == "device"
    assert scanner._classify_tag("IFD0", "ModelTiePoint")[0] != "device"
    assert scanner._classify_tag("IFD0", "ModelTransform")[0] != "device"


# ---------------------------------------------------------------------------
# Removal arguments must be valid ExifTool names
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "category",
    [category for category in config.METADATA_CATEGORIES if category != "all"],
)
def test_removal_arguments_are_writable_exiftool_tags(
    category: str, jpeg_with_category_metadata: Path, temp_dir: Path
) -> None:
    """Every argument must name a tag ExifTool can delete.

    ExifTool only warns (and still exits 0 for these cases), so a typo in a
    category definition would otherwise remove nothing while looking successful.
    """
    target = temp_dir / f"arguments_{category}.jpg"
    shutil.copyfile(jpeg_with_category_metadata, target)

    result = subprocess.run(
        ["exiftool", "-q", "-overwrite_original", *_removal_args(category), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )

    diagnostics = (result.stderr or "").strip()
    invalid = [marker for marker in _INVALID_ARG_MARKERS if marker in diagnostics]
    assert not invalid, f"{category} arguments rejected by ExifTool: {diagnostics}"
    assert result.returncode < 2, f"{category} arguments failed: {diagnostics}"


# ---------------------------------------------------------------------------
# Synthetic fixture really exercises every category
# ---------------------------------------------------------------------------
def test_fixture_exercises_every_targeted_category(
    jpeg_with_category_metadata: Path,
) -> None:
    scan = MetadataScanner().scan(jpeg_with_category_metadata)

    assert scan.inspection_complete, scan.limitations
    missing = [category for category in TARGETED_CATEGORIES if not scan.categories[category].detected]
    assert not missing, f"Fixture does not cover categories: {missing}"


# ---------------------------------------------------------------------------
# Selective removal: clears its own category, keeps structure and controls
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("category", TARGETED_CATEGORIES)
def test_selective_removal_clears_only_its_category(
    category: str, jpeg_with_category_metadata: Path, temp_dir: Path
) -> None:
    output = temp_dir / f"selective_{category}.jpg"

    result = MetadataRemover().clean(
        jpeg_with_category_metadata,
        output,
        categories=[category],
        overwrite_output=True,
    )
    assert result.success, result.errors

    scan = MetadataScanner().scan(output)
    assert scan.categories[category].tags == [], (
        f"{category} still contains: "
        f"{[(tag.group, tag.name) for tag in scan.categories[category].tags]}"
    )

    # Orientation is required for correct display and must survive every strip.
    orientation = next(
        (tag for tag in scan.image_metadata.values() if tag.name == "Orientation"), None
    )
    assert orientation is not None, "Orientation must survive selective cleaning"
    assert orientation.display_value == "Rotate 90 CW"

    # A category outside the requested one must still be detectable.
    assert scan.categories[CONTROL_CATEGORY[category]].detected, (
        f"Cleaning '{category}' unexpectedly removed "
        f"'{CONTROL_CATEGORY[category]}' metadata"
    )

    names = {tag.name for tag in scan.image_metadata.values()}
    if category in ("gps", "date"):
        # SubjectLocation is image-relative composition data, not a place.
        assert {"SubjectLocation", "SubjectArea"} <= names
    if category == "date":
        # ``-*Date*`` must not widen into photographic time settings.
        assert "ExposureTime" in names


# ---------------------------------------------------------------------------
# Profile-level behaviour on the same rich fixture
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "profile,expected_empty,expected_present",
    [
        (
            "location",
            ("gps",),
            ("author", "comments", "date", "device"),
        ),
        (
            "basic",
            ("gps", "author", "comments", "copyright"),
            ("date", "device", "software"),
        ),
        (
            "personal",
            ("author", "copyright", "comments", "identifiers"),
            ("gps", "device"),
        ),
    ],
)
def test_profiles_remove_only_their_declared_categories(
    profile: str,
    expected_empty: tuple[str, ...],
    expected_present: tuple[str, ...],
    jpeg_with_category_metadata: Path,
    temp_dir: Path,
) -> None:
    output = temp_dir / f"profile_{profile}.jpg"

    result = MetadataRemover().clean(
        jpeg_with_category_metadata,
        output,
        profile=profile,
        overwrite_output=True,
    )
    assert result.success, result.errors

    scan = MetadataScanner().scan(output)
    still_present = {
        category for category in expected_empty if scan.categories[category].tags
    }
    assert not still_present, f"Profile '{profile}' left {sorted(still_present)} metadata"

    disappeared = {
        category for category in expected_present if not scan.categories[category].detected
    }
    assert not disappeared, f"Profile '{profile}' removed {sorted(disappeared)} unexpectedly"


def test_maximum_profile_verifies_clean_and_preserves_orientation(
    jpeg_with_category_metadata: Path, temp_dir: Path
) -> None:
    output = temp_dir / "maximum_category_metadata.jpg"

    result = MetadataRemover().clean(
        jpeg_with_category_metadata,
        output,
        profile="maximum",
        overwrite_output=True,
    )
    assert result.success, result.errors

    verification = MetadataVerifier().verify(
        output, profile="maximum", original_image_path=jpeg_with_category_metadata
    )
    assert verification.outcome == VerificationOutcome.VERIFIED_CLEAN
    assert verification.status.value == "PASS"
    assert verification.residual_metadata_tags == []
    assert verification.remaining_targeted_tags == []

    scan = MetadataScanner().scan(output)
    for category in TARGETED_CATEGORIES:
        assert scan.categories[category].tags == [], category

    orientation = next(
        (tag for tag in scan.image_metadata.values() if tag.name == "Orientation"), None
    )
    assert orientation is not None
    assert orientation.display_value == "Rotate 90 CW"
