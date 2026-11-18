"""Predefined sanitization profiles.

Profiles are semantic bundles of removal categories.  They exist so users do not
have to remember individual ExifTool tag groups, and so verification can state
exactly what "clean" means for the selected profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

import config


@dataclass(frozen=True)
class SanitizationProfile:
    """A named set of metadata categories to remove."""

    key: str
    name: str
    description: str
    categories: tuple[str, ...]
    full_clean: bool = False
    note: str = ""


ALL_REMOVABLE_CATEGORIES: tuple[str, ...] = tuple(
    key for key in config.METADATA_CATEGORIES if key != "all"
)

PROFILES: Dict[str, SanitizationProfile] = {
    "basic": SanitizationProfile(
        key="basic",
        name="Basic Privacy Cleanup",
        description=(
            "Removes the highest-impact privacy fields: GPS location, author/creator "
            "identity, free-text comments, and copyright ownership."
        ),
        categories=("gps", "author", "comments", "copyright"),
        note="Camera settings and timestamps are retained.",
    ),
    "location": SanitizationProfile(
        key="location",
        name="Location Removal",
        description="Removes only GPS and location-related metadata.",
        categories=("gps",),
        note="All other metadata, including identifying author fields, is retained.",
    ),
    "personal": SanitizationProfile(
        key="personal",
        name="Personal Information Removal",
        description=(
            "Removes author/creator identity, contact fields, copyright, free-text "
            "comments, and unique document/image identifiers."
        ),
        categories=("author", "copyright", "comments", "identifiers"),
        note="GPS and device details are retained; use 'basic' or 'maximum' for those.",
    ),
    "maximum": SanitizationProfile(
        key="maximum",
        name="Maximum Metadata Cleanup",
        description=(
            "Removes every supported metadata category, including EXIF, GPS, IPTC, "
            "XMP, MakerNotes, embedded thumbnails and software fields."
        ),
        categories=("all",),
        full_clean=True,
        note="Container/colour-management and orientation structure required for correct rendering is preserved.",
    ),
    "custom": SanitizationProfile(
        key="custom",
        name="Custom Cleanup",
        description="Removes exactly the categories supplied with --remove.",
        categories=(),
        note="Use --remove with a comma-separated category list.",
    ),
}


def get_profile(name: str) -> Optional[SanitizationProfile]:
    return PROFILES.get((name or "").strip().lower())


def resolve_profile(
    profile_name: str,
    custom_categories: Optional[Sequence[str] | str] = None,
) -> tuple[SanitizationProfile, List[str]]:
    """Resolves a profile name (and optional custom categories) to a category list.

    Raises:
        ValueError: for an unknown profile or an empty custom list.
    """
    profile = get_profile(profile_name)
    if profile is None:
        raise ValueError(
            f"Unknown sanitization profile '{profile_name}'. "
            f"Available profiles: {', '.join(PROFILES)}."
        )

    if profile.key == "custom":
        if not custom_categories:
            raise ValueError("The 'custom' profile requires at least one --remove category.")
        if isinstance(custom_categories, str):
            categories = [c.strip().lower() for c in custom_categories.split(",") if c.strip()]
        else:
            categories = [str(c).strip().lower() for c in custom_categories if str(c).strip()]
        if not categories:
            raise ValueError("The 'custom' profile requires at least one --remove category.")
        return profile, categories

    return profile, list(profile.categories)


def describe_profiles() -> List[Dict[str, object]]:
    """Returns a serialisable description of every profile (used by ``info``)."""
    return [
        {
            "key": p.key,
            "name": p.name,
            "description": p.description,
            "categories": list(p.categories),
            "full_clean": p.full_clean,
            "note": p.note,
        }
        for p in PROFILES.values()
    ]
