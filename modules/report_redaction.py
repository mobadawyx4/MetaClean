"""Redaction policy for MetaClean reports (F-08).

The policy is an **allowlist**, not a blocklist.  A redacted report exposes
only facts that cannot identify a person, a device, or a file:

* container facts for an explicit allowlist of structural tag names
  (format, dimensions, colour space, compression, orientation);
* tag identity (group, name, category, value type, extraction status);
* risk levels, counts, booleans, scores, category names and static
  explanations/recommendations.

Everything else is withheld in redacted mode: every non-structural metadata
value, GPS coordinates and map links, absolute paths and filenames,
filesystem timestamps, free-text previews, before/after comparison values and
evidence snippets.

A final scrub pass then removes any known identifier literal that survived in
a fallback field (warnings, limitations, narrative text), and masks e-mail
addresses, telephone numbers and home/temporary directory paths found in free
text.  The scrub pass is defence in depth: reports should not rely on it
instead of the field allowlist.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional

import config

REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED-EMAIL]"
REDACTED_PHONE = "[REDACTED-PHONE]"
REDACTED_PATH = "[REDACTED-PATH]"

# Structural names that identify the file or its location rather than the
# image content.  They stay masked even though they are technically structural.
UNSAFE_STRUCTURAL_VALUE_NAMES = frozenset({
    "FileName",
    "Directory",
    "SourceFile",
    "FileModifyDate",
    "FileAccessDate",
    "FileInodeChangeDate",
    "FilePermissions",
})

# The explicit allowlist of tag values that may be printed in redacted mode.
SAFE_STRUCTURAL_VALUE_NAMES = frozenset(
    config.STRUCTURAL_TAG_ALLOWLIST
) - UNSAFE_STRUCTURAL_VALUE_NAMES

# Filesystem attribute allowlist.  Only the size is a content fact; names,
# timestamps and permission bits are withheld.
SAFE_FILESYSTEM_FIELDS = frozenset({"file_size_bytes"})

_MIN_NEEDLE_LENGTH = 4


def safe_tag_value(tag: Any) -> bool:
    """Returns True when a tag's *value* may be shown in a redacted report."""
    name = getattr(tag, "name", "") or ""
    group = getattr(tag, "group", "") or ""
    if name not in SAFE_STRUCTURAL_VALUE_NAMES:
        return False
    if group in config.STRUCTURAL_GROUPS:
        return True
    return group == "Composite" and name in config.STRUCTURAL_COMPOSITE_TAGS


def safe_filesystem_field(name: str) -> bool:
    """Returns True when a filesystem attribute key may be shown when redacted."""
    return name in SAFE_FILESYSTEM_FIELDS


class ReportRedactor:
    """Removes residual identifiers from free-text and fallback fields."""

    _EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    _PHONE_RE = re.compile(
        r"(?<![\w])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?"
        r"\d{2,4}(?:[\s.\-]\d{2,4}){1,4}(?![\w])"
    )
    _DATE_LIKE_RE = re.compile(
        r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})"
    )
    _HOME_PATH_RE = re.compile(
        r"(?:/home/|/Users/|/root/|/tmp/|/private/var/|[A-Za-z]:\\Users\\)"
        r"[^\s\"'<>|,;]*"
    )

    def __init__(self, needles: Optional[Iterable[str]] = None) -> None:
        # Longest first so a full path is replaced before its basename.
        unique = {n for n in (needles or []) if isinstance(n, str) and len(n) >= _MIN_NEEDLE_LENGTH}
        self._needles: List[str] = sorted(unique, key=len, reverse=True)

    # ------------------------------------------------------------------
    @classmethod
    def for_scan(
        cls,
        scan: Any = None,
        removal: Any = None,
        verification: Any = None,
        file_analysis: Any = None,
    ) -> "ReportRedactor":
        """Collects the identifier literals known to one report."""
        needles: List[str] = []

        def add(value: Any) -> None:
            if value is None:
                return
            text = str(value)
            if text:
                needles.append(text)

        def add_path(path: Any) -> None:
            if path is None:
                return
            add(path)
            add(getattr(path, "name", None))
            add(getattr(path, "stem", None))

        if scan is not None:
            add_path(getattr(scan, "file_path", None))
            add(getattr(scan, "filesystem_metadata", {}).get("file_name"))

            for tag in getattr(scan, "image_metadata", {}).values():
                if safe_tag_value(tag):
                    continue  # value is intentionally exposed; never scrub it
                raw = getattr(tag, "value", None)
                if isinstance(raw, str):
                    add(raw)
                add(getattr(tag, "display_value", None))
                add(getattr(tag, "raw_value", None))

            gps = getattr(scan, "gps_coordinates", None)
            if gps is not None:
                add(getattr(gps, "formatted", None))
                add(getattr(gps, "latitude", None))
                add(getattr(gps, "longitude", None))
                add(getattr(gps, "altitude", None))

        if removal is not None:
            add_path(getattr(removal, "output_path", None))

        if verification is not None:
            add_path(getattr(verification, "target_image", None))
            add_path(getattr(verification, "original_image", None))
            for item in getattr(verification, "remaining_sensitive_tags", []) or []:
                add(getattr(item, "value_preview", None))
            comparison = getattr(verification, "comparison", None)
            for change in getattr(comparison, "changed_tags", []) or []:
                add(getattr(change, "before", None))
                add(getattr(change, "after", None))

        if file_analysis is not None:
            add(getattr(file_analysis, "trailing_data_preview", None))
            add(getattr(file_analysis, "icc_description", None))

        return cls(needles)

    # ------------------------------------------------------------------
    def scrub_text(self, text: str) -> str:
        """Masks known identifiers and recognisable PII inside one string."""
        if not text:
            return text

        scrubbed = text
        for needle in self._needles:
            if needle in scrubbed:
                scrubbed = scrubbed.replace(needle, REDACTED)

        scrubbed = self._EMAIL_RE.sub(REDACTED_EMAIL, scrubbed)

        def _phone_replacement(match: "re.Match[str]") -> str:
            candidate = match.group(0)
            if self._DATE_LIKE_RE.match(candidate):
                return candidate
            digits = sum(ch.isdigit() for ch in candidate)
            if digits < 9:
                return candidate
            return REDACTED_PHONE

        scrubbed = self._PHONE_RE.sub(_phone_replacement, scrubbed)
        scrubbed = self._HOME_PATH_RE.sub(REDACTED_PATH, scrubbed)
        return scrubbed

    def scrub(self, value: Any) -> Any:
        """Recursively scrubs strings in a report structure.

        Mapping keys are structural schema names and are left untouched; only
        values are scrubbed.
        """
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, dict):
            return {key: self.scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self.scrub(item) for item in value]
        return value
