"""Small duck-typing helpers for metadata tag objects.

``metadata_scanner`` imports ``privacy_analyzer`` for risk classification. To
avoid a circular import, the analyzer accesses tags through these helpers
instead of importing ``MetadataTag`` directly. They also allow the analyzer to
accept plain dictionaries and test doubles.
"""

from __future__ import annotations

from typing import Any, Optional


def tag_name_of(tag: Any) -> str:
    if isinstance(tag, dict):
        return str(tag.get("name", ""))
    return str(getattr(tag, "name", ""))


def tag_group(tag: Any) -> Optional[str]:
    if isinstance(tag, dict):
        group = tag.get("group")
        return str(group) if group is not None else None
    group = getattr(tag, "group", None)
    return str(group) if group is not None else None


def tag_value_of(tag: Any) -> Any:
    if isinstance(tag, dict):
        return tag.get("value")
    return getattr(tag, "value", None)


def tag_is_derived(tag: Any) -> bool:
    if isinstance(tag, dict):
        return bool(tag.get("derived", False))
    return bool(getattr(tag, "derived", False))


def tag_key_of(tag: Any) -> str:
    if isinstance(tag, dict):
        return str(tag.get("key") or f"{tag.get('group', '')}:{tag.get('name', '')}")
    key = getattr(tag, "key", "")
    if key:
        return str(key)
    return f"{tag_group(tag) or ''}:{tag_name_of(tag)}"
