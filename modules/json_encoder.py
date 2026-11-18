"""JSON encoding for MetaClean reports (F-09).

``json.dumps`` only understands ``dict``/``list``/``str``/``int``/``float``/
``bool``/``None``.  Report objects also contain paths, dates, byte strings,
sets and enums, so serialization needs an explicit, deterministic mapping for
each supported type.

Design rules:

* Every supported type has one documented representation; encoding the same
  value twice always produces the same bytes.
* Only an allowlist of types is converted.  Arbitrary objects are never
  stringified with ``repr``/``str`` because that could copy internal state or
  sensitive attributes into a report.
* An unsupported value raises :class:`JSONEncodingError`, a ``TypeError``
  subclass with a message naming the offending type, so callers get a
  controlled failure instead of a silent ``default=str`` leak.
"""

from __future__ import annotations

import base64
import datetime
import json
import uuid
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any


class JSONEncodingError(TypeError):
    """Raised when a report value cannot be encoded safely."""


_SUPPORTED_TYPES_TEXT = (
    "bytes, bytearray, memoryview, datetime/date/time, path, UUID, Decimal, "
    "set/frozenset, tuple and Enum"
)


def _canonical_sort_key(value: Any) -> str:
    """Stable ordering key for set members of mixed types."""
    try:
        return json.dumps(
            value,
            default=json_default,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return f"{type(value).__name__}:{value!r}"


def json_default(value: Any) -> Any:
    """Converts one supported non-native value into a JSON-safe equivalent.

    ``bytes`` are base64-encoded with an explicit tag so the original type is
    recoverable and no raw binary (which may itself be metadata) is merged
    into text fields.  Sets are sorted by their canonical JSON form, which
    makes output deterministic across runs and hash seeds.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {
            "$type": "bytes",
            "$encoding": "base64",
            "$value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return value.total_seconds()
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=_canonical_sort_key)
    if isinstance(value, tuple):
        return list(value)

    raise JSONEncodingError(
        f"Unsupported report value of type '{type(value).__name__}'. "
        f"Supported non-native types are: {_SUPPORTED_TYPES_TEXT}."
    )


def dumps_report(data: Any, *, indent: int = 2) -> str:
    """Serializes report data with the allowlisted encoder.

    ``allow_nan=False`` is deliberate: ``NaN``/``Infinity`` are not valid JSON
    and would produce a file that downstream parsers reject, so they raise a
    controlled error instead.
    """
    try:
        return json.dumps(
            data,
            default=json_default,
            indent=indent,
            ensure_ascii=False,
            allow_nan=False,
        )
    except JSONEncodingError:
        raise
    except (TypeError, ValueError) as exc:
        raise JSONEncodingError(f"Report could not be serialized: {exc}") from exc
