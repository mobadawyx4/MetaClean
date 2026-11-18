"""JSON default-encoder regression tests (F-09).

The encoder must map every supported report type deterministically, refuse
unsupported objects with a controlled error, and never fall back to
``str()``/``repr()`` of an arbitrary object.
"""

from __future__ import annotations

import base64
import datetime
import json
import uuid
from decimal import Decimal
from pathlib import Path

import pytest

from modules.json_encoder import JSONEncodingError, dumps_report, json_default
from modules.metadata_scanner import MetadataScanner, MetadataTag
from modules.privacy_analyzer import RiskLevel
from modules.report_generator import export_batch_json, export_json_report


# ---------------------------------------------------------------------------
# Supported types
# ---------------------------------------------------------------------------
def test_supported_types_encode_to_documented_shapes() -> None:
    payload = {
        "payload": b"\x00\x01hello",
        "when": datetime.datetime(2024, 5, 6, 7, 8, 9, tzinfo=datetime.timezone.utc),
        "day": datetime.date(2024, 5, 6),
        "clock": datetime.time(7, 8, 9),
        "span": datetime.timedelta(seconds=90),
        "path": Path("/tmp/example.jpg"),
        "identifier": uuid.UUID(int=1),
        "amount": Decimal("1.50"),
        "levels": {"CRITICAL", "HIGH", "MEDIUM"},
        "frozen": frozenset({3, 1, 2}),
        "pair": (1, "two"),
        "risk": RiskLevel.HIGH,
    }

    parsed = json.loads(dumps_report(payload))

    assert parsed["payload"] == {
        "$type": "bytes",
        "$encoding": "base64",
        "$value": base64.b64encode(b"\x00\x01hello").decode("ascii"),
    }
    assert parsed["when"] == "2024-05-06T07:08:09+00:00"
    assert parsed["day"] == "2024-05-06"
    assert parsed["clock"] == "07:08:09"
    assert parsed["span"] == 90.0
    assert parsed["path"] == "/tmp/example.jpg"
    assert parsed["identifier"] == "00000000-0000-0000-0000-000000000001"
    assert parsed["amount"] == "1.50"
    assert parsed["levels"] == ["CRITICAL", "HIGH", "MEDIUM"]
    assert parsed["frozen"] == [1, 2, 3]
    assert parsed["pair"] == [1, "two"]
    assert parsed["risk"] == "HIGH"


def test_encoding_is_deterministic() -> None:
    payload = {
        "set": {"delta", "alpha", "charlie", "bravo"},
        "mixed": {3, "three", 1.5, None, True},
        "nested": [{"z": {2, 1}}, {"a": (2, 1)}],
    }
    first = dumps_report(payload)
    second = dumps_report(payload)
    assert first == second

    # Rebuilding an equivalent set must not change the byte stream.
    rebuilt = {"delta", "alpha", "charlie", "bravo"}
    payload["set"] = rebuilt
    assert dumps_report(payload) == first


def test_json_default_handles_known_types_directly() -> None:
    assert json_default(Path("/tmp/example.jpg")) == "/tmp/example.jpg"
    assert json_default((1, 2)) == [1, 2]
    assert json_default({3, 1, 2}) == [1, 2, 3]
    assert json_default(Decimal("2.5")) == "2.5"
    assert json_default(b"hi")["$encoding"] == "base64"


# ---------------------------------------------------------------------------
# Unsupported values
# ---------------------------------------------------------------------------
def test_unsupported_object_raises_clear_error() -> None:
    with pytest.raises(JSONEncodingError, match="'object'"):
        dumps_report({"value": object()})


def test_nested_unsupported_object_raises() -> None:
    payload = {"items": [{"nested": object()}]}
    with pytest.raises(JSONEncodingError) as excinfo:
        dumps_report(payload)
    assert "object" in str(excinfo.value)
    assert "Unsupported report value" in str(excinfo.value)


def test_non_finite_floats_raise_instead_of_writing_invalid_json() -> None:
    with pytest.raises(JSONEncodingError, match="serialized"):
        dumps_report({"nan": float("nan")})
    with pytest.raises(JSONEncodingError):
        dumps_report({"inf": float("inf")})


def test_unsupported_error_does_not_stringify_object() -> None:
    class SecretHolder:
        def __init__(self) -> None:
            self.secret = "INTERNAL-TOKEN"

        def __str__(self) -> str:
            return self.secret

    with pytest.raises(JSONEncodingError) as excinfo:
        dumps_report({"holder": SecretHolder()})

    assert "INTERNAL-TOKEN" not in str(excinfo.value)
    assert "SecretHolder" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Report integration
# ---------------------------------------------------------------------------
def test_batch_json_encodes_non_native_values(tmp_path: Path) -> None:
    records = [
        {
            "file_name": "a.jpg",
            "format": "JPEG",
            "extra_bytes": b"ABC",
            "extra_date": datetime.date(2024, 1, 2),
            "extra_path": Path("/tmp/a.jpg"),
            "extra_set": {"b", "a"},
        }
    ]

    out = export_batch_json(records, tmp_path / "batch.json", redact=False)
    parsed = json.loads(out.read_text(encoding="utf-8"))

    assert parsed["results"][0]["extra_bytes"]["$type"] == "bytes"
    assert parsed["results"][0]["extra_date"] == "2024-01-02"
    assert parsed["results"][0]["extra_path"] == "/tmp/a.jpg"
    assert parsed["results"][0]["extra_set"] == ["a", "b"]


def test_redacted_export_masks_byte_values_before_encoding(
    clean_jpeg: Path, tmp_path: Path
) -> None:
    scan = MetadataScanner().scan(clean_jpeg)
    scan.image_metadata["XMP:SecretBytes"] = MetadataTag(
        name="SecretBytes", value=b"SECRET-BYTES", group="XMP", category="xmp"
    )

    redacted = export_json_report(tmp_path / "redacted.json", scan)
    redacted_text = redacted.read_text(encoding="utf-8")
    assert "SECRET-BYTES" not in redacted_text
    assert "$encoding" not in redacted_text
    assert json.loads(redacted_text)["report"]["redacted"] is True

    plain = export_json_report(tmp_path / "plain.json", scan, redact=False)
    plain_text = plain.read_text(encoding="utf-8")
    assert "$type" in plain_text
    assert base64.b64encode(b"SECRET-BYTES").decode("ascii") in plain_text
