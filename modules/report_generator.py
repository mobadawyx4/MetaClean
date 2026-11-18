"""Report generation for MetaClean.

Supports JSON audit reports, per-tag CSV exports, batch CSV summaries and a
self-contained HTML report.

Reports are **redacted by default** (F-08).  Redaction follows an allowlist:
only container facts for an explicit set of structural tag names, tag
identity, risk levels, counts and static explanations are emitted.  Metadata
values, paths, filenames, GPS data, timestamps and free-text previews are
withheld unless the caller explicitly opts out with ``redact=False``.

All values are escaped when rendered into HTML.  No external assets or network
requests are used.
"""

from __future__ import annotations

import csv
import datetime
import html
import io
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import config
from modules.comparison import comparison_to_dict
from modules.file_analyzer import FileAnalysis, FindingKind
from modules.image_validator import (
    ImageValidationError,
    file_identity,
    is_symlink,
    safe_resolve_path,
)
from modules.json_encoder import dumps_report
from modules.metadata_remover import RemovalResult
from modules.metadata_scanner import ScanResult
from modules.metadata_verifier import VerificationReport
from modules.report_redaction import (
    REDACTED,
    ReportRedactor,
    safe_filesystem_field,
    safe_tag_value,
)

_REDACTED = REDACTED


def _resolve_report_path(output_path: Path | str) -> Path:
    """Resolves a report destination without following a final-component symlink.

    Report exports are outputs of the scan/clean commands, so they follow the
    same F-06 path policy as sanitized images: a report may not be written
    through a symbolic link.
    """
    out_p = safe_resolve_path(output_path, must_exist=False, role="report output")
    out_p.parent.mkdir(parents=True, exist_ok=True)
    return out_p


def _write_text_report(out_p: Path, content: str) -> None:
    """Writes a fully built report atomically.

    The report is rendered in memory and staged in the destination directory
    first, so a serialization failure, an encoding error, or a symlink swapped
    into place mid-write cannot truncate or destroy an existing report file.
    """
    fd, name = tempfile.mkstemp(
        prefix=".metaclean-report-", suffix=out_p.suffix, dir=str(out_p.parent)
    )
    temp = Path(name)
    identity = file_identity(temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        if is_symlink(out_p):
            raise ImageValidationError(
                "Security violation: refusing to write a report through a "
                f"symbolic link at the output path: {out_p}"
            )
        os.replace(temp, out_p)
        temp = None
    finally:
        if temp is not None:
            current = file_identity(temp)
            if current is not None and current.is_same_entry(identity):
                try:
                    os.unlink(temp)
                except OSError:
                    pass


def _tag_risk_map(scan: ScanResult) -> Dict[str, str]:
    levels: Dict[str, str] = {}
    for item in (scan.privacy_report.items if scan.privacy_report else []):
        levels[item.tag_key] = item.risk_level.value
    return levels


def _file_analysis_to_dict(
    analysis: Optional[FileAnalysis], redact: bool = True
) -> Optional[Dict[str, Any]]:
    if analysis is None:
        return None
    return {
        "detected_format": analysis.detected_format,
        "declared_extension": analysis.declared_extension,
        "extension_matches": analysis.extension_matches,
        "mime_type": analysis.mime_type,
        "file_size": analysis.file_size,
        "dimensions": list(analysis.dimensions) if analysis.dimensions else None,
        "color_mode": analysis.color_mode,
        "color_model": analysis.color_model,
        "bit_depth": analysis.bit_depth,
        "has_alpha": analysis.has_alpha,
        "is_animated": analysis.is_animated,
        "n_frames": analysis.n_frames,
        "frame_durations_ms": analysis.frame_durations_ms,
        "has_icc_profile": analysis.has_icc_profile,
        "icc_profile_bytes": analysis.icc_profile_bytes,
        "icc_description": _REDACTED if redact else analysis.icc_description,
        "embedded_thumbnail_tags": analysis.embedded_thumbnail_tags,
        "metadata_groups": analysis.metadata_groups,
        "end_marker_found": analysis.end_marker_found,
        "trailing_data_bytes": analysis.trailing_data_bytes,
        "trailing_data_preview": "" if redact else analysis.trailing_data_preview,
        "structure_notes": analysis.structure_notes,
        "findings": [
            {
                "kind": f.kind.value,
                "code": f.code,
                "title": f.title,
                "detail": _REDACTED if redact else f.detail,
                "severity": f.severity,
                "evidence": _REDACTED if redact else f.evidence,
            }
            for f in analysis.findings
        ],
    }



def build_file_report_dict(
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
    redact: bool = True,
    file_analysis: Optional[FileAnalysis] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Assembles a structured dictionary representing the full security audit.

    ``redact`` defaults to True: report exports are privacy-safe unless the
    caller explicitly requests an unredacted report.
    """
    scan_id = scan_id or uuid.uuid4().hex

    detected_cats: Dict[str, Any] = {}
    for cat_name, cat_summary in scan.categories.items():
        detected_cats[cat_name] = {
            "detected": cat_summary.detected,
            "tag_count": len(cat_summary.tags),
            "tag_names": [t.name for t in cat_summary.tags],
        }

    risk_by_key = _tag_risk_map(scan)

    tags_out: List[Dict[str, Any]] = []
    for key, tag in scan.image_metadata.items():
        # Allowlist: a value is only printed when it is an explicit container
        # fact.  Everything else - names, comments, serials, dates, GPS - is
        # withheld by default.
        value_visible = (not redact) or safe_tag_value(tag)
        tags_out.append(
            {
                "group": tag.group,
                "family": tag.family,
                "name": tag.name,
                "category": tag.category,
                "value": tag.value if value_visible else _REDACTED,
                "display_value": tag.display_value if value_visible else _REDACTED,
                "raw_value": tag.raw_value if value_visible else _REDACTED,
                "value_type": tag.value_type,
                "extraction_status": tag.extraction_status,
                "derived": tag.derived,
                "risk_level": risk_by_key.get(key, "UNCLASSIFIED"),
                "redacted": not value_visible,
            }
        )

    privacy_info: Dict[str, Any] = {}
    if scan.privacy_report:
        pr = scan.privacy_report
        privacy_info = {
            "overall_risk": pr.overall_risk.value,
            "risk_score": pr.risk_score,
            "summary_narrative": pr.summary_narrative,
            "critical_count": pr.critical_count,
            "high_risk_count": pr.high_risk_count,
            "medium_risk_count": pr.medium_risk_count,
            "low_risk_count": pr.low_risk_count,
            "informational_count": pr.info_count,
            "sensitive_count": pr.sensitive_count,
            "gps_detected": pr.gps_detected,
            "device_identifiers_detected": pr.device_identifiers_detected,
            "personal_information_detected": pr.personal_information_detected,
            "timestamps_detected": pr.timestamps_detected,
            "thumbnails_detected": pr.thumbnails_detected,
            "recommendations": pr.recommendations,
            "score_explanation": pr.score_explanation,
            "score_components": [
                {
                    "level": c.level,
                    "count": c.count,
                    "weight_per_tag": c.weight_per_tag,
                    "raw_contribution": c.raw_contribution,
                    "capped_contribution": c.capped_contribution,
                }
                for c in pr.score_components
            ],
            "category_breakdown": [
                {
                    "category": c.category,
                    "count": c.count,
                    "max_level": c.max_level.value,
                    "contribution": c.contribution,
                    "examples": c.examples,
                }
                for c in pr.category_breakdown
            ],
            "assessed_tags": [
                {
                    "tag": item.tag_name,
                    "key": item.tag_key,
                    "group": item.group,
                    "category": item.category,
                    "risk_level": item.risk_level.value,
                    "preview": _REDACTED if redact else item.value_preview,
                    "explanation": item.explanation,
                    "recommendation": item.recommendation,
                }
                for item in pr.items
            ],
        }

    removed_tags: List[str] = []
    if removal:
        removed_tags = list(removal.categories_removed)
    elif verification and verification.targeted_categories:
        for check in verification.category_checks:
            if check.status.value == "PASS":
                removed_tags.append(check.category)

    verification_info: Dict[str, Any] = {}
    if verification:
        comparison_dict = None
        if verification.comparison:
            comparison_dict = comparison_to_dict(verification.comparison)
            if redact:
                # Before/after values are metadata content; withhold all of them.
                for changed in comparison_dict.get("changed_tags", []):
                    changed["before"] = _REDACTED
                    changed["after"] = _REDACTED
        verification_info = {
            "status": verification.status.value,
            "outcome": verification.outcome.value,
            "outcome_reason": verification.outcome_reason,
            "summary": verification.summary_message,
            "profile": verification.profile,
            "targeted_categories": verification.targeted_categories,
            "remaining_targeted_tags_count": len(verification.remaining_targeted_tags),
            "remaining_sensitive_tags": [
                {
                    "tag": item.tag_name,
                    "key": item.tag_key,
                    "category": item.category,
                    "risk_level": item.risk_level.value,
                    "preview": _REDACTED if redact else item.value_preview,
                }
                for item in verification.remaining_sensitive_tags
            ],
            "residual_metadata_tags": verification.residual_metadata_tags,
            "category_checks": [
                {
                    "category": c.category,
                    "status": c.status.value,
                    "message": c.message,
                    "found_tag_count": len(c.found_tags),
                }
                for c in verification.category_checks
            ],
            "comparison": comparison_dict,
        }

    all_warnings: List[str] = list(scan.validation.warnings) + list(scan.warnings)
    all_limitations: List[str] = list(scan.limitations)
    if removal:
        all_warnings.extend(removal.warnings)
    if verification:
        all_limitations.extend(verification.limitations)

    gps = scan.gps_coordinates
    gps_info = None
    if gps:
        gps_info = {
            "latitude": _REDACTED if redact else gps.latitude,
            "longitude": _REDACTED if redact else gps.longitude,
            "altitude": _REDACTED if redact else gps.altitude,
            "formatted": _REDACTED if redact else gps.formatted,
            "google_maps_url": None if redact else gps.google_maps_url,
            "openstreetmap_url": None if redact else gps.openstreetmap_url,
        }

    generated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fs_attributes = dict(scan.filesystem_metadata)
    if redact:
        # Only the byte size is a content fact; names, timestamps, permission
        # bits and error strings can all disclose the file or its owner.
        fs_attributes = {
            key: (value if safe_filesystem_field(key) else _REDACTED)
            for key, value in fs_attributes.items()
        }

    analysis_source = file_analysis or scan.file_analysis
    analysis_dict = _file_analysis_to_dict(analysis_source, redact=redact)

    report_dict: Dict[str, Any] = {
        "report": {
            "scan_id": scan_id,
            "generated_utc": generated,
            "tool": config.APP_NAME,
            "tool_version": config.APP_VERSION,
            "redacted": redact,
            "scan_mode": scan.mode,
        },
        "scan_id": scan_id,
        "scan_mode": scan.mode,
        "metaclean_version": config.APP_VERSION,
        "report_generated_utc": generated,
        "redacted_report": redact,
        "input_file": {
            "path": _REDACTED if redact else str(scan.file_path),
            "filename": _REDACTED if redact else scan.file_path.name,
            "is_valid_image": scan.validation.is_valid,
            "format": scan.validation.format_name,
            "file_size_bytes": scan.validation.file_size,
            "dimensions": scan.validation.dimensions,
            "has_transparency": scan.validation.has_transparency,
            "is_animated": scan.validation.is_animated,
        },
        "filesystem_attributes": fs_attributes,
        "metadata_scan": {
            "backend": scan.scanner_backend,
            "backend_version": scan.backend_version,
            "mode": scan.mode,
            "inspected_fields_count": scan.total_embedded_tags,
            "empty_fields_count": scan.empty_tag_count,
            "metadata_group_counts": scan.metadata_group_counts,
            "detected_categories": detected_cats,
            "warnings": scan.warnings,
            "tags": tags_out,
        },
        "file_analysis": analysis_dict,
        "gps": gps_info,
        "privacy_risk_assessment": privacy_info,
        "removal_summary": {
            "executed": removal is not None,
            "method": removal.method_used if removal else None,
            "profile": removal.profile if removal else None,
            "requested_categories": removal.categories_requested if removal else [],
            "removed_categories": removed_tags,
            "preserved_categories": removal.preserved_categories if removal else [],
            "operations_attempted": removal.operations_attempted if removal else [],
            "exiftool_args": removal.exiftool_args if removal else [],
            "output_path": (
                (_REDACTED if redact else str(removal.output_path))
                if removal
                else None
            ),
            "output_validated": removal.output_validated if removal else None,
            "tags_updated_count": removal.tags_updated_count if removal else None,
            "bytes_saved": removal.bytes_saved if removal else 0,
        },
        "remaining_fields": [t.name for t in scan.image_metadata.values()],
        "verification": verification_info,
        "warnings": sorted(set(all_warnings)),
        "limitations": sorted(set(all_limitations)),
        "methodology_note": (
            "Risk scores are additive heuristics with fixed per-level weights and caps. "
            "They are explanatory, not scientifically validated security metrics. "
            "VERIFIED CLEAN covers the inspected metadata structures for the selected profile "
            "and does not attest to pixel content or steganography."
        ),
    }

    if redact:
        # Defence in depth: remove any identifier literal that survived in a
        # fallback field (warnings, limitations, narratives, error strings).
        redactor = ReportRedactor.for_scan(
            scan, removal, verification, analysis_source
        )
        report_dict = redactor.scrub(report_dict)
        report_dict["report"]["redacted"] = True
        report_dict["redacted_report"] = True

    return report_dict


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------
def export_json_report(
    output_path: Path | str,
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
    redact: bool = True,
    file_analysis: Optional[FileAnalysis] = None,
    scan_id: Optional[str] = None,
) -> Path:
    """Writes a comprehensive JSON report to the specified file path.

    The document is serialized with :func:`modules.json_encoder.dumps_report`
    before the destination is touched, so an unsupported metadata value raises
    ``JSONEncodingError`` without truncating an existing report.
    """
    data = build_file_report_dict(
        scan, removal, verification, redact=redact,
        file_analysis=file_analysis, scan_id=scan_id,
    )
    out_p = _resolve_report_path(output_path)
    _write_text_report(out_p, dumps_report(data))
    return out_p


# ----------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------
def export_metadata_csv(
    output_path: Path | str,
    scan: ScanResult,
    redact: bool = True,
    scan_id: Optional[str] = None,
) -> Path:
    """Exports a per-tag CSV table for one image.

    Tag values follow the same allowlist as JSON/HTML: only structural
    container facts are printed when ``redact`` is True.
    """
    out_p = _resolve_report_path(output_path)
    risk_by_key = _tag_risk_map(scan)

    headers = [
        "scan_id", "file_name", "group", "family", "tag", "category",
        "risk_level", "value_type", "extraction_status", "derived", "value",
    ]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()
    for key, tag in scan.image_metadata.items():
        value_visible = (not redact) or safe_tag_value(tag)
        writer.writerow(
            {
                "scan_id": scan_id or "",
                "file_name": _REDACTED if redact else scan.file_path.name,
                "group": tag.group,
                "family": tag.family,
                "tag": tag.name,
                "category": tag.category,
                "risk_level": risk_by_key.get(key, "UNCLASSIFIED"),
                "value_type": tag.value_type,
                "extraction_status": tag.extraction_status,
                "derived": tag.derived,
                "value": (
                    _csv_safe(tag.display_value or "") if value_visible else _REDACTED
                ),
            }
        )
    _write_text_report(out_p, buffer.getvalue())
    return out_p


_BATCH_HEADERS = [
    "file_name", "validation", "format", "original_size", "cleaned_size",
    "bytes_saved", "privacy_risk", "risk_score", "gps_detected",
    "author_detected", "date_detected", "removal_status",
    "verification_status", "verification_outcome", "output_path", "notes",
]


def _redact_batch_records(
    records: List[Dict[str, Any]], redact: bool
) -> List[Dict[str, Any]]:
    """Applies the batch report allowlist.

    Batch rows are keyed by filename and carry output paths and free-text
    notes.  In redacted mode a positional label replaces the filename and
    path-bearing fields are withheld.
    """
    if not redact:
        return [dict(record) for record in records]

    redacted_records: List[Dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        item = dict(record)
        # Collect identifier literals before masking, so a record that echoes
        # its own filename or path in another field is still scrubbed.
        identifiers = [
            record.get("file_name"),
            record.get("output_path"),
            record.get("notes"),
        ]
        item["file_name"] = f"image_{index:03d}"
        if item.get("output_path"):
            item["output_path"] = _REDACTED
        if item.get("notes"):
            item["notes"] = _REDACTED
        redacted_records.append(ReportRedactor(identifiers).scrub(item))
    return redacted_records


def _redact_batch_summary(
    summary: Optional[Dict[str, Any]], redact: bool
) -> Dict[str, Any]:
    if not redact or not summary:
        return dict(summary or {})
    return ReportRedactor().scrub(dict(summary))


def export_batch_csv(
    records: List[Dict[str, Any]], output_path: Path | str, redact: bool = True
) -> Path:
    """Exports batch processing summary records to a CSV file (stable schema)."""
    out_p = _resolve_report_path(output_path)
    safe_records = _redact_batch_records(records, redact)

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_BATCH_HEADERS)
    writer.writeheader()
    for rec in safe_records:
        writer.writerow({header: _csv_safe(rec.get(header, "")) for header in _BATCH_HEADERS})
    _write_text_report(out_p, buffer.getvalue())
    return out_p


def export_batch_json(
    records: List[Dict[str, Any]],
    output_path: Path | str,
    summary: Optional[Dict[str, Any]] = None,
    redact: bool = True,
) -> Path:
    """Exports batch summary records as JSON."""
    out_p = _resolve_report_path(output_path)
    payload = {
        "report": {
            "tool": config.APP_NAME,
            "tool_version": config.APP_VERSION,
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "redacted": redact,
        },
        "summary": _redact_batch_summary(summary, redact),
        "results": _redact_batch_records(records, redact),
    }
    _write_text_report(out_p, dumps_report(payload))
    return out_p


def export_batch_html(
    records: List[Dict[str, Any]],
    output_path: Path | str,
    summary: Optional[Dict[str, Any]] = None,
    redact: bool = True,
) -> Path:
    """Renders a self-contained HTML batch summary (no external assets)."""
    out_p = _resolve_report_path(output_path)

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    summary = _redact_batch_summary(summary, redact)
    safe_records = _redact_batch_records(records, redact)
    stats_html = "".join(
        f'<div class="stat"><div class="n">{esc(v)}</div><div class="l">{esc(k)}</div></div>'
        for k, v in summary.items()
    )
    rows = []
    for rec in safe_records:
        rows.append(
            [
                f"<code>{esc(rec.get('file_name'))}</code>",
                esc(rec.get("validation")),
                esc(rec.get("format")),
                esc(rec.get("privacy_risk")),
                esc(rec.get("risk_score")),
                esc(rec.get("verification_outcome") or rec.get("verification_status")),
                esc(rec.get("removal_status")),
                esc(rec.get("notes")),
            ]
        )

    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{config.APP_NAME} batch summary</title>
<style>{_HTML_CSS}</style></head>
<body>
<header><h1>{config.APP_NAME} Batch Summary</h1>
<p>Generated {esc(datetime.datetime.now(datetime.timezone.utc).isoformat())} · v{config.APP_VERSION}
{" · REDACTED" if redact else " · unredacted"}</p></header>
<main>
  <div class="card"><h2>Overview</h2><div class="grid">{stats_html}</div></div>
  <div class="card"><h2>Per-file results</h2>
  {_html_table(("File", "Validation", "Format", "Risk", "Score", "Outcome", "Removal", "Notes"), rows)}
  </div>
</main>
<footer>Reports may contain private data; share only with consent.</footer>
</body></html>"""
    _write_text_report(out_p, document)
    return out_p


def export_batch_report(
    records: List[Dict[str, Any]],
    output_path: Path | str,
    report_format: str = "csv",
    summary: Optional[Dict[str, Any]] = None,
    redact: bool = True,
) -> Path:
    """Dispatches a batch report to the requested format."""
    fmt = (report_format or "csv").lower()
    if fmt == "csv":
        return export_batch_csv(records, output_path, redact=redact)
    if fmt == "json":
        return export_batch_json(records, output_path, summary, redact=redact)
    if fmt == "html":
        return export_batch_html(records, output_path, summary, redact=redact)
    raise ValueError(f"Unsupported batch report format '{report_format}'. Use csv, json, or html.")


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------
_HTML_CSS = """
:root{--bg:#f6f8fb;--card:#fff;--ink:#1c2733;--muted:#5a6b7b;--line:#dde5ee;
--crit:#8e1b2c;--high:#b3261e;--med:#a06400;--low:#1e6b3a;--info:#3a5f8a;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;line-height:1.5}
header{background:linear-gradient(135deg,#12304d,#1b5a73);color:#fff;padding:28px 34px}
header h1{margin:0 0 4px;font-size:26px}header p{margin:0;opacity:.85;font-size:14px}
main{max-width:1180px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px 20px;margin-bottom:18px;box-shadow:0 1px 2px rgba(16,35,55,.04)}
h2{margin:0 0 12px;font-size:18px;border-bottom:1px solid var(--line);padding-bottom:8px}
h3{margin:16px 0 8px;font-size:15px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.stat{background:#f9fbfd;border:1px solid var(--line);border-radius:8px;padding:12px}
.stat .n{font-size:24px;font-weight:700}.stat .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
.b-crit{background:var(--crit)}.b-high{background:var(--high)}.b-med{background:var(--med)}
.b-low{background:var(--low)}.b-info{background:var(--info)}.b-clean{background:var(--low)}
.b-warn{background:var(--med)}.b-fail{background:var(--high)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f3f7fb;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.muted{color:var(--muted)}.small{font-size:12px}
.note{background:#fff8e6;border-left:4px solid var(--med);padding:10px 14px;border-radius:4px;font-size:13px}
.warnlist li,.limitlist li{margin:4px 0;font-size:13px}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}
footer{color:var(--muted);font-size:12px;text-align:center;padding:18px}
@media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}header{background:#12304d}}
"""


def _badge(text: str, css: str) -> str:
    return f'<span class="badge {css}">{html.escape(text)}</span>'


def _risk_badge(level: str) -> str:
    mapping = {
        "CRITICAL": "b-crit", "HIGH": "b-high", "MEDIUM": "b-med",
        "LOW": "b-low", "INFORMATIONAL": "b-info",
    }
    return _badge(level.title(), mapping.get(level, "b-info"))


def _outcome_badge(outcome: str) -> str:
    mapping = {
        "VERIFIED CLEAN": "b-clean",
        "PARTIALLY CLEANED": "b-warn",
        "SENSITIVE DATA REMAINS": "b-fail",
        "VERIFICATION FAILED": "b-fail",
    }
    return _badge(outcome, mapping.get(outcome, "b-info"))


def _csv_safe(value: Any) -> str:
    """Neutralises spreadsheet formula injection from metadata-derived values.
    A leading ``=`` / ``+`` / ``@`` or a leading ``-`` that is *not* the sign of
    a negative number is prefixed with a single quote so spreadsheet engines do
    not interpret it as a formula.  A bare leading minus followed by a digit is
    left untouched because it is a legitimate negative value (longitude, offset).
    Embedded control characters are stripped so a crafted value cannot inject
    newlines into a CSV cell.
    """
    text = "" if value is None else str(value)
    # Strip control characters (including newlines/tabs) that could break the
    # CSV row structure or inject content into downstream consumers.
    text = "".join(ch for ch in text if ord(ch) >= 32)
    if not text:
        return ""
    first = text[0]
    if first in ("=", "+", "@"):
        return "'" + text
    if first == "-" and not (len(text) > 1 and (text[1].isdigit() or text[1] == ".")):
        return "'" + text
    return text


def _html_table(headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    header_list = list(headers)
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in header_list)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(header_list)}" class="muted">No entries.</td></tr>')
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def build_html_report(data: Dict[str, Any]) -> str:
    """Renders the report dictionary as a self-contained HTML document."""
    report = data.get("report", {})
    inp = data.get("input_file", {})
    privacy = data.get("privacy_risk_assessment", {})
    meta = data.get("metadata_scan", {})
    analysis = data.get("file_analysis") or {}
    removal = data.get("removal_summary", {})
    verification = data.get("verification") or {}
    comparison = verification.get("comparison") or {}

    score = privacy.get("risk_score", 0)
    level = privacy.get("overall_risk", "INFORMATIONAL")

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    stats = [
        ("Risk score", f"{score}/100"),
        ("Overall level", level.title()),
        ("Metadata tags", meta.get("inspected_fields_count", 0)),
        ("Sensitive tags", privacy.get("sensitive_count", 0)),
        ("Critical findings", privacy.get("critical_count", 0)),
        ("GPS", "Yes" if privacy.get("gps_detected") else "No"),
        ("Device IDs", "Yes" if privacy.get("device_identifiers_detected") else "No"),
        ("Personal info", "Yes" if privacy.get("personal_information_detected") else "No"),
    ]
    stats_html = "".join(
        f'<div class="stat"><div class="n">{esc(n)}</div><div class="l">{esc(l)}</div></div>'
        for l, n in stats
    )

    _level_priority = {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1,
    }
    sensitive_rows = []
    for item in privacy.get("assessed_tags", []):
        if _level_priority.get(str(item.get("risk_level", "")), 1) < 3:
            continue
        sensitive_rows.append(
            [
                f"<code>{esc(item.get('key') or item.get('tag'))}</code>",
                _risk_badge(str(item.get("risk_level", ""))),
                esc(item.get("category", "")),
                f"<code>{esc(item.get('preview', ''))}</code>",
                esc(item.get("recommendation", "")),
            ]
        )

    tag_rows = []
    for tag in meta.get("tags", []):
        tag_rows.append(
            [
                f"<code>{esc(tag.get('group'))}:{esc(tag.get('name'))}</code>",
                esc(tag.get("category", "")),
                _risk_badge(str(tag.get("risk_level", "UNCLASSIFIED"))) if tag.get("risk_level") != "UNCLASSIFIED" else '<span class="muted">—</span>',
                f"<code>{esc(tag.get('display_value', ''))}</code>",
                esc(tag.get("value_type", "")),
                esc(tag.get("extraction_status", "")),
            ]
        )

    analysis_findings = []
    for finding in analysis.get("findings", []):
        kind = finding.get("kind", "")
        badge = _badge(kind, "b-info" if kind == FindingKind.INFORMATIONAL.value else ("b-med" if kind == FindingKind.SUSPICIOUS.value else "b-high"))
        analysis_findings.append(
            [
                badge,
                esc(finding.get("severity", "INFO")),
                f"<strong>{esc(finding.get('title'))}</strong><br><span class='small muted'>{esc(finding.get('detail'))}</span>",
            ]
        )

    profile_line = ""
    if removal.get("executed"):
        profile_line = (
            f"<p><strong>Profile:</strong> {esc(removal.get('profile') or 'custom')} &nbsp; "
            f"<strong>Method:</strong> {esc(removal.get('method'))} &nbsp; "
            f"<strong>Output validated:</strong> {esc(removal.get('output_validated'))}</p>"
            f"<p class='small muted'>Requested: {esc(', '.join(removal.get('requested_categories', [])))}</p>"
        )

    comparison_html = ""
    if comparison:
        comparison_rows = [
            ("Tags before", comparison.get("before_total_tags", 0)),
            ("Tags after", comparison.get("after_total_tags", 0)),
            ("Removed tags", comparison.get("removed_count", 0)),
            ("Remaining non-structural tags", comparison.get("remaining_count", 0)),
            ("Changed tags", len(comparison.get("changed_tags", []))),
            ("Newly introduced tags", comparison.get("introduced_count", 0)),
            ("Sensitive tags removed", comparison.get("sensitive_removed_count", 0)),
            ("Sensitive tags remaining", comparison.get("sensitive_remaining_count", 0)),
            ("Risk score before", f"{comparison.get('risk_score_before', 0)}/100"),
            ("Risk score after", f"{comparison.get('risk_score_after', 0)}/100"),
        ]
        comparison_html = (
            "<h2>Before / After Comparison</h2>"
            + _html_table(("Metric", "Value"), [(esc(a), esc(b)) for a, b in comparison_rows])
        )
        if comparison.get("removed_tags"):
            comparison_html += (
                "<details><summary>Removed tags (" + str(len(comparison["removed_tags"])) + ")</summary>"
                "<code>" + esc(", ".join(comparison["removed_tags"][:400])) + "</code></details>"
            )
        if comparison.get("sensitive_tags_remaining"):
            comparison_html += (
                "<h3>Sensitive tags remaining</h3>"
                + _html_table(
                    ("Tag", "Category", "Risk"),
                    [
                        (f"<code>{esc(i.get('key'))}</code>", esc(i.get("category", "")), _risk_badge(str(i.get("risk", ""))))
                        for i in comparison["sensitive_tags_remaining"]
                    ],
                )
            )

    verification_html = ""
    if verification:
        verification_html = (
            "<h2>Verification</h2>"
            f"<p>{_outcome_badge(str(verification.get('outcome', '')))} "
            f"<span class='muted'>(legacy status: {esc(verification.get('status'))})</span></p>"
            f"<p>{esc(verification.get('summary'))}</p>"
            f"<p class='small muted'>{esc(verification.get('outcome_reason'))}</p>"
        )

    warnings_html = ""
    warnings = data.get("warnings", [])
    limitations = data.get("limitations", [])
    if warnings or limitations:
        warnings_html = "<h2>Warnings and Limitations</h2>"
        if warnings:
            warnings_html += "<h3>Warnings</h3><ul class='warnlist'>" + "".join(
                f"<li>{esc(w)}</li>" for w in warnings
            ) + "</ul>"
        if limitations:
            warnings_html += "<h3>Limitations</h3><ul class='limitlist'>" + "".join(
                f"<li>{esc(lim)}</li>" for lim in limitations
            ) + "</ul>"

    recommendations = privacy.get("recommendations", [])
    rec_html = ""
    if recommendations:
        rec_html = "<h2>Recommendations</h2><ul>" + "".join(
            f"<li>{esc(r)}</li>" for r in recommendations
        ) + "</ul>"

    explanation = privacy.get("score_explanation", "")
    explanation_html = (
        f"<h2>Risk Score Calculation</h2><p class='small'><code>{esc(explanation)}</code></p>"
        "<p class='note'>The score is an additive heuristic with fixed weights and caps. "
        "It is not a validated scientific security metric.</p>"
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MetaClean report — {esc(inp.get('filename'))}</title>
<style>{_HTML_CSS}</style></head>
<body>
<header>
  <h1>MetaClean Metadata &amp; Privacy Report</h1>
  <p>{esc(inp.get('filename'))} · scan {esc(report.get('scan_id'))} · {esc(report.get('generated_utc'))}
  {"· REDACTED" if report.get("redacted") else "· unredacted"}</p>
</header>
<main>
  <div class="card">
    <h2>Overview</h2>
    <div class="grid">{stats_html}</div>
    <p><strong>Detected format:</strong> {esc(inp.get('format'))} &nbsp;
       <strong>Dimensions:</strong> {esc(inp.get('dimensions'))} &nbsp;
       <strong>File size:</strong> {esc(inp.get('file_size_bytes'))} bytes &nbsp;
       <strong>Scan mode:</strong> {esc(meta.get('mode'))}</p>
    <p class="small muted">{esc(privacy.get('summary_narrative'))}</p>
  </div>
  <div class="card">{explanation_html}</div>
  <div class="card">{verification_html}{comparison_html}</div>
  <div class="card">
    <h2>Sensitive Findings</h2>
    {_html_table(("Tag", "Risk", "Category", "Value", "Recommended action"), sensitive_rows)}
  </div>
  <div class="card">
    <h2>File / Container Analysis</h2>
    <p><strong>Container:</strong> {esc(analysis.get('detected_format'))} &nbsp;
       <strong>MIME:</strong> {esc(analysis.get('mime_type'))} &nbsp;
       <strong>Extension matches:</strong> {esc(analysis.get('extension_matches'))} &nbsp;
       <strong>Bit depth:</strong> {esc(analysis.get('bit_depth'))} &nbsp;
       <strong>Colour model:</strong> {esc(analysis.get('color_model'))} &nbsp;
       <strong>Frames:</strong> {esc(analysis.get('n_frames'))}</p>
    <p><strong>ICC profile:</strong> {esc(analysis.get('has_icc_profile'))} &nbsp;
       <strong>Trailing bytes:</strong> {esc(analysis.get('trailing_data_bytes'))} &nbsp;
       <strong>End marker found:</strong> {esc(analysis.get('end_marker_found'))}</p>
    {_html_table(("Kind", "Severity", "Observation"), analysis_findings)}
  </div>
  <div class="card">
    <h2>Cleaning</h2>
    {profile_line or "<p class='muted'>No cleaning operation was performed for this report.</p>"}
  </div>
  <div class="card">
    <h2>All Extracted Metadata ({esc(meta.get('inspected_fields_count'))} tags)</h2>
    <details><summary>Show tag table</summary>
    {_html_table(("Tag", "Category", "Risk", "Value", "Type", "Status"), tag_rows)}
    </details>
  </div>
  <div class="card">{rec_html}{warnings_html}</div>
  <div class="card"><h2>Methodology</h2><p class="small muted">{esc(data.get('methodology_note'))}</p></div>
</main>
<footer>Generated by {esc(report.get('tool'))} v{esc(report.get('tool_version'))} · reports may contain private data; share only with consent.</footer>
</body></html>"""
    return html_doc


def export_html_report(
    output_path: Path | str,
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
    redact: bool = True,
    file_analysis: Optional[FileAnalysis] = None,
    scan_id: Optional[str] = None,
) -> Path:
    data = build_file_report_dict(
        scan, removal, verification, redact=redact,
        file_analysis=file_analysis, scan_id=scan_id,
    )
    out_p = _resolve_report_path(output_path)
    _write_text_report(out_p, build_html_report(data))
    return out_p


def export_report(
    output_path: Path | str,
    report_format: str,
    scan: ScanResult,
    removal: Optional[RemovalResult] = None,
    verification: Optional[VerificationReport] = None,
    redact: bool = True,
    file_analysis: Optional[FileAnalysis] = None,
    scan_id: Optional[str] = None,
) -> Path:
    """Dispatches to the requested report exporter."""
    fmt = (report_format or "json").lower()
    if fmt == "json":
        return export_json_report(
            output_path, scan, removal, verification, redact, file_analysis, scan_id
        )
    if fmt == "html":
        return export_html_report(
            output_path, scan, removal, verification, redact, file_analysis, scan_id
        )
    if fmt == "csv":
        return export_metadata_csv(output_path, scan, redact, scan_id)
    raise ValueError(f"Unsupported report format '{report_format}'. Use json, html, or csv.")
