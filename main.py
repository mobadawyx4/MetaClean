#!/usr/bin/env python3
"""MetaClean — Image Metadata Intelligence, Privacy Analysis & Sanitization CLI.

Undergraduate Cybersecurity Graduation Project.
Author: MetaClean Security Team
Target Platform: Linux Mint (Terminal) / Cross-platform POSIX & Windows.

Safety contract:
* Scanning is read-only; cleaning never modifies the original file.
* Metadata values are never executed, and filenames/extensions are never trusted.
* Reports default to redacted output; unredacted export requires an explicit
  opt-in and a confirmation when sensitive values are present.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Force UTF-8 stdout to avoid terminal encoding errors on cross-platform consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import config
from modules.batch_processor import BatchFileResult, BatchProcessor, BatchSummary
from modules.metadata_remover import MetadataRemover, RemovalResult, validate_categories
from modules.metadata_scanner import MetadataScanner, ScanResult
from modules.metadata_verifier import (
    MetadataVerifier,
    VerificationOutcome,
    VerificationReport,
    VerificationStatus,
)
from modules.privacy_analyzer import RiskLevel, RuleBasedPrivacyAnalyzer
from modules.report_generator import (
    export_batch_report,
    export_report,
)
from modules.sanitizer_profiles import PROFILES, describe_profiles, get_profile


# =====================================================================
# Terminal Styling & Color Utilities (Standard Library)
# =====================================================================
class Colors:
    """ANSI color codes with terminal detection and manual override support."""

    RESET = ""
    BOLD = ""
    DIM = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    WHITE = ""

    @classmethod
    def configure(cls, enabled: bool) -> None:
        mapping = {
            "RESET": "\033[0m",
            "BOLD": "\033[1m",
            "DIM": "\033[2m",
            "RED": "\033[31m",
            "GREEN": "\033[32m",
            "YELLOW": "\033[33m",
            "BLUE": "\033[34m",
            "MAGENTA": "\033[35m",
            "CYAN": "\033[36m",
            "WHITE": "\033[37m",
        }
        for name, code in mapping.items():
            setattr(cls, name, code if enabled else "")


Colors.configure(sys.stdout.isatty() and "NO_COLOR" not in os.environ)

# Output verbosity state (configured after argument parsing).
_VERBOSE = False
_QUIET = False


def out(message: str = "") -> None:
    """Prints unless quiet mode is active."""
    if not _QUIET:
        print(message)


def verbose(message: str) -> None:
    """Prints only in verbose mode (and never in quiet mode)."""
    if _VERBOSE and not _QUIET:
        print(message)


def err(message: str) -> None:
    """Prints an error to stderr, even in quiet mode."""
    print(message, file=sys.stderr)


def print_banner() -> None:
    """Displays the MetaClean application header."""
    if _QUIET:
        return
    backend = (
        f"ExifTool {config.EXIFTOOL_VERSION or ''}".strip()
        if config.EXIFTOOL_AVAILABLE
        else "Pillow Fallback (ExifTool Missing)"
    )
    banner = f"""{Colors.CYAN}{Colors.BOLD}""" + r"""
  __  __      _         ____ _
 |  \/  | ___| |_ __ _ / ___| | ___  __ _ _ __
 | |\/| |/ _ \ __/ _` | |   | |/ _ \/ _` | '_ \
 | |  | |  __/ || (_| | |___| |  __/ (_| | | | |
 |_|  |_|\___|\__\__,_|\____|_|\___|\__,_|_| |_|""" + f"""
 {Colors.RESET}{Colors.DIM} Image Privacy Scanner, Sanitizer & Verification Engine v{config.APP_VERSION}
 Backend: {backend}
{Colors.RESET}"""
    print(banner)


def _level_text(level: Any) -> str:
    text = (getattr(level, "value", str(level)) or "").upper()
    return text.split(".")[-1]


def format_risk_badge(level: RiskLevel | str) -> str:
    """Formats a colored badge for the five privacy risk levels."""
    lvl = _level_text(level)
    if lvl == "CRITICAL":
        return f"{Colors.MAGENTA}{Colors.BOLD}[ CRITICAL ]{Colors.RESET}"
    if lvl == "HIGH":
        return f"{Colors.RED}{Colors.BOLD}[ HIGH RISK ]{Colors.RESET}"
    if lvl == "MEDIUM":
        return f"{Colors.YELLOW}{Colors.BOLD}[ MEDIUM RISK ]{Colors.RESET}"
    if lvl == "LOW":
        return f"{Colors.GREEN}[ LOW RISK ]{Colors.RESET}"
    return f"{Colors.CYAN}[ INFORMATIONAL ]{Colors.RESET}"


def format_status_badge(status: VerificationStatus | str) -> str:
    """Formats a colored badge for legacy verification statuses."""
    s = _level_text(status)
    if s == "PASS":
        return f"{Colors.GREEN}{Colors.BOLD}PASS{Colors.RESET}"
    if s == "WARNING":
        return f"{Colors.YELLOW}{Colors.BOLD}WARNING{Colors.RESET}"
    if s == "INCOMPLETE":
        return f"{Colors.MAGENTA}{Colors.BOLD}INCOMPLETE{Colors.RESET}"
    return f"{Colors.RED}{Colors.BOLD}FAIL{Colors.RESET}"


def format_outcome_badge(outcome: VerificationOutcome | str) -> str:
    """Formats a colored badge for the explicit verification outcome."""
    s = (getattr(outcome, "value", str(outcome)) or "").upper()
    if "." in s:
        s = s.split(".")[-1]
    s = s.replace(" ", "_")
    if s == "VERIFIED_CLEAN":
        return f"{Colors.GREEN}{Colors.BOLD}VERIFIED CLEAN{Colors.RESET}"
    if s == "PARTIALLY_CLEANED":
        return f"{Colors.YELLOW}{Colors.BOLD}PARTIALLY CLEANED{Colors.RESET}"
    if s == "SENSITIVE_DATA_REMAINS":
        return f"{Colors.RED}{Colors.BOLD}SENSITIVE DATA REMAINS{Colors.RESET}"
    return f"{Colors.MAGENTA}{Colors.BOLD}VERIFICATION FAILED{Colors.RESET}"


def confirm_prompt(prompt_message: str, assume_yes: bool = False) -> bool:
    """Interactive confirmation prompt for potentially destructive operations."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        reply = input(f"{Colors.YELLOW}{prompt_message} [y/N]: {Colors.RESET}").strip().lower()
        return reply in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\nOperation aborted by user.")
        return False


# =====================================================================
# Shared helpers
# =====================================================================
CATEGORY_LABELS: Dict[str, str] = {
    "gps": "GPS Location Data",
    "date": "Capture / Creation Timestamps",
    "device": "Camera & Device Information",
    "author": "Author & Personal Identity",
    "copyright": "Copyright & Licensing Terms",
    "comments": "Comments & Descriptions",
    "exif": "Technical Camera Settings (EXIF)",
    "iptc": "IPTC Application Record",
    "xmp": "XMP Metadata Block",
    "software": "Software / Editing Environment",
    "identifiers": "Unique Document Identifiers",
    "thumbnail": "Embedded Thumbnails / Previews",
    "makernotes": "Vendor MakerNotes",
    "informational": "Informational / Structural",
}

_RISK_ORDER = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFORMATIONAL,
)


def _category_label(key: str) -> str:
    return CATEGORY_LABELS.get(key, key.replace("_", " ").title())


def _scan_mode(args: argparse.Namespace) -> str:
    if getattr(args, "full", False):
        return "full"
    if getattr(args, "privacy", False):
        return "privacy"
    if getattr(args, "deep", False):
        return "deep"
    return "standard"


def _redact_requested(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "redact", True))


def _report_format(args: argparse.Namespace, default: str = "json") -> str:
    fmt = getattr(args, "format", None) or default
    return str(fmt).lower()


def _clear_sensitive_export(
    scan: Optional[ScanResult], args: argparse.Namespace, redact: bool
) -> bool:
    """Warns (and, on a TTY, asks) before exporting unredacted sensitive values."""
    if redact or scan is None or scan.privacy_report is None:
        return True
    sensitive = [i for i in scan.privacy_report.items if i.is_sensitive]
    if not sensitive:
        return True
    err(
        f"{Colors.YELLOW}[WARNING]{Colors.RESET} This report will contain "
        f"{len(sensitive)} unredacted sensitive metadata value(s): GPS coordinates, "
        "identity fields, timestamps, or device identifiers."
    )
    err(f"{Colors.DIM}Share the report only with people you trust. Use --redact to mask values.{Colors.RESET}")
    if getattr(args, "yes", False) or not sys.stdin.isatty():
        return True
    return confirm_prompt("Write an unredacted report containing sensitive values?")


def _confirm_unredacted_batch(args: argparse.Namespace) -> bool:
    """Warns (and, on a TTY, asks) before writing a batch report with identifiers."""
    if getattr(args, "redact", True):
        return True
    err(
        f"{Colors.YELLOW}[WARNING]{Colors.RESET} This batch report will contain unredacted "
        "file names, output paths, and per-file notes."
    )
    err(f"{Colors.DIM}Use --redact to export anonymised batch results.{Colors.RESET}")
    if getattr(args, "yes", False) or not sys.stdin.isatty():
        return True
    return confirm_prompt("Write an unredacted batch report?")


def _print_privacy_summary(scan: ScanResult, args: argparse.Namespace) -> None:
    pr = scan.privacy_report
    if pr is None:
        return
    out(f"\n{Colors.BOLD}Privacy Risk Assessment:{Colors.RESET} "
        f"{format_risk_badge(pr.overall_risk)} (Risk Score: {pr.risk_score}/100)")
    out(f"  {pr.summary_narrative}")

    if getattr(args, "detailed", False) or _VERBOSE:
        out(f"\n  {Colors.BOLD}Score calculation:{Colors.RESET}")
        for comp in pr.score_components:
            if comp.count:
                out(
                    f"    • {comp.count} x {comp.level} x {comp.weight_per_tag} = "
                    f"{comp.raw_contribution} (capped at {comp.capped_contribution})"
                )
        out(f"  {Colors.DIM}{pr.score_explanation}{Colors.RESET}")

    limit = None if getattr(args, "detailed", False) else 5
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
        items = [i for i in pr.items if i.risk_level == level]
        if not items:
            continue
        out(f"\n  {format_risk_badge(level)} Findings ({len(items)}):")
        shown = items if limit is None else items[:limit]
        for item in shown:
            out(f"    • {Colors.BOLD}{item.tag_name}{Colors.RESET} ({item.category}): {item.value_preview}")
            out(f"      {Colors.DIM}{item.explanation}{Colors.RESET}")
            if _VERBOSE and item.recommendation:
                out(f"      {Colors.DIM}Action: {item.recommendation}{Colors.RESET}")
        if limit is not None and len(items) > limit:
            out(f"    {Colors.DIM}... and {len(items) - limit} more (use --detailed){Colors.RESET}")

    if pr.recommendations and (getattr(args, "detailed", False) or _VERBOSE):
        out(f"\n  {Colors.BOLD}Recommendations:{Colors.RESET}")
        for rec in pr.recommendations:
            out(f"    • {rec}")


def _print_file_analysis(scan: ScanResult) -> None:
    analysis = scan.file_analysis
    if analysis is None:
        return
    out(f"\n{Colors.CYAN}{Colors.BOLD}--- File / Container Analysis ---{Colors.RESET}")
    out(
        f"  Container: {analysis.detected_format or 'unknown'} | MIME: {analysis.mime_type or 'unknown'} | "
        f"Extension matches: {'yes' if analysis.extension_matches else 'NO'}"
    )
    out(
        f"  Bit depth: {analysis.bit_depth if analysis.bit_depth is not None else 'n/a'} | "
        f"Colour model: {analysis.color_model or analysis.color_mode or 'n/a'} | "
        f"Frames: {analysis.n_frames}"
    )
    out(
        f"  ICC profile: {'present' if analysis.has_icc_profile else 'absent'} | "
        f"Trailing bytes: {analysis.trailing_data_bytes} | "
        f"End marker found: {analysis.end_marker_found}"
    )
    if analysis.structure_notes:
        for note in analysis.structure_notes:
            out(f"  {Colors.DIM}· {note}{Colors.RESET}")
    if analysis.findings:
        out(f"  {Colors.BOLD}Findings:{Colors.RESET}")
        for finding in analysis.findings:
            color = {
                "CONFIRMED": Colors.YELLOW,
                "SUSPICIOUS": Colors.MAGENTA,
                "INFORMATIONAL": Colors.CYAN,
            }.get(finding.kind.value, Colors.WHITE)
            out(f"    {color}[{finding.kind.value}]{Colors.RESET} {finding.title}: {finding.detail}")
    else:
        out(f"  {Colors.GREEN}No structural inconsistencies detected.{Colors.RESET}")


def _print_comparison(comparison: Any) -> None:
    if comparison is None:
        return
    out(f"\n{Colors.BOLD}Before / After Comparison:{Colors.RESET}")
    out(
        f"  Tags: {comparison.before_total} -> {comparison.after_total} "
        f"(removed {comparison.removed_count}, remaining {comparison.remaining_count}, "
        f"introduced {comparison.introduced_count})"
    )
    out(
        f"  Risk score: {comparison.before_risk_score}/100 -> {comparison.after_risk_score}/100 "
        f"({comparison.before_risk_level or 'n/a'} -> {comparison.after_risk_level or 'n/a'})"
    )
    out(
        f"  Sensitive tags: removed {comparison.sensitive_removed_count}, "
        f"remaining {comparison.sensitive_remaining_count}"
    )
    if comparison.sensitive_remaining and _VERBOSE:
        for item in comparison.sensitive_remaining[:10]:
            out(f"    • {item.tag_name} [{item.risk_level.value}]: {item.value_preview}")


def _outcome_exit_code(outcome: VerificationOutcome | str) -> int:
    value = (getattr(outcome, "value", str(outcome)) or "").upper()
    if value == VerificationOutcome.VERIFIED_CLEAN.value:
        return config.EXIT_SUCCESS
    if value == VerificationOutcome.PARTIALLY_CLEANED.value:
        return config.EXIT_WARNING
    return config.EXIT_FAIL


# =====================================================================
# Command: SCAN
# =====================================================================
def handle_scan(args: argparse.Namespace) -> int:
    """Executes the image scan command."""
    print_banner()
    image_path = Path(args.image)
    mode = _scan_mode(args)
    out(f"\n{Colors.BOLD}Target File:{Colors.RESET} {image_path}")
    out(f"{Colors.BOLD}Scan Mode:{Colors.RESET} {mode}")

    scanner = MetadataScanner()
    scan = scanner.scan(image_path, mode=mode)

    if not scan.validation.is_valid:
        err(f"\n{Colors.RED}{Colors.BOLD}[ERROR] Image Validation Failed:{Colors.RESET}")
        for error in scan.validation.errors:
            err(f"  • {error}")
        return config.EXIT_FAIL

    out(f"{Colors.BOLD}Format:{Colors.RESET} {scan.validation.format_name} | "
        f"{Colors.BOLD}Dimensions:{Colors.RESET} {scan.validation.dimensions[0]}x{scan.validation.dimensions[1]} | "
        f"{Colors.BOLD}Size:{Colors.RESET} {scan.validation.file_size:,} bytes")
    out(f"{Colors.BOLD}Backend:{Colors.RESET} {scan.scanner_backend}"
        + (f" {scan.backend_version}" if scan.backend_version else ""))

    if scan.validation.has_transparency:
        out(f"{Colors.CYAN}Transparency detected (alpha channel preserved).{Colors.RESET}")
    if scan.validation.is_animated:
        out(f"{Colors.CYAN}Animation detected ({scan.validation.n_frames} frames).{Colors.RESET}")

    out(f"\n{Colors.CYAN}{Colors.BOLD}--- Filesystem Attributes (Non-Embedded) ---{Colors.RESET}")
    out(f"  • Modified on disk: {scan.filesystem_metadata.get('fs_modified')}")
    out(f"  • Created on disk:  {scan.filesystem_metadata.get('fs_created')}")
    out(f"  • File size:        {scan.filesystem_metadata.get('file_size_bytes')} bytes")

    out(f"\n{Colors.BOLD}--- Embedded Metadata Scan ---{Colors.RESET}")
    detected = 0
    for cat_key, summary in scan.categories.items():
        if not summary.detected:
            if _VERBOSE:
                out(f"  - {_category_label(cat_key)}: {Colors.GREEN}NOT DETECTED{Colors.RESET}")
            continue
        detected += 1
        count = len(summary.tags)
        out(f"  • {_category_label(cat_key)}: {Colors.RED}{Colors.BOLD}DETECTED{Colors.RESET} "
            f"({count} tag{'s' if count != 1 else ''})")

        if cat_key == "gps" and scan.gps_coordinates:
            gps = scan.gps_coordinates
            out(f"      {Colors.DIM}|--{Colors.RESET} {Colors.GREEN}{Colors.BOLD}Coordinates:{Colors.RESET} "
                f"{gps.formatted} (Decimal: {gps.latitude:.6f}, {gps.longitude:.6f})")
            if gps.altitude:
                out(f"      {Colors.DIM}|--{Colors.RESET} {Colors.GREEN}{Colors.BOLD}Altitude:{Colors.RESET} {gps.altitude}")
            out(f"      {Colors.DIM}|--{Colors.RESET} {Colors.CYAN}{Colors.BOLD}Google Maps:{Colors.RESET} {gps.google_maps_url}")
            out(f"      {Colors.DIM}|--{Colors.RESET} {Colors.CYAN}{Colors.BOLD}OpenStreetMap:{Colors.RESET} {gps.openstreetmap_url}")

        max_display = len(summary.tags) if getattr(args, "detailed", False) else min(15, len(summary.tags))
        for i, tag in enumerate(summary.tags[:max_display]):
            val_str = str(tag.display_value if tag.display_value is not None else tag.value).strip()
            if len(val_str) > 80 and not getattr(args, "detailed", False):
                val_str = val_str[:77] + "..."
            branch = "\\--" if i == len(summary.tags[:max_display]) - 1 and len(summary.tags) <= max_display else "|--"
            out(f"      {Colors.DIM}{branch}{Colors.RESET} {Colors.CYAN}{tag.name}{Colors.RESET}: {val_str}")
        if len(summary.tags) > max_display:
            out(f"      {Colors.DIM}\\-- ... and {len(summary.tags) - max_display} more tags "
                f"(use --detailed){Colors.RESET}")

    if detected == 0:
        out(f"\n  {Colors.GREEN}No embedded metadata found. Image is clean.{Colors.RESET}")

    if _VERBOSE and scan.metadata_group_counts:
        out(f"\n{Colors.BOLD}Metadata groups:{Colors.RESET} " + ", ".join(
            f"{group}={count}" for group, count in sorted(scan.metadata_group_counts.items())
        ))
        out(f"{Colors.BOLD}Total embedded tags:{Colors.RESET} {scan.total_embedded_tags} "
            f"(empty: {scan.empty_tag_count})")

    _print_privacy_summary(scan, args)
    _print_file_analysis(scan)

    if scan.warnings:
        out(f"\n{Colors.YELLOW}{Colors.BOLD}Scanner Warnings:{Colors.RESET}")
        for warning in scan.warnings:
            out(f"  ! {warning}")
    if scan.limitations:
        out(f"\n{Colors.YELLOW}{Colors.BOLD}Inspection Limitations:{Colors.RESET}")
        for limitation in scan.limitations:
            out(f"  ! {limitation}")
    if scan.uninspected_categories and _VERBOSE:
        out(f"\n{Colors.DIM}Not exhaustively inspected: {', '.join(scan.uninspected_categories)}{Colors.RESET}")

    # Optional report export.
    explicit_report = getattr(args, "report", None)
    if explicit_report or getattr(args, "json", False):
        fmt = _report_format(args)
        report_path = (
            Path(explicit_report) if explicit_report
            else Path(f"{image_path.stem}_report.{fmt}")
        )
        redact = _redact_requested(args)
        if not _clear_sensitive_export(scan, args, redact):
            out("Report export cancelled.")
        else:
            saved = export_report(report_path, fmt, scan=scan, redact=redact)
            mode_note = "REDACTED" if redact else "UNREDACTED"
            out(f"\n{Colors.GREEN}{fmt.upper()} scan report ({mode_note}) written to: {saved}{Colors.RESET}")

    pr = scan.privacy_report
    if getattr(args, "fail_on_risk", False) and pr and pr.overall_risk.priority >= RiskLevel.HIGH.priority:
        return config.EXIT_WARNING
    return config.EXIT_SUCCESS


# =====================================================================
# Command: CLEAN
# =====================================================================
def handle_clean(args: argparse.Namespace) -> int:
    """Executes metadata removal and automated independent verification."""
    print_banner()
    in_path = Path(args.image)
    out_path = Path(args.output) if getattr(args, "output", None) else (
        in_path.parent / f"{in_path.stem}_clean{in_path.suffix}"
    )

    out(f"\n{Colors.BOLD}Input File:{Colors.RESET}  {in_path}")
    out(f"{Colors.BOLD}Output File:{Colors.RESET} {out_path}")

    if out_path.exists() and not getattr(args, "yes", False):
        if not confirm_prompt(f"Output file '{out_path.name}' already exists. Overwrite?"):
            out("Operation cancelled.")
            return config.EXIT_USAGE_ERROR

    profile_name = getattr(args, "profile", None)
    raw_cats = getattr(args, "remove", None)

    if profile_name:
        profile_obj = get_profile(profile_name)
        if profile_obj is None:
            err(f"{Colors.RED}[ERROR] Unknown profile '{profile_name}'. "
                f"Available: {', '.join(PROFILES)}{Colors.RESET}")
            return config.EXIT_USAGE_ERROR
        if profile_obj.key == "custom":
            if not raw_cats:
                err(f"{Colors.RED}[ERROR] The 'custom' profile requires explicit --remove categories.{Colors.RESET}")
                return config.EXIT_USAGE_ERROR
            valid_cats, invalid_cats = validate_categories(raw_cats)
        else:
            valid_cats, invalid_cats = list(profile_obj.categories), []
        out(f"\n{Colors.BOLD}Profile:{Colors.RESET} {profile_obj.name} ({profile_obj.key})")
        out(f"  {profile_obj.description}")
        if profile_obj.note:
            out(f"  {Colors.DIM}{profile_obj.note}{Colors.RESET}")
    else:
        valid_cats, invalid_cats = validate_categories(raw_cats or "all")
        out(f"\n{Colors.BOLD}Profile:{Colors.RESET} custom (explicit categories)")

    if invalid_cats:
        err(f"{Colors.RED}[ERROR] Invalid categories specified: {', '.join(invalid_cats)}{Colors.RESET}")
        err(f"Supported categories: {', '.join(config.METADATA_CATEGORIES.keys())}")
        return config.EXIT_USAGE_ERROR

    if not valid_cats:
        err(f"{Colors.RED}[ERROR] No valid categories specified for removal.{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    out(f"{Colors.BOLD}Requested Removal:{Colors.RESET} {', '.join(valid_cats)}")
    if "all" not in valid_cats:
        out(f"{Colors.YELLOW}[WARNING] Selective removal active. "
            f"Unselected categories may retain identifying information!{Colors.RESET}")

    remover = MetadataRemover()
    out(f"\n{Colors.CYAN}Sanitizing image metadata...{Colors.RESET}")
    removal = remover.clean(
        input_path=in_path,
        output_path=out_path,
        categories=valid_cats,
        overwrite_output=True,
        profile=profile_name,
    )

    if not removal.success:
        err(f"\n{Colors.RED}{Colors.BOLD}[FAILED] Metadata removal encountered errors:{Colors.RESET}")
        for error in removal.errors:
            err(f"  • {error}")
        return config.EXIT_FAIL

    out(f"{Colors.GREEN}Action: Metadata removal completed successfully.{Colors.RESET}")
    out(f"  • Engine: {removal.method_used}")
    out(f"  • Output validated: {'yes' if removal.output_validated else 'no'}")
    if removal.tags_updated_count is not None:
        out(f"  • Tags updated: {removal.tags_updated_count}")
    out(f"  • Cleaned file: {out_path} ({removal.cleaned_size:,} bytes, "
        f"{removal.bytes_saved:,} bytes stripped)")
    for warning in removal.warnings:
        out(f"  {Colors.YELLOW}! {warning}{Colors.RESET}")

    out(f"\n{Colors.CYAN}Executing independent verification of the cleaned image...{Colors.RESET}")
    verifier = MetadataVerifier()
    verification = verifier.verify(
        image_path=out_path,
        targeted_categories=valid_cats,
        original_image_path=in_path,
        profile=profile_name,
        scan_mode=_scan_mode(args),
    )

    out(f"\n{Colors.BOLD}Category Checks:{Colors.RESET}")
    for check in verification.category_checks:
        if check.status == VerificationStatus.PASS:
            out(f"  • {check.category}: {Colors.GREEN}NOT DETECTED{Colors.RESET}")
        else:
            out(f"  • {check.category}: {Colors.RED}DETECTED ({len(check.found_tags)} tags){Colors.RESET}")

    _print_comparison(verification.comparison)

    if verification.remaining_sensitive_tags:
        out(f"\n{Colors.YELLOW}{Colors.BOLD}Remaining Sensitive Tags "
            f"({len(verification.remaining_sensitive_tags)}):{Colors.RESET}")
        for item in verification.remaining_sensitive_tags[:15]:
            out(f"  • [{item.risk_level.value}] {item.tag_name}: {item.value_preview}")

    out(f"\n{Colors.BOLD}Final Outcome:{Colors.RESET} {format_outcome_badge(verification.outcome)}")
    out(f"  Legacy status: {format_status_badge(verification.status)}")
    out(f"  {verification.outcome_reason}")
    if _VERBOSE:
        out(f"  {Colors.DIM}{verification.summary_message}{Colors.RESET}")
    for limitation in verification.limitations:
        verbose(f"  ! {limitation}")

    report_path = getattr(args, "report", None)
    if report_path:
        fmt = _report_format(args)
        redact = _redact_requested(args)
        if not _clear_sensitive_export(verification.scan_result, args, redact):
            out("Report export cancelled.")
        else:
            saved = export_report(
                report_path,
                fmt,
                scan=verification.scan_result or MetadataScanner().scan(out_path),
                removal=removal,
                verification=verification,
                redact=redact,
            )
            mode_note = "REDACTED" if redact else "UNREDACTED"
            out(f"{Colors.GREEN}{fmt.upper()} processing report ({mode_note}) saved to: {saved}{Colors.RESET}")

    return _outcome_exit_code(verification.outcome)


# =====================================================================
# Command: VERIFY
# =====================================================================
def handle_verify(args: argparse.Namespace) -> int:
    """Executes independent verification on an image."""
    print_banner()
    image_path = Path(args.image)
    mode = _scan_mode(args)
    profile_name = getattr(args, "profile", None)
    out(f"\n{Colors.BOLD}Verifying Image:{Colors.RESET} {image_path}")
    out(f"{Colors.BOLD}Scan Mode:{Colors.RESET} {mode}")

    targets = getattr(args, "targets", None) or "all"
    valid_targets, invalid_targets = validate_categories(targets)
    if invalid_targets:
        err(f"{Colors.RED}[ERROR] Invalid target category name(s): {', '.join(invalid_targets)}{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    if profile_name and get_profile(profile_name) is None:
        err(f"{Colors.RED}[ERROR] Unknown profile '{profile_name}'. "
            f"Available: {', '.join(PROFILES)}{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    if profile_name == "custom" and targets == "all":
        err(f"{Colors.RED}[ERROR] The 'custom' profile requires explicit --targets "
            f"categories for verification.{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    verifier = MetadataVerifier()
    report = verifier.verify(
        image_path=image_path,
        targeted_categories=valid_targets,
        original_image_path=getattr(args, "original", None),
        profile=profile_name,
        scan_mode=mode,
    )

    if report.status == VerificationStatus.FAIL and not report.scan_result:
        err(f"{Colors.RED}[FAIL] {report.summary_message}{Colors.RESET}")
        return config.EXIT_FAIL

    if profile_name:
        out(f"{Colors.BOLD}Profile:{Colors.RESET} {profile_name}")

    out(f"\n{Colors.BOLD}Category Checks:{Colors.RESET}")
    for check in report.category_checks:
        badge = (
            Colors.GREEN + "CLEAN" + Colors.RESET
            if check.status == VerificationStatus.PASS
            else Colors.RED + "REMAINING" + Colors.RESET
        )
        out(f"  • [{badge}] Category '{check.category}': {len(check.found_tags)} tags found")
        if check.found_tags and _VERBOSE:
            for tag in check.found_tags[:5]:
                out(f"      - {tag}")

    if report.remaining_sensitive_tags:
        out(f"\n{Colors.YELLOW}{Colors.BOLD}Sensitive Metadata Remnants "
            f"({len(report.remaining_sensitive_tags)}):{Colors.RESET}")
        for item in report.remaining_sensitive_tags[:15]:
            out(f"  • [{item.risk_level.value}] {item.tag_name}: {item.value_preview}")

    _print_comparison(report.comparison)

    if report.limitations:
        out(f"\n{Colors.MAGENTA}{Colors.BOLD}Verification Limitations:{Colors.RESET}")
        for limitation in report.limitations:
            out(f"  ! {limitation}")

    out(f"\n{Colors.BOLD}Final Verification Outcome:{Colors.RESET} {format_outcome_badge(report.outcome)}")
    out(f"  {report.outcome_reason}")
    out(f"  Legacy status: {format_status_badge(report.status)}")

    explicit_report = getattr(args, "report", None)
    if explicit_report or getattr(args, "json", False):
        fmt = _report_format(args)
        report_path = (
            Path(explicit_report) if explicit_report
            else Path(f"{image_path.stem}_verification.{fmt}")
        )
        redact = _redact_requested(args)
        if not _clear_sensitive_export(report.scan_result, args, redact):
            out("Report export cancelled.")
        else:
            saved = export_report(
                report_path,
                fmt,
                scan=report.scan_result or MetadataScanner().scan(image_path, mode=mode),
                verification=report,
                redact=redact,
            )
            mode_note = "REDACTED" if redact else "UNREDACTED"
            out(f"\n{Colors.GREEN}{fmt.upper()} verification report ({mode_note}) written to: {saved}{Colors.RESET}")

    return _outcome_exit_code(report.outcome)


# =====================================================================
# Command: BATCH
# =====================================================================
def _batch_records(summary: BatchSummary) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for r in summary.file_results:
        records.append({
            "file_name": r.input_path.name,
            "validation": r.validation_status,
            "format": r.format_name,
            "original_size": r.original_size,
            "cleaned_size": r.cleaned_size,
            "bytes_saved": max(0, r.original_size - r.cleaned_size),
            "privacy_risk": r.privacy_risk,
            "risk_score": r.risk_score,
            "gps_detected": r.gps_detected,
            "author_detected": r.author_detected,
            "date_detected": r.date_detected,
            "removal_status": r.removal_status,
            "verification_status": r.verification_status,
            "verification_outcome": r.verification_outcome,
            "output_path": str(r.output_path) if r.output_path else "",
            "notes": r.error_message or ("duplicate of " + str(r.duplicate_of) if r.duplicate_of else ""),
        })
    return records


def _batch_summary_dict(summary: BatchSummary) -> Dict[str, Any]:
    return {
        "total": summary.total_found,
        "success": summary.success_count,
        "failed": summary.failure_count,
        "verified_clean": summary.verified_clean_count,
        "partially_cleaned": summary.partially_cleaned_count,
        "sensitive_remaining": summary.sensitive_remaining_count,
        "verification_failed": summary.verification_failed_count,
        "skipped_duplicates": summary.skipped_duplicates,
        "skipped_symlinks": summary.skipped_symlinks,
        "total_tags": summary.total_tags,
        "total_sensitive_tags": summary.total_sensitive_tags,
        "bytes_saved": summary.total_bytes_saved,
        "scan_only": summary.scan_only,
    }


def handle_batch(args: argparse.Namespace) -> int:
    """Executes batch scanning or sanitization across a directory."""
    print_banner()
    in_dir = Path(args.input_dir)
    scan_only = bool(getattr(args, "scan_only", False))
    out_dir_val = getattr(args, "output_dir", None)
    out_dir = Path(out_dir_val) if out_dir_val else None

    if not scan_only and out_dir is None:
        err(f"{Colors.RED}[ERROR] --output-dir is required unless --scan-only is used.{Colors.RESET}")
        return config.EXIT_USAGE_ERROR
    if not in_dir.is_dir():
        err(f"{Colors.RED}[ERROR] Input path is not a directory: {in_dir}{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    out(f"\n{Colors.BOLD}Batch Input Directory:{Colors.RESET}  {in_dir}")
    if scan_only:
        out(f"{Colors.BOLD}Mode:{Colors.RESET} scan-only (no files will be written)")
    else:
        out(f"{Colors.BOLD}Batch Output Directory:{Colors.RESET} {out_dir}")

    profile_name = getattr(args, "profile", None)
    if profile_name:
        profile_obj = get_profile(profile_name)
        if profile_obj is None:
            err(f"{Colors.RED}[ERROR] Unknown profile '{profile_name}'. "
                f"Available: {', '.join(PROFILES)}{Colors.RESET}")
            return config.EXIT_USAGE_ERROR
        if profile_obj.key == "custom" and not getattr(args, "remove", None):
            err(f"{Colors.RED}[ERROR] The 'custom' profile requires explicit --remove categories.{Colors.RESET}")
            return config.EXIT_USAGE_ERROR
        out(f"{Colors.BOLD}Profile:{Colors.RESET} {profile_obj.name} ({profile_obj.key})")

    if not getattr(args, "yes", False) and not scan_only:
        action = f"Process all images in '{in_dir}' and save to '{out_dir}'?"
        if not confirm_prompt(action):
            out("Operation aborted.")
            return config.EXIT_USAGE_ERROR

    # Batch summaries are redacted by default; unredacted export is opt-in and
    # confirmed here rather than after a long cleaning run.
    if not _confirm_unredacted_batch(args):
        out("Batch report export cancelled.")
        return config.EXIT_USAGE_ERROR
    redact = _redact_requested(args)

    processor = BatchProcessor()

    def progress_callback(item: BatchFileResult, current: int, total: int) -> None:
        if _QUIET:
            return
        if item.skipped:
            status = f"{Colors.DIM}SKIPPED (duplicate){Colors.RESET}"
        elif item.success:
            status = Colors.GREEN + item.verification_outcome + Colors.RESET
        else:
            status = Colors.RED + (item.verification_outcome or "FAILED") + Colors.RESET
        target = item.output_path.name if item.output_path else "—"
        print(
            f"[{current}/{total}] {item.input_path.name} -> {target}: {status} "
            f"({item.format_name}, risk {item.privacy_risk}/{item.risk_score}, "
            f"{item.original_size:,}B -> {item.cleaned_size:,}B)"
        )
        if item.error_message:
            print(f"    {Colors.RED}Error: {item.error_message}{Colors.RESET}")

    out(f"\n{Colors.CYAN}Starting batch processing...{Colors.RESET}\n")
    try:
        summary = processor.process_batch(
            input_dir=in_dir,
            output_dir=out_dir,
            categories=getattr(args, "remove", None) or "all",
            overwrite=getattr(args, "yes", False),
            recursive=getattr(args, "recursive", False),
            progress_callback=progress_callback,
            scan_only=scan_only,
            skip_duplicates=getattr(args, "skip_duplicates", False),
            follow_symlinks=getattr(args, "follow_symlinks", False),
            scan_mode=_scan_mode(args),
            profile=profile_name,
            max_files=getattr(args, "max_files", None),
        )
    except (ValueError, NotADirectoryError, OSError) as exc:
        err(f"{Colors.RED}[ERROR] {exc}{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    out(f"\n{Colors.BOLD}Batch Summary:{Colors.RESET}")
    out(f"  • Total images discovered: {summary.total_found}")
    out(f"  • Successfully processed:  {Colors.GREEN}{summary.success_count}{Colors.RESET}")
    out(f"  • Failed / corrupted:      {Colors.RED if summary.failure_count else Colors.GREEN}{summary.failure_count}{Colors.RESET}")
    out(f"  • Verified clean:          {Colors.GREEN}{summary.verified_clean_count}{Colors.RESET}")
    out(f"  • Partially cleaned:       {Colors.YELLOW}{summary.partially_cleaned_count}{Colors.RESET}")
    out(f"  • Sensitive data remains:  {Colors.RED}{summary.sensitive_remaining_count}{Colors.RESET}")
    out(f"  • Verification failed:     {summary.verification_failed_count}")
    out(f"  • Skipped duplicates:      {summary.skipped_duplicates}")
    out(f"  • Skipped symlinks:        {summary.skipped_symlinks}")
    out(f"  • Total metadata tags:     {summary.total_tags} (sensitive: {summary.total_sensitive_tags})")
    out(f"  • Total bytes stripped:    {summary.total_bytes_saved:,} bytes")

    fmt = _report_format(args, default="csv")
    explicit_report = getattr(args, "report", None)
    if explicit_report:
        report_path = Path(explicit_report)
    else:
        base_dir = out_dir if out_dir else Path.cwd()
        report_path = base_dir / f"batch_summary.{fmt}"

    saved = export_batch_report(
        _batch_records(summary),
        report_path,
        report_format=fmt,
        summary=_batch_summary_dict(summary),
        redact=redact,
    )
    mode_note = "REDACTED" if redact else "UNREDACTED"
    out(f"\n{Colors.GREEN}Batch summary exported to {fmt.upper()} ({mode_note}): {saved}{Colors.RESET}")

    if summary.failure_count or summary.sensitive_remaining_count:
        return config.EXIT_WARNING
    if summary.processed_count == 0 and summary.total_found > 0:
        return config.EXIT_WARNING
    return config.EXIT_SUCCESS


# =====================================================================
# Command: REPORT
# =====================================================================
def handle_report(args: argparse.Namespace) -> int:
    """Generates a detailed security and privacy report for an image."""
    print_banner()
    in_path = Path(args.image)
    out_file = Path(args.output)
    fmt = _report_format(args)
    mode = _scan_mode(args)

    out(f"\nGenerating security and privacy report for: {in_path}")
    out(f"{Colors.BOLD}Format:{Colors.RESET} {fmt} | {Colors.BOLD}Scan mode:{Colors.RESET} {mode}")

    scanner = MetadataScanner()
    scan = scanner.scan(in_path, mode=mode)
    if not scan.validation.is_valid:
        err(f"{Colors.RED}[ERROR] Image validation failed: {'; '.join(scan.validation.errors)}{Colors.RESET}")
        return config.EXIT_FAIL

    verification = None
    removed = None
    cleaned = getattr(args, "cleaned", None)
    if cleaned:
        profile_name = getattr(args, "profile", None)
        verifier = MetadataVerifier(scanner=scanner)
        verification = verifier.verify(
            cleaned,
            original_image_path=in_path,
            profile=profile_name,
            scan_mode=mode,
        )
        removed = None

    redact = _redact_requested(args)
    if not _clear_sensitive_export(scan, args, redact):
        out("Report generation cancelled.")
        return config.EXIT_USAGE_ERROR

    saved = export_report(
        out_file,
        fmt,
        scan=scan,
        removal=removed,
        verification=verification,
        redact=redact,
    )
    mode_note = "REDACTED" if redact else "UNREDACTED"
    out(f"{Colors.GREEN}Comprehensive {fmt.upper()} report ({mode_note}) written to: {saved}{Colors.RESET}")
    if verification:
        out(f"Verification outcome: {format_outcome_badge(verification.outcome)}")
    return config.EXIT_SUCCESS


# =====================================================================
# Command: INFO
# =====================================================================
def handle_info(args: argparse.Namespace) -> int:
    """Prints tool, backend, profile, category, and exit-code information."""
    profiles = describe_profiles()
    info: Dict[str, Any] = {
        "name": config.APP_NAME,
        "version": config.APP_VERSION,
        "description": config.APP_DESCRIPTION,
        "exiftool_available": config.EXIFTOOL_AVAILABLE,
        "exiftool_path": config.EXIFTOOL_PATH,
        "exiftool_version": config.EXIFTOOL_VERSION,
        "supported_extensions": sorted(config.SUPPORTED_EXTENSIONS),
        "scan_modes": list(config.SCAN_MODES),
        "categories": {
            key: {"description": value.get("description")}
            for key, value in config.METADATA_CATEGORIES.items()
        },
        "profiles": profiles,
        "privacy_levels": [
            {
                "level": level.value,
                "weight_per_tag": RuleBasedPrivacyAnalyzer.LEVEL_WEIGHTS[level],
                "cap": RuleBasedPrivacyAnalyzer.LEVEL_CAPS[level],
            }
            for level in (
                RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
                RiskLevel.LOW, RiskLevel.INFORMATIONAL,
            )
        ],
        "exit_codes": {
            "0": "success / verified clean",
            "1": "warning / partially cleaned / risk threshold reached",
            "2": "failure / sensitive data remains / invalid input",
            "3": "usage error",
        },
        "methodology_note": (
            "Privacy scores are additive heuristics with fixed weights and caps; "
            "they are explanatory, not a validated scientific metric."
        ),
    }

    if getattr(args, "json", False):
        import json
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return config.EXIT_SUCCESS

    print_banner()
    out(f"\n{Colors.BOLD}Version:{Colors.RESET} {config.APP_NAME} {config.APP_VERSION}")
    out(f"{Colors.BOLD}Description:{Colors.RESET} {config.APP_DESCRIPTION}")
    backend = (
        f"ExifTool {config.EXIFTOOL_VERSION} ({config.EXIFTOOL_PATH})"
        if config.EXIFTOOL_AVAILABLE
        else "Pillow fallback (ExifTool not found)"
    )
    out(f"{Colors.BOLD}Backend:{Colors.RESET} {backend}")
    out(f"{Colors.BOLD}Supported formats:{Colors.RESET} {', '.join(sorted(config.SUPPORTED_EXTENSIONS))}")

    out(f"\n{Colors.BOLD}Scan modes:{Colors.RESET}")
    for mode in config.SCAN_MODES:
        out(f"  • {mode:<9} {config.SCAN_MODE_DESCRIPTIONS.get(mode, '')}")

    out(f"\n{Colors.BOLD}Sanitization profiles:{Colors.RESET}")
    for profile in profiles:
        categories = ", ".join(profile["categories"]) if profile["categories"] else "(custom --remove)"
        out(f"  • {profile['key']:<9} {profile['name']}")
        out(f"      {profile['description']}")
        out(f"      Categories: {categories}")
        if profile.get("note"):
            out(f"      {Colors.DIM}{profile['note']}{Colors.RESET}")

    out(f"\n{Colors.BOLD}Privacy levels (heuristic score):{Colors.RESET}")
    for entry in info["privacy_levels"]:
        out(f"  • {entry['level']:<14} weight {entry['weight_per_tag']}/tag, capped at {entry['cap']}")

    out(f"\n{Colors.BOLD}Metadata categories:{Colors.RESET}")
    for key, value in config.METADATA_CATEGORIES.items():
        out(f"  • {key:<12} {value.get('description', '')}")

    out(f"\n{Colors.BOLD}Exit codes:{Colors.RESET}")
    for code, meaning in info["exit_codes"].items():
        out(f"  • {code}: {meaning}")

    out(f"\n{Colors.DIM}{info['methodology_note']}{Colors.RESET}")
    return config.EXIT_SUCCESS


# =====================================================================
# Main Argument Parser
# =====================================================================
class _Parser(argparse.ArgumentParser):
    """ArgumentParser that maps usage errors to MetaClean's exit-code contract."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        err(f"{self.prog}: error: {message}")
        err(f"Use '{self.prog} --help' for usage.")
        raise SystemExit(config.EXIT_USAGE_ERROR)


def _common_parent() -> argparse.ArgumentParser:
    """Global flags accepted both before and after the subcommand."""
    parent = _Parser(add_help=False)
    # SUPPRESS prevents subparser defaults from overwriting values parsed before
    # the subcommand.
    parent.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
                        help="Show additional diagnostic detail.")
    parent.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="Suppress informational output (errors still go to stderr).")
    parent.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="Disable ANSI colors.")
    return parent


def _add_scan_mode_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--deep",
        action="store_true",
        help=config.SCAN_MODE_DESCRIPTIONS.get(
            "deep", "Deep extraction: structured XMP/IPTC, raw values, container analysis."
        ),
    )
    group.add_argument(
        "--privacy",
        action="store_true",
        help=config.SCAN_MODE_DESCRIPTIONS.get(
            "privacy", "Privacy-focused deep extraction and reporting."
        ),
    )
    group.add_argument(
        "--full",
        action="store_true",
        help=config.SCAN_MODE_DESCRIPTIONS.get(
            "full", "Exhaustive extraction including embedded files (-ee)."
        ),
    )


def _add_redaction_flags(parser: argparse.ArgumentParser) -> None:
    """Adds the redact/no-redact pair shared by every report-producing command."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--redact", dest="redact", action="store_true",
                       help="Mask sensitive values in exported reports (default).")
    group.add_argument("--no-redact", dest="redact", action="store_false",
                       help="Export report values unredacted (requires confirmation on a TTY).")
    parser.set_defaults(redact=True)


def _add_report_flags(
    parser: argparse.ArgumentParser,
    formats: tuple[str, ...] = ("json", "html", "csv"),
) -> None:
    _add_redaction_flags(parser)
    parser.add_argument("--format", choices=list(formats), default=None,
                        help="Report format (default: json, or csv for batch).")


def build_parser() -> argparse.ArgumentParser:
    """Builds the top-level CLI argument parser."""
    common = _common_parent()
    parser = _Parser(
        prog="metaclean",
        description=f"{config.APP_NAME} — Image Metadata Intelligence, Privacy Analysis & Sanitization.",
        epilog="Academic Graduation Project in Cybersecurity | Designed for Linux Mint & POSIX Terminals.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show additional diagnostic detail.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.add_argument("-V", "--version", action="version",
                        version=f"{config.APP_NAME} {config.APP_VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: SCAN
    scan_p = subparsers.add_parser(
        "scan", parents=[common],
        help="Scan an image and inspect metadata with privacy risk classification.",
    )
    scan_p.add_argument("image", help="Path to the image file to scan.")
    _add_scan_mode_flags(scan_p)
    scan_p.add_argument("--json", action="store_true",
                        help="Export scan results to a JSON report (legacy alias).")
    scan_p.add_argument("--report", help="Write a report to this path (format from --format).")
    scan_p.add_argument("--detailed", action="store_true", help="Print every tag and finding.")
    scan_p.add_argument("--fail-on-risk", action="store_true",
                        help="Exit with code 1 when HIGH or CRITICAL risk is detected.")
    scan_p.add_argument("--yes", "-y", action="store_true",
                        help="Do not prompt before exporting unredacted sensitive values.")
    _add_report_flags(scan_p)

    # Command: CLEAN
    clean_p = subparsers.add_parser(
        "clean", parents=[common],
        help="Remove all or selective metadata categories to a new copy.",
    )
    clean_p.add_argument("image", help="Path to original input image (preserved untouched).")
    clean_p.add_argument("--output", "-o", default=None,
                         help="Path to save the cleaned copy (default: <name>_clean.<ext>).")
    clean_p.add_argument("--remove", "-r", default="all",
                         help="Categories to remove when no profile is used (default: all).")
    clean_p.add_argument("--profile", choices=list(PROFILES), default=None,
                         help="Sanitization profile: basic, location, personal, maximum, custom.")
    _add_scan_mode_flags(clean_p)
    clean_p.add_argument("--yes", "-y", action="store_true",
                         help="Overwrite existing output and skip confirmations.")
    clean_p.add_argument("--report", help="Optional path for a detailed processing/audit report.")
    _add_report_flags(clean_p)

    # Command: VERIFY
    verify_p = subparsers.add_parser(
        "verify", parents=[common],
        help="Independently verify an image's metadata status.",
    )
    verify_p.add_argument("image", help="Path to the image to verify.")
    verify_p.add_argument("--targets", "-t", default="all",
                          help="Categories targeted for verification (default: all).")
    verify_p.add_argument("--original", help="Optional original image path for before/after diffing.")
    verify_p.add_argument("--profile", choices=list(PROFILES), default=None,
                          help="Verify against the expectations of a sanitization profile.")
    _add_scan_mode_flags(verify_p)
    verify_p.add_argument("--json", action="store_true",
                          help="Write verification results to a JSON file (legacy alias).")
    verify_p.add_argument("--report", help="Write a verification report to this path.")
    verify_p.add_argument("--yes", "-y", action="store_true",
                          help="Do not prompt before exporting unredacted sensitive values.")
    _add_report_flags(verify_p)

    # Command: BATCH
    batch_p = subparsers.add_parser(
        "batch", parents=[common],
        help="Batch scan or sanitize multiple images in a directory.",
    )
    batch_p.add_argument("input_dir", help="Directory containing source images.")
    batch_p.add_argument("--output-dir", "-o", default=None,
                         help="Destination directory for cleaned images (not needed with --scan-only).")
    batch_p.add_argument("--remove", "-r", default="all", help="Categories to remove (default: all).")
    batch_p.add_argument("--profile", choices=list(PROFILES), default=None,
                         help="Sanitization profile to apply to every file.")
    batch_p.add_argument("--scan-only", action="store_true",
                         help="Scan and report only; write no cleaned files.")
    batch_p.add_argument("--skip-duplicates", action="store_true",
                         help="Skip files whose SHA-256 content hash was already processed.")
    batch_p.add_argument("--follow-symlinks", action="store_true",
                         help="Follow symbolic links (disabled by default for safety).")
    batch_p.add_argument("--max-files", type=int, default=None,
                         help="Maximum number of files to process (default: configuration limit).")
    _add_scan_mode_flags(batch_p)
    batch_p.add_argument("--format", choices=["csv", "json", "html"], default="csv",
                         help="Batch summary format (default: csv).")
    batch_p.add_argument("--report", help="Path to save the batch summary report.")
    _add_redaction_flags(batch_p)
    batch_p.add_argument("--recursive", action="store_true", help="Recursively process subdirectories.")
    batch_p.add_argument("--yes", "-y", action="store_true",
                         help="Confirm operations without interactive prompts.")

    # Command: REPORT
    rep_p = subparsers.add_parser(
        "report", parents=[common],
        help="Generate an in-depth security and privacy audit report.",
    )
    rep_p.add_argument("image", help="Target image to audit.")
    rep_p.add_argument("--output", "-o", required=True, help="Destination file path for the report.")
    rep_p.add_argument("--cleaned", help="Optional cleaned image to verify against the original.")
    rep_p.add_argument("--profile", choices=list(PROFILES), default=None,
                       help="Profile to assume when verifying --cleaned.")
    _add_scan_mode_flags(rep_p)
    rep_p.add_argument("--yes", "-y", action="store_true",
                       help="Do not prompt before exporting unredacted sensitive values.")
    _add_report_flags(rep_p)

    # Command: INFO
    info_p = subparsers.add_parser(
        "info", parents=[common],
        help="Show version, backend, scan modes, profiles, categories, and exit codes.",
    )
    info_p.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    return parser


def interactive_menu() -> int:
    """Friendly interactive CLI wizard with menu choices and drag & drop support."""
    print_banner()
    while True:
        out(f"\n{Colors.BOLD}{Colors.CYAN}================== MetaClean Easy Menu =================={Colors.RESET}")
        out(f"  {Colors.BOLD}[1]{Colors.RESET} Scan an Image           (فحص صورة وعرض بياناتها وموقعها الجغرافي)")
        out(f"  {Colors.BOLD}[2]{Colors.RESET} Clean an Image          (حذف الميتاداتا وحماية الخصوصية)")
        out(f"  {Colors.BOLD}[3]{Colors.RESET} Verify an Image         (التحقق المستقل من نظافة الصورة)")
        out(f"  {Colors.BOLD}[4]{Colors.RESET} Batch Clean a Folder    (تنظيف مجلد كامل دفعة واحدة)")
        out(f"  {Colors.BOLD}[5]{Colors.RESET} Generate Security Report(إنشاء تقرير أمني شامل)")
        out(f"  {Colors.BOLD}[6]{Colors.RESET} Tool Information        (معلومات الأداة والملفات الشخصية)")
        out(f"  {Colors.BOLD}[0]{Colors.RESET} Exit                    (خروج)")
        out(f"{Colors.BOLD}{Colors.CYAN}========================================================={Colors.RESET}")

        try:
            choice = input(f"\n{Colors.YELLOW}Enter your choice [0-6]: {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            return config.EXIT_SUCCESS

        if choice in ("0", "exit", "q", "quit"):
            print("Exiting MetaClean. Stay safe!")
            return config.EXIT_SUCCESS

        elif choice == "1":
            try:
                raw_path = input(f"{Colors.CYAN}Drag & drop your image here (or type path): {Colors.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            path_str = raw_path.strip("'\"")
            if not path_str:
                continue
            ns = argparse.Namespace(image=path_str, json=False, detailed=False)
            handle_scan(ns)

            if Path(path_str).exists():
                try:
                    do_clean = input(
                        f"\n{Colors.YELLOW}Would you like to clean and remove metadata "
                        f"from this image now? [Y/n]: {Colors.RESET}"
                    ).strip().lower()
                    if do_clean in ("", "y", "yes"):
                        clean_ns = argparse.Namespace(
                            image=path_str,
                            output=None,
                            remove="all",
                            profile="maximum",
                            yes=True,
                            report=None,
                        )
                        handle_clean(clean_ns)
                except (KeyboardInterrupt, EOFError):
                    pass

        elif choice == "2":
            try:
                raw_path = input(f"{Colors.CYAN}Enter or drag & drop image to clean: {Colors.RESET}").strip()
                path_str = raw_path.strip("'\"")
                if not path_str:
                    continue
                raw_out = input(
                    f"{Colors.CYAN}Output path [Press Enter for automatic naming]: {Colors.RESET}"
                ).strip().strip("'\"")
                out_val = raw_out if raw_out else None
                raw_profile = input(
                    f"{Colors.CYAN}Profile [basic/location/personal/maximum/custom, "
                    f"Enter for maximum]: {Colors.RESET}"
                ).strip().lower()
                profile_val = raw_profile if raw_profile in PROFILES else "maximum"
                rem_val = "all"
                if profile_val == "custom":
                    raw_rem = input(
                        f"{Colors.CYAN}Categories to remove "
                        f"(comma-separated): {Colors.RESET}"
                    ).strip()
                    rem_val = raw_rem if raw_rem else "all"
            except (KeyboardInterrupt, EOFError):
                continue

            clean_ns = argparse.Namespace(
                image=path_str,
                output=out_val,
                remove=rem_val,
                profile=profile_val,
                yes=True,
                report=None,
            )
            handle_clean(clean_ns)

        elif choice == "3":
            try:
                raw_path = input(f"{Colors.CYAN}Enter or drag & drop image to verify: {Colors.RESET}").strip()
                path_str = raw_path.strip("'\"")
                if not path_str:
                    continue
                raw_profile = input(
                    f"{Colors.CYAN}Profile expectation [Enter for all categories]: {Colors.RESET}"
                ).strip().lower()
                profile_val = raw_profile if raw_profile in PROFILES else None
            except (KeyboardInterrupt, EOFError):
                continue

            v_ns = argparse.Namespace(
                image=path_str, targets="all", original=None,
                json=False, profile=profile_val,
            )
            handle_verify(v_ns)

        elif choice == "4":
            try:
                raw_in = input(f"{Colors.CYAN}Enter folder containing images: {Colors.RESET}").strip().strip("'\"")
                if not raw_in:
                    continue
                raw_out = input(
                    f"{Colors.CYAN}Destination folder [Press Enter for 'cleaned_images']: {Colors.RESET}"
                ).strip().strip("'\"")
                out_val = raw_out if raw_out else "cleaned_images"
            except (KeyboardInterrupt, EOFError):
                continue

            b_ns = argparse.Namespace(
                input_dir=raw_in,
                output_dir=out_val,
                remove="all",
                profile="maximum",
                format="csv",
                report=None,
                recursive=False,
                yes=True,
                scan_only=False,
                skip_duplicates=False,
                follow_symlinks=False,
                max_files=None,
            )
            handle_batch(b_ns)

        elif choice == "5":
            try:
                raw_path = input(f"{Colors.CYAN}Enter image path: {Colors.RESET}").strip().strip("'\"")
                if not raw_path:
                    continue
                raw_rep = input(
                    f"{Colors.CYAN}Report file [Press Enter for 'report.json']: {Colors.RESET}"
                ).strip().strip("'\"")
                rep_val = raw_rep if raw_rep else "report.json"
                raw_fmt = input(
                    f"{Colors.CYAN}Format [json/html/csv, Enter for json]: {Colors.RESET}"
                ).strip().lower()
                fmt_val = raw_fmt if raw_fmt in ("json", "html", "csv") else "json"
            except (KeyboardInterrupt, EOFError):
                continue

            r_ns = argparse.Namespace(
                image=raw_path, output=rep_val, cleaned=None,
                format=fmt_val, redact=True, yes=True, profile=None,
            )
            handle_report(r_ns)

        elif choice == "6":
            handle_info(argparse.Namespace(json=False))

        else:
            print(f"{Colors.RED}Invalid option. Please choose a number between 0 and 6.{Colors.RESET}")


def _configure_output(args: argparse.Namespace) -> None:
    global _VERBOSE, _QUIET
    _VERBOSE = bool(getattr(args, "verbose", False))
    _QUIET = bool(getattr(args, "quiet", False))
    if getattr(args, "no_color", False) or _QUIET:
        Colors.configure(False)


def main() -> int:
    """Application entry point."""
    # 1. No arguments: launch interactive easy menu
    if len(sys.argv) <= 1:
        Colors.configure(sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        return interactive_menu()

    # 2. Interactive shortcut flag
    if len(sys.argv) == 2 and sys.argv[1] in ("-i", "--interactive", "menu"):
        Colors.configure(sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        return interactive_menu()

    # 3. Version shortcut
    if len(sys.argv) == 2 and sys.argv[1] in ("-V", "--version", "version"):
        print(f"{config.APP_NAME} {config.APP_VERSION}")
        return config.EXIT_SUCCESS

    # 4. Direct image path shortcut: python main.py photo.jpg
    if len(sys.argv) == 2 and sys.argv[1] not in (
        "scan", "clean", "verify", "batch", "report", "info", "-h", "--help",
    ):
        candidate = Path(sys.argv[1].strip("'\""))
        if candidate.is_file() or candidate.suffix.lower() in config.SUPPORTED_EXTENSIONS:
            ns = argparse.Namespace(image=str(candidate), json=False, detailed=False)
            _configure_output(ns)
            return handle_scan(ns)

    parser = build_parser()
    args = parser.parse_args()
    _configure_output(args)

    if args.command == "scan":
        return handle_scan(args)
    if args.command == "clean":
        return handle_clean(args)
    if args.command == "verify":
        return handle_verify(args)
    if args.command == "batch":
        return handle_batch(args)
    if args.command == "report":
        return handle_report(args)
    if args.command == "info":
        return handle_info(args)

    parser.print_help()
    return config.EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
