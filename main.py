#!/usr/bin/env python3
"""MetaClean — A Complete Image Metadata Scanner and Remover CLI Tool.

Undergraduate Cybersecurity Graduation Project.
Author: MetaClean Security Team
Target Platform: Linux Mint (Terminal) / Cross-platform POSIX & Windows.
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
from modules.batch_processor import BatchFileResult, BatchProcessor
from modules.image_validator import validate_image
from modules.metadata_remover import MetadataRemover, RemovalResult, validate_categories
from modules.metadata_scanner import MetadataScanner, ScanResult
from modules.metadata_verifier import MetadataVerifier, VerificationReport, VerificationStatus
from modules.privacy_analyzer import RiskLevel
from modules.report_generator import export_batch_csv, export_json_report


# =====================================================================
# Terminal Styling & Color Utilities (Standard Library)
# =====================================================================
class Colors:
    """ANSI color codes with automatic terminal and NO_COLOR detection."""
    _USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""

    RED = "\033[31m" if _USE_COLOR else ""
    GREEN = "\033[32m" if _USE_COLOR else ""
    YELLOW = "\033[33m" if _USE_COLOR else ""
    BLUE = "\033[34m" if _USE_COLOR else ""
    MAGENTA = "\033[35m" if _USE_COLOR else ""
    CYAN = "\033[36m" if _USE_COLOR else ""
    WHITE = "\033[37m" if _USE_COLOR else ""


def print_banner() -> None:
    """Displays the MetaClean application header."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}""" + r"""
  __  __      _         ____ _                 
 |  \/  | ___| |_ __ _ / ___| | ___  __ _ _ __  
 | |\/| |/ _ \ __/ _` | |   | |/ _ \/ _` | '_ \ 
 | |  | |  __/ || (_| | |___| |  __/ (_| | | | |
 |_|  |_|\___|\__\__,_|\____|_|\___|\__,_|_| |_|""" + f"""
{Colors.RESET}{Colors.DIM} Image Privacy Scanner, Sanitizer & Verification Engine v{config.APP_VERSION}
 Backend: {'ExifTool ' + (config.EXIFTOOL_VERSION or '') if config.EXIFTOOL_AVAILABLE else 'Pillow Fallback (ExifTool Missing)'}
{Colors.RESET}"""
    print(banner)


def format_risk_badge(level: RiskLevel | str) -> str:
    """Formats a colored badge for risk levels."""
    lvl = (getattr(level, "value", str(level)) or "").upper()
    if "." in lvl:
        lvl = lvl.split(".")[-1]
    if lvl == "HIGH":
        return f"{Colors.RED}{Colors.BOLD}[ HIGH RISK ]{Colors.RESET}"
    if lvl == "MEDIUM":
        return f"{Colors.YELLOW}{Colors.BOLD}[ MEDIUM RISK ]{Colors.RESET}"
    if lvl == "LOW":
        return f"{Colors.GREEN}[ LOW RISK ]{Colors.RESET}"
    return f"{Colors.CYAN}[ INFORMATIONAL ]{Colors.RESET}"


def format_status_badge(status: VerificationStatus | str) -> str:
    """Formats a colored badge for verification statuses."""
    s = (getattr(status, "value", str(status)) or "").upper()
    if "." in s:
        s = s.split(".")[-1]
    if s == "PASS":
        return f"{Colors.GREEN}{Colors.BOLD}PASS{Colors.RESET}"
    if s == "WARNING":
        return f"{Colors.YELLOW}{Colors.BOLD}WARNING{Colors.RESET}"
    if s == "INCOMPLETE":
        return f"{Colors.MAGENTA}{Colors.BOLD}INCOMPLETE{Colors.RESET}"
    return f"{Colors.RED}{Colors.BOLD}FAIL{Colors.RESET}"


def confirm_prompt(prompt_message: str, assume_yes: bool = False) -> bool:
    """Interactive confirmation prompt for potentially destructive operations."""
    if assume_yes:
        return True
    try:
        reply = input(f"{Colors.YELLOW}{prompt_message} [y/N]: {Colors.RESET}").strip().lower()
        return reply in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\nOperation aborted by user.")
        return False


# =====================================================================
# Command: SCAN
# =====================================================================
def handle_scan(args: argparse.Namespace) -> int:
    """Executes the image scan command."""
    print_banner()
    image_path = Path(args.image)
    print(f"\n{Colors.BOLD}Target File:{Colors.RESET} {image_path}")

    scanner = MetadataScanner()
    scan = scanner.scan(image_path)

    # Validation check
    if not scan.validation.is_valid:
        print(f"\n{Colors.RED}{Colors.BOLD}[ERROR] Image Validation Failed:{Colors.RESET}")
        for err in scan.validation.errors:
            print(f"  • {err}")
        return config.EXIT_FAIL

    print(f"{Colors.BOLD}Format:{Colors.RESET} {scan.validation.format_name} | "
          f"{Colors.BOLD}Dimensions:{Colors.RESET} {scan.validation.dimensions[0]}x{scan.validation.dimensions[1]} | "
          f"{Colors.BOLD}Size:{Colors.RESET} {scan.validation.file_size:,} bytes")

    if scan.validation.has_transparency:
        print(f"{Colors.CYAN}Transparency detected (Alpha Channel preserved).{Colors.RESET}")
    if scan.validation.is_animated:
        print(f"{Colors.CYAN}Animation detected ({scan.validation.n_frames} frames).{Colors.RESET}")

    # Filesystem vs Embedded separation
    print(f"\n{Colors.CYAN}{Colors.BOLD}--- Filesystem Attributes (Non-Embedded) ---{Colors.RESET}")
    print(f"  • Modified on Disk: {scan.filesystem_metadata.get('fs_modified')}")
    print(f"  • Created on Disk:  {scan.filesystem_metadata.get('fs_created')}")

    # Metadata Category Scan
    print(f"\n{Colors.BOLD}--- Embedded Metadata Scan ---{Colors.RESET}")
    core_categories = [
        ("gps", "GPS Location Data"),
        ("date", "Capture / Creation Timestamps"),
        ("device", "Camera & Device Information"),
        ("author", "Author & Personal Identity"),
        ("copyright", "Copyright & Licensing Terms"),
        ("comments", "Comments & Descriptions"),
        ("exif", "Technical Camera Settings & EXIF"),
        ("iptc", "IPTC Application Record"),
        ("xmp", "XMP Metadata Block"),
    ]

    total_detected_categories = 0
    for cat_key, cat_label in core_categories:
        summary = scan.categories.get(cat_key)
        if summary and summary.detected:
            total_detected_categories += 1
            tag_count = len(summary.tags)
            print(f"  • {cat_label}: {Colors.RED}{Colors.BOLD}DETECTED{Colors.RESET} ({tag_count} tag{'s' if tag_count != 1 else ''})")
            
            # Show GPS decoded location prominently
            if cat_key == "gps" and scan.gps_coordinates:
                gps = scan.gps_coordinates
                print(f"      {Colors.DIM}|--{Colors.RESET} {Colors.GREEN}{Colors.BOLD}Coordinates:{Colors.RESET} {gps.formatted} (Decimal: {gps.latitude:.6f}, {gps.longitude:.6f})")
                if gps.altitude:
                    print(f"      {Colors.DIM}|--{Colors.RESET} {Colors.GREEN}{Colors.BOLD}Altitude:{Colors.RESET} {gps.altitude}")
                print(f"      {Colors.DIM}|--{Colors.RESET} {Colors.CYAN}{Colors.BOLD}Google Maps:{Colors.RESET} {gps.google_maps_url}")
                print(f"      {Colors.DIM}|--{Colors.RESET} {Colors.CYAN}{Colors.BOLD}OpenStreetMap:{Colors.RESET} {gps.openstreetmap_url}")

            # Show tags directly by default
            max_display = len(summary.tags) if getattr(args, "detailed", False) else min(15, len(summary.tags))
            for i, t in enumerate(summary.tags[:max_display]):
                val_str = str(t.display_value if t.display_value is not None else t.value).strip()
                if len(val_str) > 80 and not getattr(args, "detailed", False):
                    val_str = val_str[:77] + "..."
                is_last = (i == len(summary.tags[:max_display]) - 1) and (len(summary.tags) <= max_display)
                branch = "\\--" if is_last else "|--"
                print(f"      {Colors.DIM}{branch}{Colors.RESET} {Colors.CYAN}{t.name}{Colors.RESET}: {val_str}")
            
            if len(summary.tags) > max_display:
                remaining = len(summary.tags) - max_display
                print(f"      {Colors.DIM}\\-- ... and {remaining} more tags (use --detailed to see all){Colors.RESET}")
        else:
            print(f"  - {cat_label}: {Colors.GREEN}NOT DETECTED{Colors.RESET}")

    if total_detected_categories == 0:
        print(f"\n  {Colors.GREEN}No embedded metadata found. Image is clean.{Colors.RESET}")

    # Privacy Risk
    pr = scan.privacy_report
    if pr:
        print(f"\n{Colors.BOLD}Privacy Risk Assessment:{Colors.RESET} {format_risk_badge(pr.overall_risk)} (Risk Score: {pr.risk_score}/100)")
        print(f"  {pr.summary_narrative}")

        # Highlight geographic exposure if detected
        if scan.gps_coordinates:
            print(f"\n  {Colors.RED}{Colors.BOLD}Geographic Exposure Detected:{Colors.RESET}")
            print(f"    * Coordinates: {Colors.BOLD}{scan.gps_coordinates.formatted}{Colors.RESET} (Lat: {scan.gps_coordinates.latitude:.6f}, Lon: {scan.gps_coordinates.longitude:.6f})")
            print(f"    * Google Maps: {scan.gps_coordinates.google_maps_url}")
        if pr.high_risk_count > 0:
            print(f"\n  {Colors.RED}{Colors.BOLD}High-Risk Findings ({pr.high_risk_count}):{Colors.RESET}")
            for item in pr.items:
                if item.risk_level == RiskLevel.HIGH:
                    print(f"    • {Colors.RED}{item.tag_name}{Colors.RESET}: {item.value_preview}")
                    print(f"      {Colors.DIM}Reason: {item.explanation}{Colors.RESET}")

        if pr.medium_risk_count > 0:
            print(f"\n  {Colors.YELLOW}{Colors.BOLD}Medium-Risk Findings ({pr.medium_risk_count}):{Colors.RESET}")
            for item in pr.items:
                if item.risk_level == RiskLevel.MEDIUM:
                    print(f"    • {Colors.YELLOW}{item.tag_name}{Colors.RESET}: {item.value_preview}")
                    if getattr(args, "detailed", False):
                        print(f"      {Colors.DIM}Reason: {item.explanation}{Colors.RESET}")

    # Limitations
    if scan.limitations:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Inspection Limitations:{Colors.RESET}")
        for lim in scan.limitations:
            print(f"  ! {lim}")

    # Export report if requested
    if args.json:
        report_file = Path(f"{image_path.stem}_report.json")
        export_json_report(report_file, scan)
        print(f"\n{Colors.GREEN}Full JSON scan report exported to: {report_file}{Colors.RESET}")

    return config.EXIT_SUCCESS


# =====================================================================
# Command: CLEAN
# =====================================================================
def handle_clean(args: argparse.Namespace) -> int:
    """Executes metadata removal and automated verification."""
    print_banner()
    in_path = Path(args.image)
    out_path = Path(args.output) if args.output else in_path.parent / f"{in_path.stem}_clean{in_path.suffix}"

    print(f"\n{Colors.BOLD}Input File:{Colors.RESET}  {in_path}")
    print(f"{Colors.BOLD}Output File:{Colors.RESET} {out_path}")

    # Overwrite check
    if out_path.exists() and not args.yes:
        if not confirm_prompt(f"Output file '{out_path.name}' already exists. Overwrite?"):
            print("Operation cancelled.")
            return config.EXIT_USAGE_ERROR

    # Parse categories
    raw_cats = args.remove if args.remove else "all"
    valid_cats, invalid_cats = validate_categories(raw_cats)
    if invalid_cats:
        print(f"{Colors.RED}[ERROR] Invalid categories specified: {', '.join(invalid_cats)}{Colors.RESET}")
        print(f"Supported categories: {', '.join(config.METADATA_CATEGORIES.keys())}")
        return config.EXIT_USAGE_ERROR

    print(f"{Colors.BOLD}Requested Removal:{Colors.RESET} {', '.join(valid_cats)}")
    if "all" not in valid_cats:
        print(f"{Colors.YELLOW}[WARNING] Selective removal active. Unselected categories may retain identifying info!{Colors.RESET}")

    # Execute removal
    remover = MetadataRemover()
    print(f"\n{Colors.CYAN}Sanitizing image metadata...{Colors.RESET}")
    removal = remover.clean(
        input_path=in_path,
        output_path=out_path,
        categories=valid_cats,
        overwrite_output=True,
    )

    if not removal.success:
        print(f"\n{Colors.RED}{Colors.BOLD}[FAILED] Metadata removal encountered errors:{Colors.RESET}")
        for err in removal.errors:
            print(f"  • {err}")
        return config.EXIT_FAIL

    saved = removal.bytes_saved
    print(f"{Colors.GREEN}Action: Metadata removal completed successfully.{Colors.RESET}")
    print(f"  • Engine: {removal.method_used}")
    print(f"  • Cleaned File: {out_path} ({removal.cleaned_size:,} bytes, {saved:,} bytes stripped)")

    # Execute Independent Post-Clean Verification
    print(f"\n{Colors.CYAN}Executing independent verification of cleaned image...{Colors.RESET}")
    verifier = MetadataVerifier()
    verification = verifier.verify(
        image_path=out_path,
        targeted_categories=valid_cats,
        original_image_path=in_path,
    )

    print(f"\n{Colors.BOLD}Verification Results:{Colors.RESET}")
    for check in verification.category_checks:
        if check.status == VerificationStatus.PASS:
            print(f"  • Targeted {check.category.upper()}: {Colors.GREEN}NOT DETECTED{Colors.RESET}")
        else:
            print(f"  • Targeted {check.category.upper()}: {Colors.RED}DETECTED ({len(check.found_tags)} tags){Colors.RESET}")

    print(f"\n{Colors.BOLD}Status:{Colors.RESET} {format_status_badge(verification.status)}")
    print(f"  {verification.summary_message}")

    # Optional report export
    if args.report:
        rep_p = export_json_report(
            args.report,
            scan=verification.scan_result or MetadataScanner().scan(out_path),
            removal=removal,
            verification=verification,
        )
        print(f"{Colors.GREEN}Detailed processing report saved to: {rep_p}{Colors.RESET}")

    if verification.status == VerificationStatus.PASS:
        return config.EXIT_SUCCESS
    elif verification.status in (VerificationStatus.WARNING, VerificationStatus.INCOMPLETE):
        return config.EXIT_WARNING
    return config.EXIT_FAIL


# =====================================================================
# Command: VERIFY
# =====================================================================
def handle_verify(args: argparse.Namespace) -> int:
    """Executes independent verification on an image."""
    print_banner()
    image_path = Path(args.image)
    print(f"\n{Colors.BOLD}Verifying Image:{Colors.RESET} {image_path}")

    targets = args.targets if args.targets else "all"
    valid_targets, invalid_targets = validate_categories(targets)
    if invalid_targets:
        print(f"{Colors.RED}[ERROR] Invalid target category name(s): {', '.join(invalid_targets)}{Colors.RESET}")
        return config.EXIT_USAGE_ERROR

    verifier = MetadataVerifier()
    report = verifier.verify(
        image_path=image_path,
        targeted_categories=valid_targets,
        original_image_path=args.original,
    )

    if report.status == VerificationStatus.FAIL and not report.scan_result:
        print(f"{Colors.RED}[FAIL] {report.summary_message}{Colors.RESET}")
        return config.EXIT_FAIL

    print(f"\n{Colors.BOLD}Category Checks:{Colors.RESET}")
    for check in report.category_checks:
        badge = Colors.GREEN + "CLEAN" + Colors.RESET if check.status == VerificationStatus.PASS else Colors.RED + "REMAINING" + Colors.RESET
        print(f"  • [{badge}] Category '{check.category}': {len(check.found_tags)} tags found")
        if check.found_tags:
            for tag in check.found_tags[:5]:
                print(f"      - {tag}")

    if report.remaining_sensitive_tags:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Sensitive Metadata Remnants ({len(report.remaining_sensitive_tags)}):{Colors.RESET}")
        for item in report.remaining_sensitive_tags:
            print(f"  • [{item.risk_level.value}] {item.tag_name}: {item.value_preview}")

    if report.limitations:
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}Verification Limitations:{Colors.RESET}")
        for lim in report.limitations:
            print(f"  ! {lim}")

    print(f"\n{Colors.BOLD}Final Verification Status:{Colors.RESET} {format_status_badge(report.status)}")
    print(f"Summary: {report.summary_message}")

    if args.json:
        rep_p = Path(f"{image_path.stem}_verification.json")
        export_json_report(
            rep_p,
            scan=report.scan_result or MetadataScanner().scan(image_path),
            verification=report
        )
        print(f"\n{Colors.GREEN}Verification JSON report written to: {rep_p}{Colors.RESET}")

    if report.status == VerificationStatus.PASS:
        return config.EXIT_SUCCESS
    elif report.status in (VerificationStatus.WARNING, VerificationStatus.INCOMPLETE):
        return config.EXIT_WARNING
    return config.EXIT_FAIL


# =====================================================================
# Command: BATCH
# =====================================================================
def handle_batch(args: argparse.Namespace) -> int:
    """Executes batch processing across a directory."""
    print_banner()
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)

    print(f"\n{Colors.BOLD}Batch Input Directory:{Colors.RESET}  {in_dir}")
    print(f"{Colors.BOLD}Batch Output Directory:{Colors.RESET} {out_dir}")

    # Confirmation
    if not args.yes:
        if not confirm_prompt(f"Process all images in '{in_dir}' and save to '{out_dir}'?"):
            print("Operation aborted.")
            return config.EXIT_USAGE_ERROR

    processor = BatchProcessor()

    def progress_callback(item: BatchFileResult, current: int, total: int) -> None:
        status_color = Colors.GREEN if item.success else Colors.RED
        print(f"[{current}/{total}] {item.input_path.name} -> {item.output_path.name if item.output_path else 'N/A'}: "
              f"{status_color}{item.verification_status}{Colors.RESET} "
              f"({item.format_name}, {item.original_size:,}B -> {item.cleaned_size:,}B)")
        if item.error_message:
            print(f"    {Colors.RED}Error: {item.error_message}{Colors.RESET}")

    print(f"\n{Colors.CYAN}Starting batch processing...{Colors.RESET}\n")
    summary = processor.process_batch(
        input_dir=in_dir,
        output_dir=out_dir,
        categories=args.remove or "all",
        overwrite=args.yes,
        recursive=args.recursive,
        progress_callback=progress_callback,
    )

    print(f"\n{Colors.BOLD}Batch Processing Summary:{Colors.RESET}")
    print(f"  • Total Images Discovered: {summary.total_found}")
    print(f"  • Successfully Processed:  {Colors.GREEN}{summary.success_count}{Colors.RESET}")
    print(f"  • Failed / Corrupted:      {Colors.RED if summary.failure_count else Colors.GREEN}{summary.failure_count}{Colors.RESET}")
    print(f"  • Verification Passed:     {Colors.GREEN}{summary.pass_count}{Colors.RESET}")
    print(f"  • Verification Warnings:   {Colors.YELLOW}{summary.warning_count}{Colors.RESET}")
    print(f"  • Total Bytes Stripped:    {summary.total_bytes_saved:,} bytes")

    # Export batch summary
    report_path = Path(args.report) if args.report else out_dir / "batch_summary.csv"
    records = []
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
            "output_path": str(r.output_path) if r.output_path else "",
            "notes": r.error_message or "",
        })

    if args.format == "json":
        json_path = report_path.with_suffix(".json")
        with open(json_path, "w", encoding="utf-8") as f:
            import json
            json.dump({
                "summary": {
                    "total": summary.total_found,
                    "success": summary.success_count,
                    "failed": summary.failure_count,
                    "bytes_saved": summary.total_bytes_saved,
                },
                "results": records
            }, f, indent=2)
        print(f"\n{Colors.GREEN}Batch summary exported to JSON: {json_path}{Colors.RESET}")
    else:
        csv_path = report_path.with_suffix(".csv")
        export_batch_csv(records, csv_path)
        print(f"\n{Colors.GREEN}Batch summary exported to CSV: {csv_path}{Colors.RESET}")

    return config.EXIT_SUCCESS if summary.failure_count == 0 else config.EXIT_WARNING


# =====================================================================
# Command: REPORT
# =====================================================================
def handle_report(args: argparse.Namespace) -> int:
    """Generates a detailed security report for an image."""
    print_banner()
    in_path = Path(args.image)
    out_file = Path(args.output)

    print(f"\nGenerating security and privacy report for: {in_path}")
    scanner = MetadataScanner()
    scan = scanner.scan(in_path)

    verification = None
    if args.cleaned:
        verifier = MetadataVerifier(scanner=scanner)
        verification = verifier.verify(args.cleaned, original_image_path=in_path)

    saved_p = export_json_report(out_file, scan=scan, verification=verification)
    print(f"{Colors.GREEN}Comprehensive audit report successfully generated:{Colors.RESET} {saved_p}")
    return config.EXIT_SUCCESS


# =====================================================================
# Main Argument Parser
# =====================================================================
def build_parser() -> argparse.ArgumentParser:
    """Builds the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="metaclean",
        description=f"{config.APP_NAME} — Complete Image Metadata Scanner, Privacy Risk Analyzer & Sanitizer.",
        epilog="Academic Graduation Project in Cybersecurity | Designed for Linux Mint & POSIX Terminals.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: SCAN
    scan_p = subparsers.add_parser("scan", help="Scan an image and inspect metadata with privacy risk classification.")
    scan_p.add_argument("image", help="Path to the image file to scan.")
    scan_p.add_argument("--json", action="store_true", help="Export scan results to a JSON report file.")
    scan_p.add_argument("--detailed", action="store_true", help="Print detailed tag breakdown in terminal.")

    # Command: CLEAN
    clean_p = subparsers.add_parser("clean", help="Remove all or selective metadata categories to a new copy.")
    clean_p.add_argument("image", help="Path to original input image (preserved untouched).")
    clean_p.add_argument("--output", "-o", required=False, default=None,
                         help="Path to save the cleaned copy (optional, defaults to <filename>_clean.<ext>).")
    clean_p.add_argument("--remove", "-r", default="all",
                         help="Metadata categories to remove: gps, date, device, author, copyright, comments, exif, iptc, xmp, all (default: all).")
    clean_p.add_argument("--yes", "-y", action="store_true", help="Automatically confirm overwriting existing output.")
    clean_p.add_argument("--report", help="Optional path to export a detailed JSON cleaning audit report.")

    # Command: VERIFY
    verify_p = subparsers.add_parser("verify", help="Independently verify an image's metadata status.")
    verify_p.add_argument("image", help="Path to the image to verify.")
    verify_p.add_argument("--targets", "-t", default="all",
                          help="Categories targeted for verification (default: all).")
    verify_p.add_argument("--original", help="Optional original image path for comparative diffing.")
    verify_p.add_argument("--json", action="store_true", help="Output verification results in JSON format.")

    # Command: BATCH
    batch_p = subparsers.add_parser("batch", help="Batch process and sanitize multiple images in a directory.")
    batch_p.add_argument("input_dir", help="Directory containing source images.")
    batch_p.add_argument("--output-dir", "-o", required=True, help="Destination directory for cleaned images.")
    batch_p.add_argument("--remove", "-r", default="all", help="Categories to remove (default: all).")
    batch_p.add_argument("--format", choices=["csv", "json"], default="csv", help="Summary report format.")
    batch_p.add_argument("--report", help="Path to save summary report (CSV or JSON).")
    batch_p.add_argument("--recursive", action="store_true", help="Recursively process subdirectories.")
    batch_p.add_argument("--yes", "-y", action="store_true", help="Confirm operations without interactive prompts.")

    # Command: REPORT
    rep_p = subparsers.add_parser("report", help="Generate an in-depth security and privacy JSON audit report.")
    rep_p.add_argument("image", help="Target image to audit.")
    rep_p.add_argument("--output", "-o", required=True, help="Destination file path for JSON report.")
    rep_p.add_argument("--cleaned", help="Optional cleaned image file to verify against the original.")

    return parser


def interactive_menu() -> int:
    """Friendly interactive CLI wizard with menu choices and drag & drop support."""
    print_banner()
    while True:
        print(f"\n{Colors.BOLD}{Colors.CYAN}================== MetaClean Easy Menu =================={Colors.RESET}")
        print(f"  {Colors.BOLD}[1]{Colors.RESET} Scan an Image           (فحص صورة وعرض بياناتها وموقعها الجغرافي)")
        print(f"  {Colors.BOLD}[2]{Colors.RESET} Clean an Image          (حذف الميتاداتا وحماية الخصوصية)")
        print(f"  {Colors.BOLD}[3]{Colors.RESET} Verify an Image         (التحقق المستقل من نظافة الصورة)")
        print(f"  {Colors.BOLD}[4]{Colors.RESET} Batch Clean a Folder    (تنظيف مجلد كامل دفعة واحدة)")
        print(f"  {Colors.BOLD}[5]{Colors.RESET} Generate Security Report(إنشاء تقرير أمني شامل بصيغة JSON)")
        print(f"  {Colors.BOLD}[0]{Colors.RESET} Exit                    (خروج)")
        print(f"{Colors.BOLD}{Colors.CYAN}========================================================={Colors.RESET}")

        try:
            choice = input(f"\n{Colors.YELLOW}Enter your choice [0-5]: {Colors.RESET}").strip()
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

            # Interactive follow-up: offer to clean immediately!
            if Path(path_str).exists():
                try:
                    do_clean = input(f"\n{Colors.YELLOW}Would you like to clean and remove metadata from this image now? [Y/n]: {Colors.RESET}").strip().lower()
                    if do_clean in ("", "y", "yes"):
                        clean_ns = argparse.Namespace(
                            image=path_str,
                            output=None,
                            remove="all",
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
                raw_out = input(f"{Colors.CYAN}Output path [Press Enter for automatic naming]: {Colors.RESET}").strip().strip("'\"")
                out_val = raw_out if raw_out else None
                raw_rem = input(f"{Colors.CYAN}Categories to remove [Press Enter for 'all']: {Colors.RESET}").strip()
                rem_val = raw_rem if raw_rem else "all"
            except (KeyboardInterrupt, EOFError):
                continue

            clean_ns = argparse.Namespace(
                image=path_str,
                output=out_val,
                remove=rem_val,
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
            except (KeyboardInterrupt, EOFError):
                continue

            v_ns = argparse.Namespace(image=path_str, targets="all", original=None, json=False)
            handle_verify(v_ns)

        elif choice == "4":
            try:
                raw_in = input(f"{Colors.CYAN}Enter folder containing images: {Colors.RESET}").strip().strip("'\"")
                if not raw_in:
                    continue
                raw_out = input(f"{Colors.CYAN}Destination folder [Press Enter for 'cleaned_images']: {Colors.RESET}").strip().strip("'\"")
                out_val = raw_out if raw_out else "cleaned_images"
            except (KeyboardInterrupt, EOFError):
                continue

            b_ns = argparse.Namespace(
                input_dir=raw_in,
                output_dir=out_val,
                remove="all",
                format="csv",
                report=None,
                recursive=False,
                yes=True,
            )
            handle_batch(b_ns)

        elif choice == "5":
            try:
                raw_path = input(f"{Colors.CYAN}Enter image path: {Colors.RESET}").strip().strip("'\"")
                if not raw_path:
                    continue
                raw_rep = input(f"{Colors.CYAN}Report file [Press Enter for 'report.json']: {Colors.RESET}").strip().strip("'\"")
                rep_val = raw_rep if raw_rep else "report.json"
            except (KeyboardInterrupt, EOFError):
                continue

            r_ns = argparse.Namespace(image=raw_path, output=rep_val, cleaned=None)
            handle_report(r_ns)

        else:
            print(f"{Colors.RED}Invalid option. Please choose a number between 0 and 5.{Colors.RESET}")


def main() -> int:
    """Application entry point."""
    # 1. No arguments: launch interactive easy menu
    if len(sys.argv) <= 1:
        return interactive_menu()

    # 2. Interactive shortcut flag
    if len(sys.argv) == 2 and sys.argv[1] in ("-i", "--interactive", "menu"):
        return interactive_menu()

    # 3. Direct image path shortcut: python main.py photo.jpg
    if len(sys.argv) == 2 and sys.argv[1] not in ("scan", "clean", "verify", "batch", "report", "-h", "--help"):
        candidate = Path(sys.argv[1].strip("'\""))
        if candidate.is_file() or candidate.suffix.lower() in config.SUPPORTED_EXTENSIONS:
            ns = argparse.Namespace(image=str(candidate), json=False, detailed=False)
            return handle_scan(ns)

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "clean":
        return handle_clean(args)
    elif args.command == "verify":
        return handle_verify(args)
    elif args.command == "batch":
        return handle_batch(args)
    elif args.command == "report":
        return handle_report(args)
    else:
        parser.print_help()
        return config.EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
