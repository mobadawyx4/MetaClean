# MetaClean Review Findings & Implementation Status (F-10 through F-27)

This document tracks the audit, implementation, and test verification status for review findings **F-10 through F-27** in MetaClean 2.0.0.

---

## Executive Summary

| Finding | Area | Description | Status | Test Suite |
| :--- | :--- | :--- | :--- | :--- |
| **F-10** | File Analysis | Structural JPEG/PNG/BMP/WEBP analysis & resource limits | **FIXED** | `tests/test_file_analyzer.py` (10 passed) |
| **F-11** | Reporting | CSV formula injection protection & number preservation | **FIXED** | `tests/test_comparison_report.py` (9 passed) |
| **F-12** | Privacy | Phone number masking in free-text value previews | **FIXED** | `tests/test_privacy_levels.py` (23 passed) |
| **F-13** | Privacy | Contact & personal information (PII) classification | **FIXED** | `tests/test_privacy_levels.py` (23 passed) |
| **F-14** | Privacy | GPS altitude and textual location privacy indicators | **FIXED** | `tests/test_privacy_levels.py` (23 passed) |
| **F-15** | Batch | Accurate batch counters & collision detection | **FIXED** | `tests/test_batch_advanced.py`, `tests/test_batch.py` (17 passed) |
| **F-16** | CLI | Strict error handling & standardized CLI exit codes | **FIXED** | `tests/test_cli.py` (14 passed) |
| **F-17** | Profiles | Custom profile validation (prevent accidental full clean) | **FIXED** | `tests/test_profiles.py` (12 passed) |
| **F-18** | Security | Filesystem safety & restricted output permissions (0o600) | **FIXED** | `tests/test_fs_safety.py` (24 passed) |
| **F-19** | Batch | `--max-files` ceiling enforcement & non-positive rejection | **FIXED** | `tests/test_batch_advanced.py` (17 passed) |
| **F-20** | Remover | Informative warnings on no-op / zero-tag removal | **FIXED** | `tests/test_remover.py` (9 passed) |
| **F-21** | Redaction | Path redaction & structural resource limits | **FIXED** | `tests/test_report_redaction.py` (12 passed) |
| **F-22** | CLI / Library | Library and CLI behavioral consistency | **FIXED** | `tests/test_cli.py`, `main.py` |
| **F-23** | Documentation | Comprehensive user & technical documentation | **FIXED** | `README.md`, `docs/*` |
| **F-24** | Remover | Secure metadata removal & fail-closed execution | **FIXED** | `tests/test_fs_safety.py`, `tests/test_remover.py` |
| **F-25** | Verification | Independent verification consistency & residual allowlist | **FIXED** | `tests/test_verifier.py` (15 passed), `tests/test_category_coverage.py` (87 passed) |
| **F-26** | Configuration | Single source of truth for scan-mode descriptions | **FIXED** | `config.py`, `main.py` |
| **F-27** | Reporting | Batch and report export consistency (redacted by default) | **FIXED** | `tests/test_comparison_report.py`, `main.py` |

**Full Test Suite Result:** **273 passed**, 0 failed.

---

## Detailed Finding Audits & Implementation Evidence

### F-10: Structural JPEG/PNG/BMP/WEBP Analysis & Resource Limits
- **Issue**: Structural file analysis previously lacked thorough container boundary checks for BMP and WEBP formats; container size mismatches and trailing bytes were not systematically detected, and recursive parser limits were missing.
- **Implementation**:
  - `modules/file_analyzer.py`: Implemented `_riff_declared_size` for RIFF/WEBP and `_bmp_declared_size` for BMP headers. Added `end_marker_found = True` when container size is fully accounted for. Added dedicated detection and findings for `trailing_data_bmp`, `trailing_data_webp`, `bmp_size_mismatch`, and `webp_size_mismatch`.
  - `config.py`: Enforced structural parser bounds (`STRUCTURE_MAX_SEGMENTS = 10_000`, `STRUCTURE_MAX_CHUNKS = 10_000`, `STRUCTURE_MAX_ENTROPY_SCAN_BYTES = 64 KiB`).
- **Relevant Files**: `modules/file_analyzer.py`, `config.py`
- **Test Evidence**: `tests/test_file_analyzer.py::test_bmp_structure_and_trailing_data`, `tests/test_file_analyzer.py::test_webp_trailing_data_and_size_mismatch` (10 passed).

---

### F-11: CSV Formula Injection Protection & Number Preservation
- **Issue**: Naive CSV escaping prefixed any value starting with `-` with a quote, corrupting legitimate negative numeric values (e.g. GPS longitude `-122.4194` or UTC offsets), while control characters (newlines, carriage returns) could break CSV structure.
- **Implementation**:
  - `modules/report_generator.py`: Updated `_csv_safe` to inspect the character following a leading minus (`-`). If followed by a digit or period (`.`), it is recognized as a legitimate negative number and left unquoted. Formula injection triggers (`=`, `+`, `@`, and `-` followed by non-digits) are prefixed with a single quote (`'`). Control characters (`ord(ch) < 32`) are stripped.
- **Relevant Files**: `modules/report_generator.py`
- **Test Evidence**: `tests/test_comparison_report.py::test_csv_safe_preserves_negative_numbers_and_strips_controls` (9 passed).

---

### F-12: Phone Number Masking in Free-Text Previews
- **Issue**: Email addresses in free-text fields were masked, but telephone numbers embedded in comments or contact fields leaked in full.
- **Implementation**:
  - `modules/privacy_analyzer.py`: Added `_PHONE_RE` regular expression and `_mask_phone` helper in `_sanitize_value_preview`. Numbers with 9+ digits are masked to retain only prefix and suffix (e.g. `+1 (555) 123-4567` -> `+1 ***67`). Technical camera numbers (ISO, exposure ratios, dimensions) are guarded and preserved.
- **Relevant Files**: `modules/privacy_analyzer.py`
- **Test Evidence**: `tests/test_privacy_levels.py::test_phone_in_free_text_is_masked`, `tests/test_privacy_levels.py::test_phone_in_contact_tag_is_masked`, `tests/test_privacy_levels.py::test_plain_numbers_are_not_masked_as_phones`.

---

### F-13: Contact & Personal Information (PII) Classification
- **Issue**: `personal_information_detected` only checked for explicit `author` tags, failing to flag free-text comments containing contact details (emails, phone numbers, postal addresses).
- **Implementation**:
  - `modules/privacy_analyzer.py`: `personal_information_detected` now triggers if `category == "author"` OR if any item is `CRITICAL` with contact details detected in free-text previews or address fields.
- **Relevant Files**: `modules/privacy_analyzer.py`
- **Test Evidence**: `tests/test_privacy_levels.py::test_personal_information_detected_for_phone_only`, `tests/test_privacy_levels.py::test_personal_information_detected_for_email_only`, `tests/test_privacy_levels.py::test_personal_information_detected_for_postal_address`.

---

### F-14: GPS Altitude and Textual Location Privacy Indicators
- **Issue**:
  - IPTC City and location tags were categorized as `gps` by the scanner but ignored by `RuleBasedPrivacyAnalyzer.evaluate_tag`, causing `PrivacyReport.gps_detected` to be `False`.
  - `gps_altitude_detected` and `gps_location_text_detected` flags were not properly segregated.
- **Implementation**:
  - `modules/privacy_analyzer.py`:
    - Updated `evaluate_tag` to accept `category` and recognize `_LOCATION_NAMES` (city, state, country, sublocation, etc.) as category `"gps"` (risk level `LOW`, subcategory `"gps_other"`).
    - Updated `analyze_tags` to pass `category=getattr(tag, "category", None)`.
    - Corrected `gps_altitude = any("altitude" in i.tag_name.lower() for i in items)` so non-altitude GPS tags do not falsely trip `gps_altitude_detected`.
    - Added `gps_altitude_detected` and `gps_location_text_detected` to legacy dictionary `analyze()` path.
- **Relevant Files**: `modules/privacy_analyzer.py`
- **Test Evidence**: `tests/test_privacy_levels.py::test_gps_location_text_detected_flag`, `tests/test_privacy_levels.py::test_gps_altitude_detected_flag`, `tests/test_privacy_levels.py::test_gps_latitude_only_flags`, `tests/test_privacy_levels.py::test_legacy_analyze_gps_flags` (23 passed).

---

### F-15: Batch Counters & Collision Detection
- **Issue**: In `modules/batch_processor.py`, failure paths (e.g. removal failure) omitted `summary.processed_count += 1`, violating the fundamental invariant `processed_count == success_count + failure_count`.
- **Implementation**:
  - `modules/batch_processor.py`: Ensured `summary.processed_count += 1` is executed on every branch (failed removal, unexpected exception, incomplete verification). `summary.failure_count` is incremented for any incomplete or failed verification.
- **Relevant Files**: `modules/batch_processor.py`
- **Test Evidence**: `tests/test_batch_advanced.py::test_processed_equals_success_plus_failure`, `tests/test_batch_advanced.py::test_collision_free_path_increments`.

---

### F-16: Strict Error Handling & CLI Exit Codes
- **Issue**: CLI handlers in `main.py` previously lacked early returns on certain validation errors (unknown profiles, bad directories, invalid category names), risking fall-through or incorrect exit codes.
- **Implementation**:
  - `main.py`: All commands strictly return standard exit codes:
    - `0` (`config.EXIT_SUCCESS`): Success.
    - `1` (`config.EXIT_WARNING`): Warning / partial cleaning / threat found with `--fail-on-risk`.
    - `2` (`config.EXIT_FAIL`): Operation failed / invalid input file.
    - `3` (`config.EXIT_USAGE_ERROR`): CLI usage error, invalid arguments, or unknown profiles.
  - Implemented `_Parser` subclass to raise `SystemExit(config.EXIT_USAGE_ERROR)` on argparse syntax errors.
- **Relevant Files**: `main.py`, `config.py`
- **Test Evidence**: `tests/test_cli.py::test_scan_invalid_file_exits_2`, `tests/test_cli.py::test_scan_fail_on_risk`, `tests/test_cli.py::test_usage_error_exit_code` (14 passed).

---

### F-17: Custom Profile Validation
- **Issue**: Invoking `--profile custom` without specifying `--remove` silently defaulted to removing `"all"`, effectively performing a full wipe without user awareness.
- **Implementation**:
  - `modules/metadata_remover.py`: `validate_categories` updated with `default_all=False` when validating custom profiles. `clean()` explicitly rejects `profile="custom"` with empty categories, returning `RemovalResult(success=False)`.
  - `main.py`: `handle_clean` and `handle_batch` check for `profile_obj.key == "custom"` and verify that `--remove` was explicitly provided; otherwise they output an error and return `config.EXIT_USAGE_ERROR`.
- **Relevant Files**: `modules/sanitizer_profiles.py`, `modules/metadata_remover.py`, `main.py`
- **Test Evidence**: `tests/test_profiles.py::test_custom_profile_requires_categories`, `tests/test_profiles.py::test_empty_categories_rejected`, `tests/test_profiles.py::test_resolve_profile_errors`.

---

### F-18: Filesystem Safety & Restricted Output Permissions
- **Issue**: Need verification that output images and reports are created with secure permissions and cannot be read by unprivileged users on shared POSIX filesystems.
- **Implementation**:
  - `modules/metadata_remover.py` and `modules/report_generator.py`: Working copies and reports are created via `tempfile.mkstemp`, enforcing `0o600` (read/write by owner only) on POSIX platforms.
  - Refusal of symlinks on input and destination paths prevents link traversal and clobbering attacks.
- **Relevant Files**: `modules/metadata_remover.py`, `modules/report_generator.py`
- **Test Evidence**: `tests/test_fs_safety.py::test_output_and_report_file_permissions` (24 passed).

---

### F-19: Batch Max-Files Validation & Hard Ceiling
- **Issue**: Non-positive `--max-files` (e.g. `0` or `-5`) caused Python negative-indexing slice truncation, and arbitrarily large inputs lacked a defense-in-depth ceiling.
- **Implementation**:
  - `modules/batch_processor.py`: Explicitly validates `max_files > 0` and enforces `max_files <= config.MAX_BATCH_FILES_CEILING` (5000), raising `ValueError` otherwise. Slicing uses safe forward indexing.
- **Relevant Files**: `modules/batch_processor.py`, `config.py`
- **Test Evidence**: `tests/test_batch_advanced.py::test_max_files_rejects_non_positive`, `tests/test_batch_advanced.py::test_max_files_rejects_above_ceiling`, `tests/test_batch_advanced.py::test_max_files_ceiling_is_respected`.

---

### F-20: No-Op Removal Warnings
- **Issue**: When a user requested selective cleaning (e.g. `--remove gps`) on an image that had no GPS metadata, ExifTool updated 0 tags without indicating to the user that no changes occurred.
- **Implementation**:
  - `modules/metadata_remover.py`: In `_clean_with_exiftool`, if `updated == 0`, adds an explicit warning: `"ExifTool reported that no tags were updated; the requested fields may have already been absent..."`. If `updated is None`, warns that update count could not be confirmed.
- **Relevant Files**: `modules/metadata_remover.py`
- **Test Evidence**: `tests/test_remover.py::test_noop_removal_warns_when_no_tags_updated` (9 passed).

---

### F-21: Path Redaction & Privacy Report Allowlist
- **Issue**: Reports exported to disk could accidentally leak source usernames, home directories, temporary directories, or sensitive filesystem paths.
- **Implementation**:
  - `modules/report_redaction.py`: Employs a strict allowlist (`SAFE_STRUCTURAL_VALUE_NAMES`, `SAFE_FILESYSTEM_FIELDS`) for redacted reports. Replaces file paths, directory paths, and usernames with `[REDACTED-PATH]` via `_HOME_PATH_RE`.
- **Relevant Files**: `modules/report_redaction.py`, `config.py`
- **Test Evidence**: `tests/test_report_redaction.py` (12 passed).

---

### F-22: Library / CLI Consistency
- **Issue**: Discrepancies between programmatic library APIs and CLI flag handling regarding profile definitions, scan modes, and exit codes.
- **Implementation**:
  - Unified data structures across library and CLI: `config.SCAN_MODES`, `config.METADATA_CATEGORIES`, and `modules.sanitizer_profiles.PROFILES` serve as shared definitions.
- **Relevant Files**: `main.py`, `config.py`, `modules/sanitizer_profiles.py`
- **Test Evidence**: `tests/test_cli.py::test_info_json_is_machine_readable`, `tests/test_cli.py::test_clean_verify_roundtrip`.

---

### F-23: Comprehensive Documentation
- **Issue**: Documentation needed full alignment with MetaClean 2.0.0 features: profiles, verification outcomes, exit codes, privacy scoring heuristic, and safety mechanisms.
- **Implementation**:
  - Maintained and updated `README.md`, `docs/ARCHITECTURE.md`, `docs/METHODOLOGY.md`, `docs/THREAT_MODEL.md`, and `docs/DEVELOPMENT_PLAN.md`.
- **Relevant Files**: `README.md`, `docs/`

---

### F-24: Security-Sensitive Removal & Parser Safety
- **Issue**: Potential command injection, race conditions, or truncated file installation during metadata stripping.
- **Implementation**:
  - Subprocess calls use argument lists directly (`argv` arrays) without `shell=True`.
  - Staging in `.metaclean-XXXXXX` working copy with atomic `os.replace`.
  - Inode validation before and after cleaning steps ensures files are not swapped mid-process.
  - Fail-closed execution: any validation failure aborts installation and preserves original target.
- **Relevant Files**: `modules/metadata_remover.py`, `modules/exiftool_backend.py`
- **Test Evidence**: `tests/test_fs_safety.py` (24 passed), `tests/test_remover.py` (9 passed).

---

### F-25: Independent Verification Consistency & Residual Allowlist
- **Issue**: Re-scanning cleaned images could trigger false positive "dirty" results from essential structural container tags (e.g. Dimensions, ColorSpace, Orientation) or fail to detect selective remnants. Furthermore, `is_structural_tag()` previously allowed any tag whose name appeared in `STRUCTURAL_TAG_ALLOWLIST` regardless of metadata group, risking non-structural tag exemptions (e.g. `IPTC:Orientation`, `XMP:Compression`).
- **Implementation**:
  - `config.py`: Consolidated `STRUCTURAL_GROUPS` into a single authoritative set including EXIF structural groups (`IFD0`, `ExifIFD`, `InteropIFD`, `SubIFD`, `EXIF`). Enforced that structural tag classification requires matching BOTH a recognized structural group and an allowed tag name, preventing non-structural tags in unrelated groups from being classified as structural.
  - `modules/comparison.py`: Aligned structural remaining checks with `config.is_structural_tag(tag.group, tag.name)`, eliminating erroneous exemptions for arbitrary derived tags (such as `Composite:GPSPosition`).
  - `modules/metadata_verifier.py`: Verification re-reads the output independently and checks targeted categories against `STRUCTURAL_TAG_ALLOWLIST` and `is_structural_tag`. Non-targeted categories are accurately reported as preserved rather than failed.
- **Relevant Files**: `config.py`, `modules/comparison.py`, `modules/metadata_verifier.py`
- **Test Evidence**: `tests/test_verifier.py` (15 passed), `tests/test_category_coverage.py` (87 passed), `tests/test_comparison_report.py` (10 passed).

---

### F-26: Single Source of Truth for Scan-Mode Descriptions
- **Issue**: Scan mode descriptions were duplicated with conflicting wording between CLI help, interactive menu, and documentation.
- **Implementation**:
  - `config.py`: `SCAN_MODE_DESCRIPTIONS` defines the canonical description for `"standard"`, `"deep"`, `"privacy"`, and `"full"`.
  - `main.py`: `_add_scan_mode_flags()` and `handle_info()` read directly from `config.SCAN_MODE_DESCRIPTIONS`.
- **Relevant Files**: `config.py`, `main.py`
- **Test Evidence**: `tests/test_cli.py::test_help_exits_zero`, `tests/test_cli.py::test_info_json_is_machine_readable`.

---

### F-27: Batch & Report Export Consistency
- **Issue**: Discrepancies between single-file and batch report exports in redaction defaults and schema fields.
- **Implementation**:
  - `modules/report_generator.py`: `export_batch_report` defaults to `redact=True`. Both single-file and batch exporters support `json`, `csv`, and `html` with consistent redaction allowlists and injection protection.
- **Relevant Files**: `modules/report_generator.py`, `main.py`
- **Test Evidence**: `tests/test_comparison_report.py::test_batch_exports_json_csv_html`, `tests/test_comparison_report.py::test_export_report_dispatch_and_errors`.
