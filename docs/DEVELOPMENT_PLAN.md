# MetaClean Development Plan

This document records the phased delivery of MetaClean 2.0 and the planned future work.

## 1. Delivery phases

| Phase | Objective | Deliverables | Status |
| --- | --- | --- | --- |
| 0 | Baseline audit | Repository audit, dependency check, 39 passing tests, ExifTool discovery. | Complete |
| 1 | Configuration and backend hardening | `config.py` scan modes, categories, structural allowlist; `modules/exiftool_backend.py` with safe argv, timeouts, JSON parsing, numeric pass, write helper. | Complete |
| 2 | Exhaustive extraction | Rewritten `metadata_scanner.py`: provenance fields, deep/privacy/full modes, GPS decoding, derived handling, warnings, group counts. | Complete |
| 3 | Privacy taxonomy | Rewritten `privacy_analyzer.py`: five levels, documented scoring, category breakdown, contact/PII detection, masking, recommendations. | Complete |
| 4 | Deep file analysis | `modules/file_analyzer.py`: extension/MIME mismatch, bit depth, frames, ICC, trailing data, timestamp contradictions, confirmed/suspicious/informational findings. | Complete |
| 5 | Sanitization profiles | `modules/sanitizer_profiles.py`; rewritten `metadata_remover.py` with profiles, temp-copy cleaning, atomic replace, symlink refusal, output validation, operation recording. | Complete |
| 6 | Comparison and verification | `modules/comparison.py`; rewritten `metadata_verifier.py` with explicit outcomes, legacy status, residual allowlist, profile-aware targets, comparison integration. | Complete |
| 7 | Reporting | Rewritten `report_generator.py`: JSON, CSV, HTML, redaction, escaping, formula-injection neutralisation, comparison sections; batch JSON/CSV/HTML exporters. | Complete |
| 8 | Batch safety | Rewritten `batch_processor.py`: scan-only, profiles, duplicate hashing, symlink policy, output exclusion, per-file isolation, limits. | Complete |
| 9 | CLI professionalization | Rewritten `main.py`: modes, profiles, report formats, redaction controls, `info`, verbose/quiet/no-color, stable exit codes, updated interactive menu. | Complete |
| 10 | Test expansion | New suites for privacy levels, profiles, file analysis, comparison/reporting, advanced batch, and CLI; legacy tests updated for the CRITICAL GPS classification. | Complete |
| 11 | Documentation | README rewrite plus architecture, threat model, methodology, and development plan. | Complete |

## 2. Test coverage summary

| Suite | Focus |
| --- | --- |
| `test_validator.py` | Magic bytes, limits, path handling. |
| `test_scanner.py` | Extraction, categorization, fallback, corrupted input. |
| `test_privacy_levels.py` | Five-level taxonomy, rule precedence, PII masking, scoring. |
| `test_profiles.py` | Profile resolution, full and selective cleaning, original preservation. |
| `test_file_analyzer.py` | Container mismatch, trailing data, PNG header, deep-scan attachment. |
| `test_comparison_report.py` | Before/after diff, redaction, HTML escaping, CSV injection, batch exports. |
| `test_batch.py` | Mixed valid/corrupt batches, collisions, CSV summary, originals preserved. |
| `test_batch_advanced.py` | Scan-only, duplicates, symlinks, output exclusion, limits, profiles. |
| `test_verifier.py` | Legacy status, selective verification, fallback behaviour. |
| `test_remover.py` | Removal safety and output validation. |
| `test_cli.py` | Exit codes, quiet/color, clean/verify round-trip, redacted reports, usage errors. |

All fixtures generate synthetic images at test time; no personal data or sample photographs are stored in the repository.

## 3. Design decisions and rationale

| Decision | Rationale |
| --- | --- |
| GPS coordinates are `CRITICAL` | They pinpoint a real-world location and enable physical harm; `HIGH` understated the impact. |
| Keep legacy `VerificationStatus` alongside `VerificationOutcome` | Avoids breaking existing reports and tests while adding explicit outcomes. |
| Centralise ExifTool in one backend | Makes safety review and argument auditing tractable. |
| Reject `-api RequestAll=3` | Injects nondeterministic tags that corrupt reports and comparisons. |
| Structural allowlist for full-clean verification | Prevents false "dirty" results from container/decoder structure. |
| Reports redacted by default in the CLI | Reduces accidental disclosure; library exporters keep `redact=False` for compatibility. |
| Refuse selective cleaning without ExifTool | A Pillow re-encode cannot honour selective categories; silently cleaning everything would be misleading. |
| Atomic replace after validation | Guarantees a failed clean never destroys a pre-existing output. |
| Symlinks skipped by default in batch | Prevents a link from pulling arbitrary files into a batch. |

## 4. Future work

### 4.1 Detection depth

- Per-vendor MakerNotes dictionaries with differential before/after validation.
- HEIC/AVIF and RAW container support.
- Detection of metadata in ancillary PNG chunks and WebP extended chunks.
- Optional entropy and trailing-data heuristics with explicit confidence language.

### 4.2 Classification quality

- Rule versioning and a published rule changelog.
- A labelled evaluation corpus of real camera files.
- Configurable policy profiles for organisations (e.g. journalism vs. healthcare).
- Optional locale-aware PII detection (national ID formats, addresses).

### 4.3 Verification strength

- Differential pixel comparison to detect unintended re-encoding changes.
- Structural re-serialization checks for JPEG segment order.
- Third-party cross-checks (e.g. compare against `exiftool -validate` output).
- Machine-readable verification certificates with hashes.

### 4.4 Usability

- Shell completions and man pages.
- Native packaging (`.deb`, Homebrew, pipx).
- A read-only web viewer for redacted reports.
- Richer interactive menu with profile explanations and report previews.

### 4.5 Engineering

- Typed public API with `py.typed`.
- Property-based tests for parsers and redaction.
- CI matrix across Python 3.10–3.13 and ExifTool versions.
- Performance benchmarks for large batches.

## 5. Constraints respected

- The original repository structure and CLI command names were preserved.
- No user files were deleted or overwritten.
- No external dependency was added beyond Pillow and pytest.
- No network access or metadata execution was introduced.
- Nothing was committed or pushed without explicit authorization.
