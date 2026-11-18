# MetaClean Architecture

This document describes the internal structure of MetaClean 2.0, its data flow, and the design decisions that connect the modules.

## 1. Design goals

1. **Exhaustive, provenance-preserving metadata extraction.**
2. **Transparent, explainable privacy classification.**
3. **Non-destructive sanitization with independent verification.**
4. **Safe handling of untrusted files and metadata.**
5. **A scriptable CLI with stable exit codes and machine-readable reports.**

### Non-goals

- Detecting steganography or arbitrary data encoded in pixels.
- Proving that a file contains no hidden information anywhere.
- Executing, rendering, or trusting metadata values.
- Network access of any kind.

## 2. Layered view

```text
┌──────────────────────────────────────────────────────────────┐
│ CLI (main.py)                                                │
│  scan · clean · verify · batch · report · info · menu        │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│ Orchestration                                                │
│  batch_processor.py        metadata_verifier.py              │
│  comparison.py             sanitizer_profiles.py             │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│ Analysis & transformation                                    │
│  metadata_scanner.py   privacy_analyzer.py   file_analyzer.py│
│  metadata_remover.py   image_validator.py                    │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│ Backends                                                     │
│  exiftool_backend.py (subprocess, safe argv)                 │
│  Pillow (decode, fallback extraction, re-encode fallback)    │
└──────────────────────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│ Output                                                       │
│  report_generator.py → JSON · CSV · HTML                    │
│  terminal rendering (ANSI, optional color)                   │
└──────────────────────────────────────────────────────────────┘
```

## 3. Module responsibilities

| Module | Responsibility |
| --- | --- |
| `config.py` | Version, limits, categories, scan modes, structural-tag allowlist, ExifTool discovery. |
| `exiftool_backend.py` | The only place ExifTool is invoked. Builds argv, enforces timeouts, parses JSON, captures warnings, performs writes, parses update counts. |
| `image_validator.py` | Magic-byte checks, decode validation, size/pixel limits, path resolution. |
| `metadata_scanner.py` | Extraction in `standard`/`deep`/`privacy`/`full` modes; tag provenance; category summaries; GPS decoding; optional container analysis. |
| `privacy_analyzer.py` | Five-level taxonomy, per-tag explanations and recommendations, aggregate scoring, category breakdown. |
| `file_analyzer.py` | Container/extension/MIME consistency, bit depth, frames, ICC, trailing data, timestamp contradictions, finding confidence classes. |
| `sanitizer_profiles.py` | Named category bundles and custom resolution. |
| `metadata_remover.py` | Temporary-copy cleaning, atomic replacement, symlink/same-file refusal, output validation, operation recording. |
| `comparison.py` | Diff between two scans: removed, remaining, changed, introduced, sensitive removed/remaining. |
| `metadata_verifier.py` | Independent re-scan, profile-aware outcome decision, legacy status, comparison integration. |
| `report_generator.py` | Redacted-by-default JSON, CSV, HTML; batch JSON/CSV/HTML; escaping and formula-injection neutralisation; staged atomic report writes. |
| `report_redaction.py` | Allowlist redaction policy, structural value allowlist, recursive free-text scrub (identifiers, e-mail, phone, home paths). |
| `json_encoder.py` | Allowlisted JSON default encoder for bytes, dates/times, paths, UUID, Decimal, sets, tuples and enums; controlled errors for unsupported values. |
| `batch_processor.py` | Discovery, symlink policy, output exclusion, duplicate hashing, per-file isolation, profiles, scan-only. |
| `main.py` | Argument parsing, terminal presentation, confirmation prompts, exit-code mapping, interactive menu. |

## 4. Data flow

### 4.1 Scan

```text
path → validate_image
     → ExifToolBackend.read_tags(structured, numeric, exhaustive)
     → MetadataTag{group, name, raw, display, type, status, category, derived}
     → CategorySummary (per config.METADATA_CATEGORIES)
     → RuleBasedPrivacyAnalyzer.analyze_tags → PrivacyReport
     → GPS decode (numeric raw pass preferred)
     → FileAnalyzer.analyze (deep/privacy/full only)
     → ScanResult
```

`ScanResult` is the single source of truth consumed by the verifier, comparison, and report generator.

### 4.2 Clean

```text
input ────────────────────────────────► never modified
  │
  ├─ resolve profile/categories
  ├─ mkstemp in output directory → copyfile
  ├─ ExifTool write on the temporary copy
  ├─ validate_image(temp)
  ├─ os.replace(temp, output)         (atomic)
  └─ validate_image(output) + dimension check
```

On any failure the temporary copy is removed and the destination is left untouched.

### 4.3 Verify

```text
cleaned file → independent MetadataScanner.scan
             → category checks
             → residual non-structural tags (structural allowlist applied)
             → sensitive findings
             → optional compare_scans(original, cleaned)
             → outcome decision
```

The outcome logic never treats an ExifTool exit code as evidence.

### 4.4 Batch

```text
discover → [symlink filter] → [output-dir exclusion] → [limit]
        → for each file (isolated try/except):
             [duplicate hash]
             scan → [scan-only? stop]
                  → remove → verify → summarize
        → aggregate summary → CSV/JSON/HTML
```

### 4.5 Report

`build_file_report_dict` normalises all result objects into one dictionary. Exporters consume that dictionary:

- JSON serialises it with the allowlisted encoder in `json_encoder.py`, so bytes, dates, paths and sets have one deterministic representation and unsupported values fail with a controlled error.
- CSV flattens per-tag rows (or batch records) and applies the same tag-value allowlist.
- HTML renders escaped sections and an explicit methodology note.

Redaction is applied while building the dictionary, so every exporter inherits the same policy. `redact` defaults to `True`; `report_redaction.py` owns the allowlist (structural container facts only) and a recursive scrub pass for leftover identifiers in warnings, limitations and narratives. Batch exporters redact records independently (positional file labels, no paths or notes).

Every writer renders the document in memory, stages it in the destination directory, re-checks that the destination is not a symlink, and installs it with `os.replace`. A failed serialization or write therefore cannot truncate an existing report.

## 5. Data model

| Type | Key fields |
| --- | --- |
| `MetadataTag` | `name`, `value`, `group`, `category`, `display_value`, `raw_value`, `value_type`, `extraction_status`, `derived`, `key`, `family` |
| `CategorySummary` | `name`, `description`, `detected`, `tags` |
| `ScanResult` | `validation`, `scanner_backend`, `filesystem_metadata`, `image_metadata`, `categories`, `privacy_report`, `gps_coordinates`, `limitations`, `mode`, `warnings`, `metadata_group_counts`, `file_analysis` |
| `RiskAssessmentItem` | `tag_name`, `category`, `risk_level`, `value_preview`, `explanation`, `recommendation`, `tag_key` |
| `PrivacyReport` | `overall_risk`, `risk_score`, `items`, `score_components`, `score_explanation`, `category_breakdown`, detection flags |
| `RemovalResult` | `success`, sizes, `categories_requested/removed/preserved`, `method_used`, `operations_attempted`, `output_validated`, `tags_updated_count` |
| `ComparisonResult` | removed/remaining/changed/introduced tags, sensitive removed/remaining, risk before/after |
| `VerificationReport` | `status`, `outcome`, `outcome_reason`, `category_checks`, `remaining_sensitive_tags`, `residual_metadata_tags`, `comparison` |
| `FileAnalysis` | format/extension/MIME, bit depth, frames, ICC, trailing data, findings |

## 6. Safety invariants

1. `MetadataRemover` never opens the input for writing.
2. Output paths that are symlinks, directories, or the same inode as the input are rejected.
3. A pre-existing output is replaced only after the temporary copy passes validation.
4. `exiftool` is always invoked with an argument list and `--` before the path.
5. Batch discovery skips symlinks unless explicitly enabled and never descends into the output directory.
6. Metadata values are escaped at render time and never interpreted as code.
7. Reports are redacted unless the user explicitly opts out.
8. Unselected selective-clean categories produce a warning, never a silent claim of full cleanliness.

## 7. Extension points

- **New sanitization profile:** add a `SanitizationProfile` entry in `sanitizer_profiles.py` and a category bundle in `config.METADATA_CATEGORIES` if new tags are needed.
- **New risk rules:** extend `RuleBasedPrivacyAnalyzer.evaluate_tag`; keep rule order explicit because earlier rules win.
- **Alternative privacy engine:** implement `BasePrivacyAnalyzer.analyze_tags`/`analyze` and inject it into the scanner.
- **New format support:** extend `config.FILE_SIGNATURES`, `SUPPORTED_EXTENSIONS`, `file_analyzer._FORMAT_EXTENSIONS`, and the Pillow fallback paths.
- **New report format:** add an exporter and extend `export_report`/`export_batch_report`.

## 8. Dependencies

- **Pillow** — image validation, decode, fallback extraction and re-encode.
- **ExifTool** — primary extraction and lossless metadata writing.
- **pytest** — test suite.

No web framework, database, or network library is used.
