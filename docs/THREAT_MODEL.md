# MetaClean Threat Model

This document defines the assets MetaClean protects, the adversaries it considers, the trust boundaries it crosses, and the mitigations implemented in version 2.0.

## 1. Scope

MetaClean is a local, offline command-line tool. It reads untrusted image files, reports what metadata they contain, writes a sanitized copy, and verifies the result.

### In scope

- Metadata disclosure through shared images.
- Malformed or adversarial image containers.
- Unsafe handling of filenames, paths, and metadata values.
- Accidental destruction or modification of user files.
- Misleading verification claims.
- Accidental leakage through reports and logs.

### Out of scope

- Steganography and arbitrary pixel-level encoding.
- Visible sensitive content (faces, documents, screenshots).
- Compromised operating system or ExifTool binary.
- Network interception (the tool performs no network access).
- Side-channel attacks against the host.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Original image files | Irreplaceable user data. |
| Exported cleaned images | The artifact the user intends to publish. |
| Metadata values | GPS, identity, device identifiers, timestamps. |
| Reports | Aggregate sensitive data into one file. |
| Filesystem paths | Can reveal usernames, project names, or directory structure. |
| User trust in verification | A false "clean" claim causes real-world harm. |

## 3. Adversaries and threat sources

| Actor | Capability | Motivation |
| --- | --- | --- |
| **Recipient / viewer** | Receives a shared image and reads its metadata. | Deanonymization, stalking, profiling. |
| **Malicious image author** | Crafts adversarial containers, long values, control characters, malformed EXIF. | Crash the tool, inject terminal escapes, exploit downstream consumers. |
| **Careless user** | Runs cleaning in the wrong directory, overwrites outputs, exports unredacted reports. | Accidental data loss or disclosure. |
| **Local attacker** | Pre-creates symlinks or hardlinks at output paths. | Redirect writes to sensitive files. |
| **Report consumer** | Opens CSV/HTML reports in spreadsheets or browsers. | Formula injection or script execution via metadata. |
| **Verification adversary** | Relies on an incorrect "clean" result. | False assurance. |

## 4. Trust boundaries

```text
[untrusted file] ──► validator ──► ExifTool ──► parser ──► analyzer
                                                         │
[user terminal] ◄── escaped rendering ◄──────────────────┘
       │
       ├──► reports (JSON/CSV/HTML) ──► external consumers
       │
       └──► sanitized output ──► recipient
```

1. **File boundary:** every byte from the input is untrusted.
2. **Metadata boundary:** tag names and values are untrusted even after parsing.
3. **Process boundary:** ExifTool output is parsed, never evaluated.
4. **Presentation boundary:** terminal and report output must be escaped.
5. **Filesystem boundary:** output paths must not resolve to the input or through links.

## 5. Threat table

| # | Threat | Vector | Mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| T1 | Original file modified | Cleaning in place | Temporary copy + atomic replace; same-inode and symlink refusal | Low |
| T2 | Output overwritten unexpectedly | Pre-existing destination | Existence check + confirmation unless `--yes` | Low |
| T3 | Symlink clobbering | Attacker pre-creates output symlink | `Path.is_symlink()` refusal; `os.samefile` check | Low |
| T4 | Batch pulls in files outside the target | Symlink inside input directory | Symlinks skipped by default; opt-in `--follow-symlinks` | Medium (user opt-in) |
| T5 | Batch re-processes its own output | Output nested under input | Output directory excluded from discovery | Low |
| T6 | Command injection via filename | Filename containing shell metacharacters | Argument-list subprocess calls; `--` before paths; no shell | Low |
| T7 | Terminal escape injection | Metadata containing ANSI/control bytes | Values stringified and length-limited; `_safe_preview` hex for binary; no control-byte pass-through in reports | Medium |
| T8 | HTML/JS injection in report | Metadata containing `<script>` | `html.escape` on every rendered value; no external assets | Low |
| T9 | Spreadsheet formula injection | Metadata beginning with `=`, `+`, `-`, `@` | `_csv_safe` prefixes a single quote | Low |
| T10 | Unredacted report leak | User exports with `--no-redact` | Redacted by default; explicit opt-in; warning and TTY confirmation | Medium (deliberate) |
| T11 | False "clean" claim | ExifTool exit 0 but tags remain | Independent re-scan; residual allowlist; explicit outcomes | Low |
| T12 | Verification with weak backend | ExifTool missing | Pillow fallback reports `VERIFICATION FAILED` rather than clean | Low |
| T13 | Corrupt image crashes the tool | Truncated/broken containers | Validation + per-file exception isolation | Low |
| T14 | Resource exhaustion | Huge files, pixel bombs, many files | Size limit, pixel limit, subprocess timeout, batch file cap | Medium |
| T15 | Metadata executed as code | Template/expression-looking values | Values are never evaluated; only displayed/escaped | Low |
| T16 | Misleading selective clean | Unselected categories retain data | Explicit warning + PARTIALLY CLEANED/SENSITIVE DATA REMAINS outcomes | Medium (inherent) |

## 6. Security requirements traced to implementation

| Requirement | Implementation |
| --- | --- |
| Never modify originals | `metadata_remover.clean` writes to `mkstemp` copy |
| Never trust extensions | `image_validator` magic bytes + `file_analyzer` container detection |
| Never execute metadata | No `eval`, `exec`, templates, or shell interpolation |
| Safe subprocess use | `exiftool_backend` builds argv lists with `--` |
| Preserve uncommitted work | Tool only writes to explicit output paths |
| No hidden network activity | No HTTP/socket imports in the codebase |
| Deterministic reports | Fixed scoring constants; no random values in scan output |

## 7. Assumptions

- The user runs MetaClean on a trusted host with a genuine ExifTool binary.
- The output directory is writable by the user and not attacker-controlled.
- Filesystem permissions enforce normal OS isolation.
- The user reviews the verification outcome before publishing.

## 8. Verification guarantees and non-guarantees

`VERIFIED CLEAN` guarantees, for the selected profile:

1. The output re-opened as a valid image with matching dimensions.
2. No non-structural metadata remains for a full-clean profile, or no sensitive finding remains in targeted categories for a selective profile.
3. No sensitive finding was newly introduced.
4. The inspection backend could read the relevant structures.

`VERIFIED CLEAN` does **not** guarantee:

- Absence of steganographic or pixel-embedded data.
- Absence of metadata in structures the backend cannot parse.
- That the visible image is safe to publish.
- That a recipient cannot infer context from the image itself.

## 9. Residual risks and future mitigations

- **Vendor MakerNotes** may contain undocumented fields. Future work: per-vendor tag dictionaries and differential removal testing.
- **Control characters** in metadata could still reach a terminal if a future renderer bypasses the escaping helpers. Future work: centralised output sanitizer.
- **Very large batches** can exhaust disk space. Future work: pre-flight free-space check.
- **Fallback cleaning re-encodes** and may alter pixels slightly. Future work: surface a quality-delta metric.
- **Ambiguous risk rules** can under- or over-classify. Future work: rule-versioning and a labelled evaluation corpus.
