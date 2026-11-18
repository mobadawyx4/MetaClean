# MetaClean Methodology

This document explains how MetaClean extracts metadata, how it classifies privacy risk, how sanitization profiles are defined, and how verification decisions are made. It is intended to make the tool's reasoning reproducible and auditable.

## 1. Extraction methodology

### 1.1 Backend selection

MetaClean uses ExifTool as its primary extraction backend. If ExifTool is unavailable, it falls back to Pillow, which reads the EXIF IFD, the Exif SubIFD, the GPS IFD, and common `img.info` keys (`icc_profile`, `xmp`, text chunks).

The fallback is deliberately conservative:

- It cannot inspect IPTC application records, structured XMP, or proprietary MakerNotes.
- It records explicit limitations in `ScanResult.limitations`.
- Verification under the fallback returns `VERIFICATION FAILED` rather than a clean claim.

### 1.2 ExifTool invocation

All calls go through `modules/exiftool_backend.py`. The base command is:

```text
exiftool -charset filename=UTF8 -json -G1 -a -u [mode flags] -- <path>
```

- `-json` returns machine-readable output.
- `-G1` preserves the metadata group (e.g. `EXIF`, `XMP-dc`, `GPS`, `MakerNotes`).
- `-a` allows duplicate tags so no same-named tag hides another.
- `-u` includes unknown tags.
- `--` terminates option parsing before the path.
- A hard timeout bounds execution.

Mode-specific flags:

| Mode | Flags | Purpose |
| --- | --- | --- |
| `standard` | base | Named and unknown tags. |
| `deep` | `-struct` + numeric second pass | Structured XMP/IPTC plus raw numeric values. |
| `privacy` | same as deep | Privacy-focused reporting view. |
| `full` | `-struct -ee` + numeric pass | Embedded-file extraction and exhaustive inspection. |

The numeric pass is a second invocation with `-n`, used to decode GPS coordinates and obtain true numeric values without locale formatting.

`-api RequestAll=3` is intentionally **not** used: it injects nondeterministic tags such as `ExifTool:Now` and `NewGUID`, which would pollute reports and comparisons.

### 1.3 Tag provenance

Every extracted tag becomes a `MetadataTag` with:

| Field | Meaning |
| --- | --- |
| `group` | ExifTool group family (`IFD0`, `GPS`, `XMP-dc`, `MakerNotes`, ...). |
| `family` | Coarse family (`EXIF`, `GPS`, `XMP`, `IPTC`, `MakerNotes`, `ICC`, `Container`, ...). |
| `name` | Tag name. |
| `value` | Parsed value as returned by ExifTool. |
| `raw_value` | Numeric/raw value from the `-n` pass, when available. |
| `display_value` | Safe string rendering. |
| `value_type` | Inferred presentation type (`integer`, `decimal-string`, `datetime-string`, `rational-string`, `list`, `structure`, ...). |
| `extraction_status` | `extracted` or `empty`. |
| `derived` | `true` for ExifTool `Composite` tags. |
| `category` | Semantic category (see §2). |

`extraction_status = empty` distinguishes "tag present but empty" from "tag absent". Empty tags are excluded from privacy scoring because they expose nothing.

### 1.4 Derived and structural separation

- `Composite` tags (e.g. `GPSPosition`, `ImageSize`) are marked `derived` and excluded from privacy scoring to avoid double-counting.
- `ExifTool` and `System` groups are dropped during extraction: they describe the tool and the filesystem, not the image.
- Filesystem timestamps are reported in a separate `filesystem_metadata` block and never mixed with embedded tags.

## 2. Semantic categorization

`_classify_tag` maps each tag to one category. Rule precedence matters; earlier rules win:

1. ICC groups → `informational`.
2. `System` group → filesystem (excluded).
3. Filesystem `File` tags → filesystem (excluded).
4. Structural/technical allowlist → `informational` (except `ImageUniqueID` → `identifiers`). This includes `Orientation`, `ColorSpace`, `ExifVersion`, `FlashpixVersion`, `InteropVersion`, `ComponentsConfiguration`, and composition fields such as `SubjectLocation`/`SubjectArea`/`SubjectDistance`.
5. Tag names beginning with `MakerNote` (vendor blobs embedded in ordinary IFD0 groups) → `makernotes`.
6. Thumbnail/preview content tags (`ThumbnailImage`, `PreviewImage`, `OtherImage`, `JpgFromRaw`, read-only preview representations) → `thumbnail`. Offset/length/size companions are not classified here because they cannot be deleted safely on their own.
7. Geographic positioning and textual location → `gps`.
8. Unique document identifiers → `identifiers`.
9. MakerNotes group: serial/lens/model IDs → `device`, otherwise `makernotes`.
10. Software/creator-tool fields → `software`.
11. Device make/model/serial/lens/firmware/host/device IDs → `device`.
12. Author/creator/contact/owner fields → `author`.
13. Copyright/rights → `copyright`.
14. Comments/descriptions/titles/keywords → `comments`.
15. Timestamps → `date`.
16. Remaining IPTC → `iptc`, XMP → `xmp`, EXIF IFDs → `exif`.
17. Anything else → `other`.

Rule 7 uses explicit textual place names (`City`, `State`, `Country`,
`Sub-location`, `Location`, `ContentLocation*`, `LocationCreated*`,
`LocationShown*`, `RatingRegion*`, `Geography`) in addition to GPS values, so
`location` also removes where a photo was taken as written in IPTC/XMP. Fields
prefixed with `creator` (`CreatorCity`, `CreatorCountry`) are contact data and
stay in `author`. `SubjectLocation` is image-relative pixel data and stays
`informational`.

Rules 10–15 deliberately separate the editing software (`software`) from camera
hardware (`device`): `Software` and `ProcessingSoftware` are detected as
`software` even though `-*Software*` is also part of the `device` removal
arguments. `Make`/`Model` are exact matches so GeoTIFF `ModelTiePoint` and
`ModelTransform` are not mistaken for camera hardware.


## 3. Privacy taxonomy

### 3.1 Levels

| Level | Rationale |
| --- | --- |
| `CRITICAL` | Directly locates or identifies a person. Irreversible once disclosed. |
| `HIGH` | Strong identifier or persistent fingerprint (names, serials, unique IDs, previews). |
| `MEDIUM` | Correlatable or contextual data (timestamps, device model, copyright, comments). |
| `LOW` | Technical settings with weak identifying value. |
| `INFORMATIONAL` | Container, geometry, colour management; no personal impact. |

GPS coordinates are classified `CRITICAL`, not `HIGH`: they pinpoint a residence or workplace and enable physical harm. GPS altitude is `HIGH` because it refines location. GPS reference fields (`N/S/E/W`) are `INFORMATIONAL` on their own.

### 3.2 Special rules

- **Contact detection:** known contact tags (`Contact`, `Email`, `Phone`, `Address`, `CreatorContactInfo`, `CIAdr*`) are `CRITICAL`. Free-text fields (comments, descriptions, captions, keywords) are also promoted to `CRITICAL` when their value matches an email or phone pattern.
- **Preview masking:** email addresses embedded in free text are masked in the preview (`a***@example.com`), and serial numbers are partially masked (`SN1****890`).
- **MakerNotes:** serial-like fields are `HIGH`; other non-empty entries are `LOW`; empty entries are `INFORMATIONAL`.
- **Software before creator:** software fields are matched before the generic `creator` substring so `CreatorTool` is not mistaken for an author name.
- **ICC is never personal:** every ICC tag is `INFORMATIONAL`.

### 3.3 Scoring

The score is additive with per-level weights and caps:

```text
contribution(level) = min(count(level) × weight(level), cap(level))
score               = min(100, Σ contribution(level))
```

| Level | Weight | Cap |
| --- | --- | --- |
| `CRITICAL` | 35 | 70 |
| `HIGH` | 18 | 45 |
| `MEDIUM` | 7 | 21 |
| `LOW` | 2 | 6 |
| `INFORMATIONAL` | 0 | 0 |

Worked example — a photo with latitude and longitude (`CRITICAL` × 2), an author name (`HIGH` × 1), a capture timestamp (`MEDIUM` × 1), and camera make (`MEDIUM` × 1):

```text
CRITICAL: min(2 × 35, 70) = 70
HIGH:     min(1 × 18, 45) = 18
MEDIUM:   min(2 × 7, 21)  = 14
LOW:      0
INFO:     0
score = min(100, 70 + 18 + 14) = 100
overall_risk = CRITICAL
```

The overall risk is the maximum level among findings, independent of the score.

**Validity statement:** the weights, caps, and category rules are fixed constants chosen for explainability. They are not derived from a validated empirical study and should not be presented as a scientific risk metric.

## 4. Deep file analysis

`modules/file_analyzer.py` inspects the physical file rather than trusting its name.

| Check | Method | Finding class |
| --- | --- | --- |
| Container vs extension | Magic bytes compared with declared suffix | `CONFIRMED` |
| MIME mismatch | Pillow `Image.MIME` vs `mimetypes.guess_type` | `SUSPICIOUS` |
| Unknown container | No supported signature | `CONFIRMED` |
| Decode failure | Pillow cannot load pixels | `CONFIRMED` |
| Bit depth / colour model | Pillow mode; PNG IHDR parsed directly | `INFORMATIONAL` |
| Animation | `n_frames` > 1 | `INFORMATIONAL` |
| ICC profile | `img.info["icc_profile"]` | `INFORMATIONAL` |
| Embedded previews | Thumbnail/preview tag names | `SUSPICIOUS` |
| Trailing data | Bytes after JPEG EOI / PNG IEND / RIFF or BMP declared size | `SUSPICIOUS` |
| Timestamp contradictions | Embedded dates vs filesystem dates | `SUSPICIOUS` |
| Parser warnings | ExifTool warnings | `SUSPICIOUS` |

Binary previews are rendered as hex, never as text, so arbitrary bytes cannot reach the terminal as control sequences.

## 5. Sanitization methodology

### 5.1 Profiles as semantic contracts

A profile is a named set of categories with an explicit verification expectation:

| Profile | Categories | Full-clean expectation |
| --- | --- | --- |
| `basic` | gps, author, comments, copyright | No |
| `location` | gps | No |
| `personal` | author, copyright, comments, identifiers | No |
| `maximum` | all | Yes |
| `custom` | user-supplied | No (unless `all` is supplied) |

### 5.2 Selective removal arguments

Category arguments are intentionally cross-group. ExifTool treats unqualified
tag names and wildcards as "match in any writable group", which is what privacy
removal needs because the same concept appears in EXIF, IPTC, and several XMP
namespaces:

| Category | Argument strategy | Deliberate coverage |
| --- | --- | --- |
| `gps` | `-GPS:all=`, `-GPS*=`, `-*Latitude=`, `-*Longitude=`, `-*Coordinates=`, explicit place names, `-*Location*=`, `-*EarthPos*=` | Native GPS, XMP GPS, IPTC/XMP place names, drone/Keys/Darwin Core location fields |
| `date` | `-*Date*=`, `-*Timestamp*=`, `-*Timecode*=`, `-SubSecTime*=`, `-OffsetTime*=`, enumerated time names | Includes GPS date stamps and vendor `TimeStamp` tags; excludes `ExposureTime` and shutter-release lag settings |
| `device` | `-Make=`, `-Model=`, `-*Model=`, `-*ModelID=`, `-*ModelName=`, `-*Serial*=`, `-*Lens*=`, `-*Firmware*=`, `-*Software*=`, `-*Device*=` | Vendor model IDs, serial/lens aliases, device IDs, and editing software |
| `author` | `Artist`, `-*Creator*=`, `-*Contributor*=`, `By-line`, `-*OwnerName=`, `-*Owner=`, `-*OwnerID=`, `Author*`, `Contact`, `Credit*`, `Source`, `Writer-Editor` | Creator/owner identity across EXIF, IPTC, XMP, PLUS, and vendor schemas |
| `comments` | `-*Comment*=`, `-*Description=`, `-*Caption*=`, `-*Keyword*=`, `-*Notes=`, `-*Instructions=`, exact `Title`/`Subject`/`Headline`/`ObjectName` | Collects plural/vendor aliases while keeping `SubjectArea`/`SubjectDistance` out of the comment bucket |
| `software` | `-*Software*=`, `CreatorTool`, `XMPToolkit`, `HistorySoftwareAgent`, `PreviewApplication*`, `CreatorAppID`, `CreatorOpenWithUIOptions` | Application identity that does not contain "software" |
| `identifiers` | `ImageUniqueID`, `-*UniqueID=`, `DocumentID`, `InstanceID`, `OriginalDocumentID`, `VersionID`, `Identifier`, `-*PhotoIdentifier=` | Tracking IDs across EXIF, XMP, and Apple metadata |
| `thumbnail` | `ThumbnailImage`, `ThumbnailPNG`, `SanyoThumbnail`, `PreviewImage`, `OtherImage`, `JpgFromRaw`, `PhotoshopThumbnail`, `PhotoshopBGRThumbnail` | Read-only preview representations are only removed by `all` |

`Make`/`Model` use exact names, and the broader `-*Model=` wildcard only matches
tag names that *end* in `Model`; GeoTIFF georeferencing tags (`ModelTiePoint`,
`ModelTransform`, `ModelPixelScale`) do not match. A generic `*location*`
wildcard is also avoided because it would remove `SubjectLocation`, which is
image-relative pixel data rather than a place.

`tests/test_category_coverage.py` locks this down in four directions: every tag
in `config.METADATA_CATEGORIES[...]["tags"]` must classify into that category
(with the documented `Software`/`ProcessingSoftware` alias); every writable tag
in ExifTool's own database that the classifier targets must match that
category's arguments; every removal argument must be accepted by ExifTool
without an "undefined/not writable" warning; and every targeted category must be
empirically emptied on a synthetic fixture while orientation and unrelated
categories survive.

### 5.3 Cleaning procedure

1. Resolve the input and output paths without following a final-component symlink (`safe_resolve_path`).
2. Refuse directories, symbolic links, and outputs that alias the input (identical path, `..`/relative alias, hardlink, or same device/inode).
3. Refuse to overwrite an existing output unless explicitly allowed.
4. Create a private temporary file in the destination directory with `mkstemp`.
5. Copy the input into it through a descriptor opened with `O_NOFOLLOW`, verifying device/inode/ctime against the identity captured before validation.
6. Run ExifTool with deletion arguments and `-overwrite_original` on the **temporary** file only.
7. Validate the working copy before installation: readable image, non-zero size, dimensions matching the input (sorted, so orientation transposition is allowed).
8. Re-check the destination immediately before replacement: it must still not be a symlink, its identity must be unchanged, the output directory identity must be unchanged, and the temporary file must still be the validated file.
9. Atomically install with `os.replace` (same directory, same filesystem).
10. Record the exact arguments, operations attempted, and update count.

No fallible operation runs after step 9.  A pre-existing destination has been atomically replaced at that point and cannot be restored, so the implementation deliberately performs all validation, dimension checks, and identity checks beforehand.  This guarantees that a backend failure, a truncated or malformed working copy, a dimension mismatch, a symlink swap, or a changed destination leaves the existing destination byte-for-byte intact.

The Pillow fallback follows the same staging: it re-encodes into the temporary file, that file is validated, and only then is it installed.  It never writes directly to the destination.

For full cleaning, the arguments are:

```text
-all= -tagsFromFile @ -ColorSpaceTags -Orientation -overwrite_original
```

This strips writable metadata while restoring colour-space and orientation tags so rendering does not change.

The Pillow fallback supports **full cleaning only**. Selective removal requires ExifTool because a pixel re-encode cannot target metadata groups; the tool reports this rather than pretending to succeed.

### 5.4 Path and symlink policy (F-06)

| Path kind | Policy | Enforcement |
| --- | --- | --- |
| Scan/verify input | Final-component symlink refused | `safe_resolve_path` lstat gate; `O_NOFOLLOW` reads |
| Clean input | Final-component symlink refused; identity re-checked at copy time | `file_identity` + `copy_regular_file_no_follow` |
| Clean destination | Existing or dangling symlink refused; same-file aliases refused | lstat gate, `os.path.samefile`, device/inode comparison |
| Batch input/output directory | Symlinked input or output directory refused | `safe_resolve_path(..., allow_dir=True)` |
| Batch discovered files | Symlinks skipped by default | `discover_images` |
| Batch `--follow-symlinks` | Explicit opt-in; the resolved target is read and written to the output directory, never through the link | `Path.resolve(strict=True)` before scan/clean |
| Report output | Symlink refused | `safe_resolve_path` in `report_generator` |
| Temporary file | Created privately; removed only if its identity still matches | `_discard_temp` |

Intermediate directory symlinks are resolved once.  Refusing them would break common systems where `/tmp`, home directories, or mounted volumes are symlinked; the destructive-operation guarantees are therefore anchored on the final component and on identity checks performed immediately before `os.replace`.

Time-of-check/time-of-use limits:

* POSIX platforms use `O_NOFOLLOW`, so a final-component symlink swap between the lstat gate and the open fails with `ELOOP` instead of following the link.
* The destination is re-`lstat`-ed immediately before `os.replace`; a symlink or a different inode/ctime aborts the install.
* `os.replace` itself is a single atomic syscall within one directory.  A process that can rewrite the destination directory between that last check and the syscall still races the kernel; eliminating that window would require `openat`/`renameat2` with directory file descriptors and is documented as a residual limitation.
* On platforms without `O_NOFOLLOW` (notably Windows), the policy degrades to an lstat gate plus post-open identity check.  The final-component race window is therefore wider there.
* Filesystems that do not implement POSIX symlink/hardlink semantics (some network or FAT mounts) cannot provide these guarantees; MetaClean refuses symlink entries it can see, but cannot enforce permissions the filesystem does not have.
* `ctime` granularity varies by filesystem.  Identity comparison uses device, inode and `ctime_ns`; on a filesystem with coarse timestamps, inode recycling immediately after deletion could theoretically evade the "destination changed" check.

## 6. Verification methodology

### 6.1 Independent re-scan

Verification never reuses the extraction that produced the file. It performs a fresh scan of the output, then:

1. Collects category checks for targeted categories.
2. Collects sensitive findings (`MEDIUM` or higher).
3. Computes residual non-structural tags using `config.is_structural_tag`.
4. Optionally compares the original and cleaned scans.
5. Decides an outcome from the evidence.

### 6.2 Structural allowlist

A full clean may legitimately leave container and decoder structure: `File`, `System`, `ExifTool`, `JFIF`, `PNG`, `RIFF`, `GIF`, `ICC_Profile`, `Composite:ImageSize`, `Composite:Megapixels`, plus an explicit list of geometry/encoding tags. Those are not user metadata and do not prevent `VERIFIED CLEAN`.

### 6.3 Decision procedure

```text
if backend cannot inspect OR file invalid:
    → VERIFICATION FAILED

if any sensitive finding belongs to a targeted category
   OR (full clean AND targeted tags remain):
    → SENSITIVE DATA REMAINS

if full clean AND residual non-structural tags remain:
    if any sensitive finding remains  → SENSITIVE DATA REMAINS
    else                             → PARTIALLY CLEANED

if selective AND any sensitive finding remains (unselected categories):
    → PARTIALLY CLEANED

if comparison found newly introduced tags:
    → PARTIALLY CLEANED

otherwise:
    → VERIFIED CLEAN
```

The legacy status is computed independently and preserved for report compatibility:

| Legacy status | Condition |
| --- | --- |
| `PASS` | No targeted remnants and no sensitive residual. |
| `WARNING` | Selective remnants, or sensitive residual in unselected categories. |
| `INCOMPLETE` | Backend lacks coverage (Pillow fallback). |
| `FAIL` | Targeted metadata remains under a full-clean request, or invalid input. |

## 7. Comparison methodology

`compare_scans(before, after)` produces:

- **Removed tags:** present before, absent after.
- **Remaining tags:** non-structural tags still present.
- **Changed tags:** present in both with different values.
- **Introduced tags:** absent before, present after (a warning sign).
- **Sensitive removed / remaining:** risk items keyed by tag key.
- **Risk score before / after.**

Structural tags are separated so that container changes do not look like user metadata.

## 8. Reporting methodology

### 8.1 Redaction

Reports are redacted by default. Redaction is an **allowlist**, not a
blacklist: a redacted report only contains fields that cannot identify a
person, a device, or a file.

Allowed by default:

- Tag identity and classification: group, family, name, category, value type,
  extraction status, derived flag, risk level.
- Container facts from an explicit structural tag allowlist (`FileType`,
  `MIMEType`, dimensions, colour space, compression, orientation, resolution,
  bit depth). `FileName`, `Directory`, `SourceFile`, filesystem timestamps and
  permission bits are never in that allowlist.
- Counts, booleans, scores, category names, static explanations and
  recommendations.

Withheld by default:

- Every non-structural metadata value: names, serial numbers, comments,
  copyright, software, dates, MakerNotes and GPS.
- GPS decimal values, formatted coordinates and map URLs.
- Absolute paths, filenames, removal output paths and report-rendered names.
- Filesystem timestamps and permission bits.
- Free-text value previews, file-analysis evidence and previews, and every
  before/after comparison value.
- Batch filenames (replaced by positional labels `image_001`, …), output paths
  and per-file notes.

Defence in depth: after the allowlist is applied, a scrub pass replaces any
known identifier literal (input path, filename, masked metadata value) that
survives in a fallback field, and masks e-mail addresses, phone numbers and
home/temporary-directory paths found in free text.

Unredacted export requires an explicit `redact=False` / `--no-redact`, prints
a warning, and asks for confirmation on a TTY. Single-image and batch exports
share the same default.

### 8.2 Output encoding

- **HTML:** every metadata-derived value passes through `html.escape`; the document is self-contained and loads no external resources.
- **CSV:** values beginning with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with `'` to neutralise spreadsheet formulas.
- **JSON:** serialized through an allowlisted default encoder. Bytes become a
  tagged base64 object, dates/times become ISO 8601, paths become strings,
  UUID and `Decimal` become strings, sets become deterministically sorted
  lists, tuples become lists, and enums become their values. `NaN`,
  `Infinity` and unsupported objects raise `JSONEncodingError`; no value is
  ever stringified with `repr`/`str`.
- **Write safety:** every report is rendered in memory and staged in the
  destination directory, then installed with `os.replace` after a final
  symlink check. A serialization error, a symlink swap or a write failure
  leaves an existing report untouched and removes only the private staging
  file.
- **Terminal:** values are stringified, length-limited, and binary previews are hex-encoded.

### 8.3 Methodology disclosure

Every JSON and HTML report includes a methodology note stating that scores are heuristic and that `VERIFIED CLEAN` covers only the inspected structures for the selected profile.

## 9. Evaluation and limitations

The implementation is evaluated with synthetic images only:

- Generated JPEG/PNG/WebP/TIFF/BMP files with controlled EXIF, GPS, text, alpha, and trailing data.
- Corrupted and mismatched containers.
- Duplicate and symlinked batch inputs.
- CLI round-trips validating exit codes and redaction.

This provides deterministic regression coverage but is **not** a representative corpus. Known limitations:

- Vendor MakerNotes may contain fields not covered by the taxonomy.
- ExifTool's parser coverage varies by camera and format.
- The score is an explanatory heuristic.
- Steganography and pixel content are out of scope.

Future evaluation should include a labelled corpus of real camera files, differential testing before/after cleaning, and comparison against independent metadata viewers.
