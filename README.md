# MetaClean — Complete Image Metadata Scanner, Privacy Risk Analyzer & Sanitizer

> **Academic Graduation Project in Cybersecurity & Digital Privacy**  
> **Author:** MetaClean Research & Engineering Team  
> **Target Environment:** Linux Mint (Terminal) / Cross-Platform POSIX & Windows  
> **Version:** 1.0.0  
> **Status:** Production-Ready & Verified

---

## 1. Executive Summary & Problem Statement

In the modern digital landscape, digital cameras, smartphones, drones, and image editing software automatically embed rich metadata into images upon capture and modification. Standard specifications such as **EXIF** (Exchangeable Image File Format), **IPTC** (International Press Telecommunications Council), and **XMP** (Extensible Metadata Platform) routinely encode:

* **High-Precision Geolocation:** Decimal GPS coordinates (latitude, longitude, altitude) accurate to within centimeters.
* **Temporal Footprints:** Microsecond capture timestamps, digitization dates, and timezone offsets.
* **Hardware & Device Fingerprints:** Camera make, model, lens serial numbers, internal device identifiers, and firmware versions.
* **Personal Identity Information (PII):** Author names, copyright holders, user comments, system paths, and embedded thumbnail images that may retain uncropped sensitive visual data.

### The Threat Model
When users upload photos to forums, e-commerce platforms, customer support tickets, or peer-to-peer communication networks, this embedded metadata presents critical privacy and operational security risks:
1. **Physical Stalking and Geospatial Profiling:** Reverse-geocoding EXIF GPS coordinates exposes homes, workplaces, travel routines, and sensitive meeting sites.
2. **De-anonymization and OSINT Correlation:** Serial numbers and author tags allow adversaries to correlate disparate online personas to a single physical device or person.
3. **Information Leakage via Thumbnails:** Cropping an image in consumer software often leaves the original, uncropped embedded thumbnail intact in EXIF headers.

**MetaClean** is an end-to-end, command-line cybersecurity tool engineered to solve this vulnerability through a rigorous 5-stage pipeline:

```
SCAN ──────► ANALYZE ──────► REMOVE ──────► VERIFY ──────► EXPORT
(Extract)    (Risk Model)   (Sanitize)     (Independent)  (JSON/CSV)
```

---

## 2. Core Architecture & System Design

MetaClean is architected as a modular, decoupled Python 3.11+ system prioritizing non-destructive execution, strict security controls, and verifiability:

```
MetaClean/
├── main.py                     # CLI entrypoint with argparse & terminal formatting
├── config.py                   # Central settings, categories, risk rules & ExifTool detection
├── requirements.txt            # Python dependencies (Pillow, pytest)
├── README.md                   # Technical documentation and Linux Mint guide
├── .gitignore                  # Git artifact isolation
├── modules/
│   ├── __init__.py
│   ├── image_validator.py      # Magic bytes signature validation & security limits
│   ├── metadata_scanner.py     # Multi-engine metadata extraction & filesystem isolation
│   ├── privacy_analyzer.py     # Rule-based privacy scoring & classification engine
│   ├── metadata_remover.py     # Lossless ExifTool sanitization & Pillow fallback
│   ├── metadata_verifier.py    # Independent compliance audit & status determination
│   ├── report_generator.py     # Sanitized JSON & CSV audit report exporter
│   └── batch_processor.py      # Batch directory processor with collision avoidance
└── tests/
    ├── __init__.py
    ├── conftest.py             # Synthetic test image fixtures (JPEG, PNG, WebP, TIFF)
    ├── test_validator.py       # Validation and security boundary tests
    ├── test_scanner.py         # Metadata extraction and privacy scoring tests
    ├── test_remover.py         # Full & selective removal, immutability tests
    ├── test_verifier.py        # Independent verification audit tests
    └── test_batch.py           # Batch processing, isolation, and CSV export tests
```

---

## 3. Installation Guide (Linux Mint & Ubuntu)

MetaClean is designed to run natively in Linux Mint terminal environments.

### Step 1: System Package Installation
Open a terminal (`Ctrl+Alt+T`) and install Python 3, venv, and ExifTool:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libimage-exiftool-perl
```

### Step 2: Clone or Navigate to Project Directory
```bash
cd /path/to/MetaClean
```

### Step 3: Create & Activate Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 4: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5: Verify ExifTool Installation
```bash
exiftool -ver
python3 -c "import config; print('ExifTool Available:', config.EXIFTOOL_AVAILABLE, config.EXIFTOOL_PATH)"
```

---

## 4. Command-Line Interface & Usage Examples

### 🌟 Ultra-Easy Mode (Interactive Menu & Shortcuts)

MetaClean is designed to be as effortless as possible:

```bash
# 1. Interactive Menu (واجهة تفاعلية سهلة جداً بالأرقام):
python3 main.py

# 2. Direct Shortcut (اسحب الصورة أو اكتب مسارها مباشرة للفحص):
python3 main.py photo.jpg

# 3. Clean in One Step (تنظيف وحفظ تلقائي بدون تعقيد):
python3 main.py clean photo.jpg
```

---

### A. Scanning an Image
Scans an image, isolates filesystem attributes from embedded tags, and evaluates privacy risk:

```bash
# Basic scan (shows all metadata, exact GPS, and Google Maps link)
python3 main.py scan photo.jpg

# Detailed tag-by-tag inspection
python3 main.py scan photo.jpg --detailed

# Export scan directly to JSON
python3 main.py scan photo.jpg --json
```

**Example Output:**
```
Target File: photo.jpg
Format: JPEG | Dimensions: 4032x3024 | Size: 3,452,118 bytes

--- Filesystem Attributes (Non-Embedded) ---
  • Modified on Disk: 2026-10-16T18:30:00+00:00
  • Created on Disk:  2026-10-16T18:30:00+00:00

--- Embedded Metadata Scan ---
  • GPS Location Data: DETECTED (8 tags)
  • Capture / Creation Timestamps: DETECTED (2 tags)
  • Camera & Device Information: DETECTED (5 tags)
  • Author & Personal Identity: DETECTED (1 tags)
  • Copyright & Licensing Terms: NOT DETECTED
  • Comments & Descriptions: NOT DETECTED
  • IPTC Application Record: NOT DETECTED
  • XMP Metadata Block: NOT DETECTED

Privacy Risk Assessment: [ HIGH RISK ] (Risk Score: 100/100)
  CRITICAL PRIVACY RISK: Image contains 9 high-risk identifying tags.
```

---

### B. Removing All Supported Metadata
Sanitizes all EXIF, GPS, IPTC, XMP, comments, and thumbnails, preserving the original file untouched and saving the output to a new file:

```bash
python3 main.py clean photo.jpg --output cleaned_photo.jpg --yes
```

**Guarantees:**
* **Immutability:** Original `photo.jpg` is never overwritten.
* **Lossless Quality:** Direct stream-level metadata stripping without JPEG recompression or DCT artifact generation.
* **Transparency Preservation:** Alpha channels in PNG and WebP are preserved intact.
* **Automated Audit:** An independent verification pass is automatically triggered post-sanitization.

---

### C. Removing Selected Metadata Categories
Allows selective removal of targeted categories while preserving non-sensitive shooting settings:

```bash
# Remove only GPS and capture timestamps
python3 main.py clean photo.jpg --output cleaned_photo.jpg --remove gps,date --yes

# Remove device serials and author info
python3 main.py clean photo.jpg --output cleaned_photo.jpg --remove device,author --yes
```

**Supported Categories:**
| Category | Description | Primary Targeted Tags |
| :--- | :--- | :--- |
| `gps` | Coordinates, altitude, speed, track | `GPSLatitude`, `GPSLongitude`, `GPSAltitude`, `GPSPosition` |
| `date` | Capture, creation, digitization times | `DateTimeOriginal`, `CreateDate`, `ModifyDate`, `SubSecTime` |
| `device` | Hardware make, model, lens & serials | `Make`, `Model`, `SerialNumber`, `LensModel`, `Software` |
| `author` | Creator, artist, owner, and contact data | `Artist`, `Creator`, `By-line`, `Author`, `OwnerName` |
| `copyright`| Copyright notices and usage terms | `Copyright`, `CopyrightNotice`, `Rights`, `UsageTerms` |
| `comments` | User comments and notes | `Comment`, `UserComment`, `ImageDescription`, `XPComment` |
| `exif` | Complete EXIF block | All standard EXIF tags |
| `iptc` | Complete IPTC block | All IPTC Application Record tags |
| `xmp` | Extensible Metadata Platform XML | All XMP namespace properties |
| `all` | Complete metadata sanitization | All removable structures |

> [!WARNING]
> Selective category removal retains unselected metadata. MetaClean displays an explicit warning and verification flag whenever unselected sensitive metadata remains in the output.

---

### D. Independent Verification Audit
Audits any image file to determine whether targeted or sensitive metadata persists:

```bash
python3 main.py verify cleaned_photo.jpg
```

**Verification Statuses:**
* **`PASS`**: All defined category checks passed; zero targeted metadata detected.
* **`WARNING`**: Targeted categories passed, but unselected sensitive tags remain, or partial remnants found.
* **`INCOMPLETE`**: ExifTool is unavailable and Pillow fallback cannot verify complex IPTC/XMP structures.
* **`FAIL`**: Targeted metadata was detected, file is corrupted, or validation failed.

---

### E. Batch Directory Processing
Sanitizes entire collections of images with failure isolation and automated collision avoidance:

```bash
# Process directory with automated collision resolution
python3 main.py batch ./raw_photos --output-dir ./sanitized_photos --yes

# Recursive subfolder processing with CSV summary
python3 main.py batch ./raw_photos --output-dir ./sanitized_photos --recursive --report ./audit.csv --yes

# Export batch summary as JSON
python3 main.py batch ./raw_photos --output-dir ./sanitized_photos --format json --yes
```

**Batch Safety Guarantees:**
1. **Error Isolation:** If `image_04.jpg` is corrupted, MetaClean logs the error and continues processing subsequent files without terminating.
2. **Collision Avoidance:** If `photo.jpg` already exists in the destination, MetaClean automatically resolves the name to `photo_1.jpg`, `photo_2.jpg`.
3. **Source Protection:** Input files are opened read-only; source directories are never mutated.

---

### F. Generating Comprehensive Security & Audit Reports
Generates detailed forensic JSON reports suitable for compliance documentation and security audits:

```bash
python3 main.py report photo.jpg --output audit_report.json --cleaned cleaned_photo.jpg
```

**Key Report Sections:**
* Image dimensions, color profile, and hash attributes.
* Isolated OS filesystem metadata vs embedded tags.
* Itemized privacy risk assessment with justification narratives.
* Removed categories diff and remaining fields listing.
* Independent verification check status and audit logs.
* Masked / sanitized previews (protecting raw GPS/PII from cleartext log leakage).

---

## 5. Privacy Risk Scoring Model

MetaClean implements a transparent, deterministic rule-based evaluation matrix:

| Level | Severity Score | Criteria | Security Justification |
| :--- | :---: | :--- | :--- |
| **HIGH** | `70 – 100` | GPS Coordinates, Latitude/Longitude, Personal Author Name, Contact Info | Enables physical tracking, geospatial pattern-of-life profiling, and direct de-anonymization. |
| **MEDIUM** | `35 – 69` | Capture Timestamps, Camera Serial Numbers, Device Models, User Comments | Enables temporal correlation, hardware fingerprinting across distinct accounts, and social engineering. |
| **LOW** | `10 – 34` | Technical Settings (ISO, Aperture, Shutter Speed, Focal Length, White Balance) | Technical photography parameters; minimal personal privacy risk under standard threat models. |
| **INFORMATIONAL** | `0` | Image Width, Height, Bit Depth, Compression Scheme | Fundamental raster dimensions required to render the image. |

---

## 6. Security Hardening & Implementation Standards

MetaClean incorporates defensive programming practices throughout:

1. **File Signature Validation:**
   Validates magic bytes (`0xFFD8FF` for JPEG, `0x89504E47` for PNG, `RIFF...WEBP` for WebP, `II*\x00` / `MM\x00*` for TIFF) before parsing. Prevents extension spoofing attacks (e.g., executing arbitrary scripts disguised as `.jpg`).
2. **Decompression Bomb Mitigation:**
   Enforces configurable pixel thresholds (`MAX_IMAGE_PIXELS = 100,000,000`) and file size limits (`MAX_FILE_SIZE_BYTES = 100 MB`) to defeat zip bombs and memory exhaustion attacks.
3. **Safe Subprocess Invocation:**
   All external ExifTool executions pass arguments as structured `List[str]` directly to `subprocess.run(shell=False)` with a 30-second timeout. Untrusted filenames are never interpolated into shell command strings.
4. **Path Traversal & Null Byte Sanitization:**
   Paths are expanded, normalized, and checked for null bytes (`\0`) and circular traversal before filesystem operations.
5. **Atomic Operations & Cleanup:**
   Temporary files are allocated using `tempfile.NamedTemporaryFile` and cleaned up inside strict `try...finally` blocks.

---

## 7. Supported Formats & Capabilities

| Format | Extension | ExifTool Lossless Stripping | Pillow Fallback Stripping | Transparency Preserved |
| :--- | :--- | :---: | :---: | :---: |
| **JPEG** | `.jpg`, `.jpeg` | Yes (Lossless) | Yes (Clean copy) | N/A |
| **PNG** | `.png` | Yes (Lossless) | Yes (Clean copy) | Yes (RGBA/LA) |
| **WebP** | `.webp` | Yes (Lossless) | Yes (Clean copy) | Yes (RGBA) |
| **TIFF** | `.tif`, `.tiff` | Yes (Lossless) | Yes (Clean copy) | Yes |
| **BMP** | `.bmp` | Yes | Yes | N/A |

---

## 8. Automated Testing & Verification

The project includes an automated test suite executed via `pytest`.

### Running Tests
```bash
# Run all tests
python3 -m pytest tests -v

# Run specific module tests
python3 -m pytest tests/test_validator.py -v
python3 -m pytest tests/test_scanner.py -v
python3 -m pytest tests/test_remover.py -v
python3 -m pytest tests/test_verifier.py -v
python3 -m pytest tests/test_batch.py -v
```

### Test Coverage Highlights
* **Synthetic Images:** Dynamically generates valid JPEG, PNG (with alpha transparency), WebP, and TIFF images.
* **Security Edge Cases:** Tests decompression bomb limits, oversized files, null-byte path injections, extension spoofing, and truncated headers.
* **Original File Immutability:** Uses SHA-256 cryptographic hashing to ensure the original input image is byte-for-byte unchanged during sanitization.
* **Degraded Environment Resilience:** Simulates environments where ExifTool is absent and validates automatic graceful fallback to Pillow.
* **Collision Resolution:** Tests multi-stage collision avoidance (`photo_1.jpg`, `photo_2.jpg`).

---

## 9. Limitations & Future Research

### Known Operational Limitations
* **Proprietary Steganography:** MetaClean targets standardized metadata headers (EXIF, IPTC, XMP). It does not detect steganographic payloads concealed within the least significant bits (LSB) of pixel data.
* **Pillow Fallback Limitations:** In environments lacking ExifTool, Pillow fallback cannot fully inspect or selectively manipulate nested XML structures in XMP or proprietary MakerNotes blocks. Installing `libimage-exiftool-perl` is strongly recommended for production use.

### Future Work
* Integration with a lightweight local machine-learning classifier to detect optical text (OCR) within images (e.g. street signs or license plates) that present visual privacy risks beyond metadata.
* Native integration as a Git pre-commit hook to prevent accidental metadata leakage in software repositories.

---

## 10. License & Academic Attribution
Developed as an academic graduation project in Cybersecurity. Released under the MIT License for educational and privacy preservation purposes.
