# MetaClean
### Image Metadata Scanner, Privacy Risk Analyzer & Sanitizer

MetaClean is a command-line tool for inspecting image metadata, assessing privacy risks, removing supported metadata, and verifying the cleaned result.

- **Project type:** Cybersecurity graduation project
- **Target environment:** Linux Mint / Ubuntu
- **Language:** Python 3
- **Metadata engine:** ExifTool (recommended)
- **License:** MIT

---

## Table of Contents

1. [Overview](#1-overview)
2. [Features](#2-features)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Quick Start](#5-quick-start)
6. [Usage Examples](#6-usage-examples)
7. [Selective Metadata Removal](#7-selective-metadata-removal)
8. [Verification Results](#8-verification-results)
9. [Batch Processing](#9-batch-processing)
10. [Security and Privacy Notes](#10-security-and-privacy-notes)
11. [Supported Formats](#11-supported-formats)
12. [Running Tests](#12-running-tests)
13. [Limitations](#13-limitations)
14. [Project Structure](#14-project-structure)
15. [License](#15-license)

---

## 1. Overview

Images can contain more than visible pixels. Metadata may include GPS coordinates, capture dates, camera details, author information, comments, and copyright details. Sharing this information unintentionally can expose private or identifying information.

MetaClean helps users:

1. Scan an image for available metadata.
2. Assess potential privacy risks.
3. Remove all supported metadata or selected categories.
4. Verify the output after cleaning.
5. Export reports for review and auditing.

**Important:** Metadata availability depends on the image, its source, and the software used to create or edit it. A scan cannot guarantee that every possible form of hidden information has been detected.

## 2. Features

- **Metadata scanning:** Inspect supported embedded metadata.
- **Privacy risk assessment:** Classify detected metadata using the project's rules.
- **Metadata cleaning:** Remove supported metadata from a copy of the input image.
- **Selective cleaning:** Target categories such as GPS, dates, device details, and author information.
- **Independent verification:** Check whether targeted metadata remains after cleaning.
- **Batch processing:** Process a directory of images.
- **Audit reports:** Export supported report formats such as JSON or CSV.
- **Input validation:** Validate image files and apply configured safety limits.
- **Automated tests:** Run the test suite with `pytest`.

## 3. Requirements

For Linux Mint or Ubuntu, you need:

- Python 3
- `python3-venv` and `python3-pip`
- ExifTool (strongly recommended)
- Git, if you are cloning the repository

## 4. Installation

### Option A: Quick installation (recommended)

#### Step 1 — Install system packages

Open a terminal with `Ctrl+Alt+T` and run:

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv libimage-exiftool-perl
```

#### Step 2 — Download the project

Run these commands only if you do not already have the project:

```bash
git clone https://github.com/mobadawyx4/MetaClean-.git
cd MetaClean-
```

If the project is already on your computer, go to its directory instead:

```bash
cd ~/MetaClean-
```

#### Step 3 — Install MetaClean

```bash
chmod +x install.sh
./install.sh
```

The installer creates a virtual environment and installs the Python dependencies. If ExifTool is missing, the script attempts to install it using `apt`.

#### Step 4 — Start MetaClean

```bash
./venv/bin/python main.py
```

### Option B: Manual installation

If you prefer to install dependencies yourself:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libimage-exiftool-perl
cd ~/MetaClean-
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt
```

Then start the application:

```bash
./venv/bin/python main.py
```

### Verify ExifTool

```bash
exiftool -ver
```

To check whether MetaClean detects ExifTool:

```bash
./venv/bin/python -c "import config; print('ExifTool Available:', config.EXIFTOOL_AVAILABLE, config.EXIFTOOL_PATH)"
```

## 5. Quick Start

Start the interactive menu:

```bash
./run.sh
```

Scan an image:

```bash
./run.sh scan photo.jpg
```

Clean an image and save the result to a new file:

```bash
./run.sh clean photo.jpg --output cleaned_photo.jpg --yes
```

Verify the cleaned image:

```bash
./run.sh verify cleaned_photo.jpg
```

Replace `photo.jpg` with the path to your own image. If a command or option is not available in your installed version, check the command help:

```bash
./run.sh --help
```

## 6. Usage Examples

The examples below assume that you are running commands from the project directory and that the input image is named `photo.jpg`.

### Scan an image

```bash
./run.sh scan photo.jpg
```

Show detailed metadata:

```bash
./run.sh scan photo.jpg --detailed
```

Export scan output as JSON, if supported by the command:

```bash
./run.sh scan photo.jpg --json
```

### Remove supported metadata

Save a cleaned copy without overwriting the original:

```bash
./run.sh clean photo.jpg --output cleaned_photo.jpg --yes
```

### Verify an image

```bash
./run.sh verify cleaned_photo.jpg
```

### Generate a report

```bash
./run.sh report photo.jpg --output audit_report.json --cleaned cleaned_photo.jpg
```

### Process a directory

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --yes
```

For all available commands and options, use the application's help output and interactive menu.

## 7. Selective Metadata Removal

MetaClean supports category-based removal through the `--remove` option where available. For example:

```bash
./run.sh clean photo.jpg --output cleaned_photo.jpg --remove gps,date --yes
```

Remove device and author information:

```bash
./run.sh clean photo.jpg --output cleaned_photo.jpg --remove device,author --yes
```

Common category names used by the project include:

| Category | Examples |
| --- | --- |
| `gps` | GPS coordinates, altitude, and position |
| `date` | Capture and creation timestamps |
| `device` | Camera make, model, lens, and device details |
| `author` | Creator, artist, owner, and contact information |
| `copyright` | Copyright and usage information |
| `comments` | Comments, descriptions, and user notes |
| `exif` | EXIF metadata |
| `iptc` | IPTC metadata |
| `xmp` | XMP metadata |
| `all` | All supported removable metadata |

**Note:** Selective cleaning intentionally retains categories that were not selected. Review the verification result before sharing the output.

## 8. Verification Results

The project uses these verification statuses:

- **`PASS`** — The configured checks passed and no targeted metadata was detected.
- **`WARNING`** — Some unselected sensitive metadata or partial remnants may remain.
- **`INCOMPLETE`** — Verification could not fully inspect some metadata structures, for example when ExifTool is unavailable.
- **`FAIL`** — Targeted metadata was detected, the file was invalid, or a check failed.

A `PASS` result applies to the checks performed by MetaClean; it is not a guarantee that an image contains no possible hidden data.

## 9. Batch Processing

Process images in a directory:

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --yes
```

Process subdirectories recursively and write a CSV report:

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --recursive --report ./audit.csv --yes
```

Export a JSON summary:

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --format json --yes
```

The exact options depend on the current CLI implementation. Use the help output if an option is rejected.

## 10. Security and Privacy Notes

- Keep an untouched backup of important files.
- Review the output path before running cleaning commands.
- MetaClean is designed to save cleaned output separately from the source image.
- ExifTool is recommended for broader metadata handling and verification.
- Metadata removal does not blur faces, remove visible text, or detect every possible steganographic payload.
- File-system timestamps are separate from metadata embedded inside an image.
- Always review the cleaned image and verification report before sharing it.

## 11. Supported Formats

The project is designed to work with common image formats including:

- JPEG (`.jpg`, `.jpeg`)
- PNG (`.png`)
- WebP (`.webp`)
- TIFF (`.tif`, `.tiff`)
- BMP (`.bmp`)

Actual extraction, removal, and verification capabilities can vary by format and by whether ExifTool is available.

## 12. Running Tests

Install the dependencies first, then run:

```bash
./venv/bin/python -m pytest tests -v
```

Run a specific test module:

```bash
./venv/bin/python -m pytest tests/test_validator.py -v
./venv/bin/python -m pytest tests/test_scanner.py -v
./venv/bin/python -m pytest tests/test_remover.py -v
./venv/bin/python -m pytest tests/test_verifier.py -v
./venv/bin/python -m pytest tests/test_batch.py -v
```

## 13. Limitations

- MetaClean focuses on supported image metadata structures such as EXIF, IPTC, and XMP.
- It does not guarantee detection of steganography or hidden information encoded in pixel values.
- Some proprietary or complex metadata may require ExifTool for fuller inspection.
- Removing metadata does not remove sensitive content visibly present in the image itself.

## 14. Project Structure

```text
MetaClean-/
├── main.py
├── config.py
├── requirements.txt
├── install.sh
├── run.sh
├── modules/
│   ├── image_validator.py
│   ├── metadata_scanner.py
│   ├── privacy_analyzer.py
│   ├── metadata_remover.py
│   ├── metadata_verifier.py
│   ├── report_generator.py
│   └── batch_processor.py
└── tests/
```

## 15. License

MetaClean is released under the MIT License. See the [`LICENSE`](LICENSE) file for the license text.
