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
git clone https://github.com/mobadawyx4/MetaClean.git
cd MetaClean
```

If the project is already on your computer, go to its directory instead:

```bash
cd ~/MetaClean
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
cd ~/MetaClean
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

### Windows (PowerShell)

**Requirements:** Python 3 and Windows PowerShell. Install Python from https://www.python.org/downloads/windows/ and enable Python on PATH.

1. Install ExifTool using WinGet:

   ```powershell
   winget install --id OliverBetz.ExifTool --exact
   ```

2. Open PowerShell in the MetaClean project folder.

3. Install dependencies:

   ```powershell
   .\install.ps1
   ```

4. Run MetaClean:

   ```powershell
   .\run.ps1 --help
   .\run.ps1 scan photo.jpg
   ```

Replace `photo.jpg` with your image path. If ExifTool was just installed, reopen PowerShell.

## 5. Quick Start

MetaClean is a command-line application. Run a subcommand directly; there is no interactive menu.

### Windows PowerShell

Run these commands from the project folder:

```powershell
.\install.ps1
.\run.ps1 --help
.\run.ps1 scan .\photo.jpg
.\run.ps1 clean .\photo.jpg --output .\cleaned_photo.jpg --yes
.\run.ps1 verify .\cleaned_photo.jpg
```

### Linux Mint

Run these commands from the project folder:

```bash
chmod +x install.sh run.sh
./install.sh
./run.sh --help
./run.sh scan photo.jpg
./run.sh clean photo.jpg --output cleaned_photo.jpg --yes
./run.sh verify cleaned_photo.jpg
```

Replace `photo.jpg` with the path to your image. Keep a backup of important originals.

## 6. Usage Examples

The examples below assume that the input image is named `photo.jpg` and that commands are run from the project folder.

### Scan an image

Windows PowerShell:

```powershell
.\run.ps1 scan .\photo.jpg
.\run.ps1 scan .\photo.jpg --detailed
.\run.ps1 scan .\photo.jpg --json
```

Linux Mint:

```bash
./run.sh scan photo.jpg
./run.sh scan photo.jpg --detailed
./run.sh scan photo.jpg --json
```

### Remove metadata

Save a cleaned copy without overwriting the original.

Windows PowerShell:

```powershell
.\run.ps1 clean .\photo.jpg --output .\cleaned_photo.jpg --yes
```

Linux Mint:

```bash
./run.sh clean photo.jpg --output cleaned_photo.jpg --yes
```

### Verify an image

Windows PowerShell:

```powershell
.\run.ps1 verify .\cleaned_photo.jpg
.\run.ps1 verify .\cleaned_photo.jpg --json
```

Linux Mint:

```bash
./run.sh verify cleaned_photo.jpg
./run.sh verify cleaned_photo.jpg --json
```

### Generate an audit report

Windows PowerShell:

```powershell
.\run.ps1 report .\photo.jpg --output .\audit_report.json --cleaned .\cleaned_photo.jpg
```

Linux Mint:

```bash
./run.sh report photo.jpg --output audit_report.json --cleaned cleaned_photo.jpg
```

### Process a directory

Create the input directory and put images in it before running these examples.

Windows PowerShell:

```powershell
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --yes
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --recursive --report .\audit.csv --yes
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --format json --report .\audit.json --yes
```

Linux Mint:

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --yes
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --recursive --report ./audit.csv --yes
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --format json --report ./audit.json --yes
```

For all supported commands and options, run `.\run.ps1 COMMAND --help` on Windows or `./run.sh COMMAND --help` on Linux.

## 7. Selective Metadata Removal

Use `--remove` to choose which metadata categories to remove. Supported categories are `gps`, `date`, `device`, `author`, `copyright`, `comments`, `exif`, `iptc`, `xmp`, and `all`.

Windows PowerShell:

```powershell
.\run.ps1 clean .\photo.jpg --output .\no_gps.jpg --remove gps --yes
.\run.ps1 clean .\photo.jpg --output .\no_device_author.jpg --remove device,author --yes
```

Linux Mint:

```bash
./run.sh clean photo.jpg --output no_gps.jpg --remove gps --yes
./run.sh clean photo.jpg --output no_device_author.jpg --remove device,author --yes
```

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

Selective cleaning retains categories that were not selected. Review the verification result before sharing the output.

## 8. Verification Results

The project uses these verification statuses:

- **`PASS`** — The configured checks passed and no targeted metadata was detected.
- **`WARNING`** — Some unselected sensitive metadata or partial remnants may remain.
- **`INCOMPLETE`** — Verification could not fully inspect some metadata structures, for example when ExifTool is unavailable.
- **`FAIL`** — Targeted metadata was detected, the file was invalid, or a check failed.

A `PASS` result applies to the checks performed by MetaClean; it is not a guarantee that an image contains no possible hidden data.

## 9. Batch Processing

Batch processing requires an input directory and `--output-dir`. Use `--recursive` to include subdirectories, and `--report` to save a CSV or JSON summary.

Windows PowerShell:

```powershell
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --yes
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --recursive --report .\audit.csv --yes
.\run.ps1 batch .\raw_photos --output-dir .\sanitized_photos --format json --report .\audit.json --yes
```

Linux Mint:

```bash
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --yes
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --recursive --report ./audit.csv --yes
./run.sh batch ./raw_photos --output-dir ./sanitized_photos --format json --report ./audit.json --yes
```

Run the batch command's help output to see all available options.

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
MetaClean/
├── main.py
├── config.py
├── requirements.txt
├── install.sh
├── install.ps1
├── run.sh
├── run.ps1
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
