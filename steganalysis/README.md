# 🔬 Steganalysis Tool

> Detects hidden data in image files — LSB steganography, metadata,
> embedded files, high-entropy regions. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](steganalysis.py)
[![Forensics](https://img.shields.io/badge/Use-Digital%20Forensics%20%7C%20CTF-blue?style=flat-square)](.)

---

## Overview

Steganalysis Tool analyzes image files for signs of hidden data without
requiring external libraries. Useful for digital forensics, CTF challenges,
and incident response investigations.

```bash
# Analyze a single image
python steganalysis.py suspicious.png

# Analyze directory
python steganalysis.py ./images/ --recursive

# Verbose output (show all findings)
python steganalysis.py image.jpg --verbose

# JSON output
python steganalysis.py image.png --json -o analysis.json
```

---

## Analysis Modules

### PNG Analysis

| Check               | Description                    | Indicators                                     |
| ------------------- | ------------------------------ | ---------------------------------------------- |
| Chunk validation    | Validate all PNG chunks        | Unknown/suspicious chunk types                 |
| CRC verification    | Verify chunk CRC values        | CRC mismatch = modified file                   |
| Non-standard chunks | Detect hidden text/data chunks | `tEXt`, `zTXt`, `iTXt` with suspicious content |
| Trailing data       | Data after IEND chunk          | Any bytes after `IEND` marker                  |
| IHDR anomalies      | Image header flags             | Interlace method, color type inconsistencies   |

### JPEG Analysis

| Check              | Description           | Indicators                          |
| ------------------ | --------------------- | ----------------------------------- |
| EXIF metadata      | Extract all EXIF tags | GPS location, camera info, software |
| GPS coordinates    | Extract location data | Hidden location information         |
| Comment markers    | JPEG comment fields   | `FFE0`/`FFFE` comment data          |
| Trailing data      | Data after EOI marker | Any bytes after `FFD9`              |
| XMP metadata       | Adobe XMP data        | Suspicious embedded XML             |
| Thumbnail analysis | Embedded thumbnails   | Different content in thumbnail      |

### Universal Analysis

| Check                | Description                    | Indicators                                     |
| -------------------- | ------------------------------ | ---------------------------------------------- |
| Shannon entropy      | Per-region entropy calculation | High entropy > 7.5 = encrypted/compressed data |
| Magic byte detection | 20+ file signatures            | ZIP, RAR, PDF, EXE, script inside image        |
| String extraction    | ASCII/UTF-8 strings            | URLs, IPs, commands, flags, passwords          |
| Interesting patterns | Security-relevant strings      | URLs, emails, IPs, PEM keys, CTF flags         |
| LSB analysis         | Least Significant Bit patterns | Unusual LSB distribution in pixels             |

---

## Usage

```bash
# Basic analysis
python steganalysis.py image.png

# Analyze all images in directory
python steganalysis.py ./uploads/ --recursive

# Extract all strings (min 8 chars)
python steganalysis.py image.jpg --strings --min-len 8

# Check for specific file signature embedded
python steganalysis.py image.png --check-magic

# JSON output for automation
python steganalysis.py image.png --json -o report.json

# Verbose — show all details including clean checks
python steganalysis.py image.png --verbose
```

---

## Example Output

```
  STEGANALYSIS REPORT
  File   : suspicious.png
  Size   : 245,760 bytes
  Type   : PNG
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] Embedded ZIP file detected
  Evidence : Magic bytes at offset 184,320: PK\x03\x04 (ZIP)
  Fix      : Extract embedded file: dd if=suspicious.png bs=1 skip=184320 of=embedded.zip

  [HIGH] Trailing data after IEND chunk
  Evidence : 61,440 bytes after IEND marker (expected: 0)
  Fix      : Extract trailing data for analysis

  [HIGH] High entropy region detected
  Evidence : Bytes 120000-180000: entropy=7.89/8.0 (likely encrypted)

  [MEDIUM] GPS coordinates in EXIF
  Evidence : Latitude: 41.1496, Longitude: -8.6109

  [LOW] Suspicious strings found
  Evidence : http://evil-c2.xyz/payload.bin
             FLAG{h1dd3n_1n_pl41n_s1ght}

  Entropy     : 7.12/8.0 (medium — possible steganographic content)
  Risk Score  : 85/100
```

---

## CTF Tips

```bash
# Common CTF steg workflow
python steganalysis.py challenge.png            # 1. Initial analysis
python steganalysis.py challenge.png --strings  # 2. Extract all strings
python steganalysis.py challenge.png --json     # 3. Get structured data

# Extract embedded file if detected
dd if=challenge.png bs=1 skip=<OFFSET> of=embedded_file

# Check for LSB steganography hints
python steganalysis.py challenge.png --verbose | grep -i lsb

# Look for common CTF patterns
python steganalysis.py challenge.png --strings | grep -E "FLAG|CTF|{.*}"
```

---

## Repository Structure

```
steganalysis/
├── steganalysis.py
├── test_images/
│   └── README.md        ← Instructions to obtain test images
├── README.md
└── .gitignore
```

---

## References

- [PNG Specification](https://www.w3.org/TR/PNG/)
- [JPEG/EXIF Specification](https://www.cipa.jp/std/documents/e/DC-008-2012_E.pdf)
- [Steganography Tools Overview](https://0xrick.github.io/lists/stego/)
- [CTF Steganography Resources](https://github.com/DominicBreuker/stego-toolkit)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*
