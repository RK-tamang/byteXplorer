# Static Malware Analyzer

A production-grade static analysis tool for Windows PE (Portable Executable) malware. Analyzes executables without running them.

## Features

- **PE/DOS Header Parsing** - Extracts machine type, entry point, image base, sections, imports, exports
- **Hash Computation** - MD5, SHA1, SHA256, imphash
- **Section Analysis** - Entropy calculation, RWX detection, suspicious section identification
- **Import/Export Analysis** - DLL imports, suspicious API detection (40+ APIs across 10+ DLLs)
- **String Extraction** - ASCII/Unicode strings with IOC extraction
- **IOC Detection** - URLs, IPs, domains, emails, registry keys, file paths
- **Risk Assessment** - Scoring algorithm (0-100) with Low/Medium/High severity
- **Packer Detection** - Heuristics based on entropy and section characteristics
- **Multi-format Reports** - JSON, Markdown, DOCX, PDF with executive summary

## Installation

### Linux/macOS
```bash
cd tools
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

**Note:** On Linux, you need `libmagic1` for python-magic:
```bash
# Debian/Ubuntu
sudo apt-get install libmagic1

# Fedora/RHEL
sudo dnf install file-devel

# Arch
sudo pacman -S file
```

### Windows
```cmd
cd tools
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Basic analysis (generates all report formats)
byteXplorerStatic malware.exe --output ./reports

# Specific format
byteXplorerStatic malware.exe --output /path/to/reports --format json

# Multiple formats
byteXplorerStatic malware.exe -o ./reports -f pdf

# Verbose mode
byteXplorerStatic malware.exe -o ./reports --format all -v
```

### Options
- `file_path` - Path to the PE file to analyze (required)
- `-o, --output` - Output directory (default: ./reports)
- `-f, --format` - Report format: json, md, docx, pdf, or all (default: all)
- `-v, --verbose` - Enable verbose logging

## Report Formats

| Format | Description |
|--------|-------------|
| JSON | Machine-readable full analysis data |
| Markdown | Human-readable report with tables |
| DOCX | Word document report |
| PDF | PDF report with styled tables |

Reports are named after the malware file: `malware.exe.json`, `malware.exe.pdf`, etc.

## Risk Scoring

| Indicator | Points |
|-----------|--------|
| High entropy section (>7.0) | +10 per section |
| RWX (executable+writable) section | +30 |
| Suspicious API imports | +3 per API (max 25) |
| Suspicious strings (cmd, powershell) | +5 per string (max 15) |
| System32 path references | +3 per reference (max 10) |

**Severity:**
- Low: 0-30
- Medium: 31-70
- High: 71-100

## Project Structure

```
tools/
├── src/
│   ├── main.py              # CLI entry point
│   ├── analyzers/           # Analysis modules
│   │   ├── file_analyzer.py
│   │   ├── pe_analyzer.py
│   │   ├── hash_analyzer.py
│   │   └── string_analyzer.py
│   ├── models/              # Data models
│   │   └── analysis.py
│   ├── reporters/           # Report generators
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   ├── docx_reporter.py
│   │   └── pdf_reporter.py
│   └── utils/              # Utilities
│       ├── entropy.py
│       └── logger.py
├── setup.py                # Package setup
├── requirements.txt        # Dependencies
└── README.md
```

## Requirements

- Python 3.8+
- pefile
- python-magic (Linux) / python-magic-bin (Windows)
- python-docx
- reportlab
- colorlog
