# Static Malware Analyzer

A production-grade static analysis tool for Windows PE (Portable Executable) malware.

---

## Windows Installation

### Step 1: Open Command Prompt

Press `Win + R`, type `cmd`, press Enter.

### Step 2: Navigate to Tool Directory

```cmd
cd path\to\byteXplorer\tool\staticAnalyser
```

### Step 3: Create Virtual Environment

```cmd
python -m venv venv
```

### Step 4: Activate Virtual Environment

```cmd
venv\Scripts\activate
```

### Step 5: Install Dependencies (Windows)

```cmd
pip install -r requirements-win.txt
```

### Step 6: Install Package

```cmd
pip install -e .
```

### Uninstall

```cmd
pip uninstall bytexplorer-static
```

---

## Linux/macOS Installation

### Step 1: Navigate to Tool Directory

```bash
cd path/to/byteXplorer/tool/staticAnalyser
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv
```

### Step 3: Activate Virtual Environment

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
pip install -r requirements-linux.txt
```

### Step 5: Install Package

```bash
pip install -e .
```

---

## Usage

After installation, use `byteXplorerStatic` from **any directory**:

```cmd
# Basic analysis
byteXplorerStatic C:\malware\sample.exe

# With output directory
byteXplorerStatic C:\malware\sample.exe --output C:\reports

# Specific format
byteXplorerStatic sample.exe --output C:\reports --format json

# All formats + verbose
byteXplorerStatic sample.exe -o C:\reports --format all -v
```

### Options

| Option | Description |
|--------|-------------|
| `file_path` | Path to PE file (required) |
| `-o, --output` | Output directory (default: ./reports) |
| `-f, --format` | Format: json, md, docx, pdf, all (default: all) |
| `-v, --verbose` | Show detailed logs |

---

## Report Output

Reports are saved in the output directory:

```
C:\reports\
├── sample.exe.json
├── sample.exe.md
├── sample.exe.docx
└── sample.exe.pdf
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Analyze file | `byteXplorerStatic sample.exe` |
| JSON only | `byteXplorerStatic sample.exe -f json` |
| PDF only | `byteXplorerStatic sample.exe -f pdf` |
| Custom output | `byteXplorerStatic sample.exe -o C:\myreports` |
| Verbose mode | `byteXplorerStatic sample.exe -v` |

---

## Risk Scoring

| Indicator | Score |
|-----------|-------|
| High entropy section (>7.0) | +10 each |
| RWX section | +30 |
| Suspicious APIs | +3 each |
| Suspicious strings | +5 each |

**Severity:** Low (0-30) | Medium (31-70) | High (71-100)
