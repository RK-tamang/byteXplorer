# ByteXplorer

A collection of security and reverse engineering tools.

## Tools

### Static Malware Analyzer
A production-grade static analysis tool for Windows PE (Portable Executable) malware.

**Location:** `tools/`

**Features:**
- PE/DOS header parsing
- Hash computation (MD5, SHA1, SHA256, imphash)
- Section entropy analysis
- Suspicious API detection
- IOC extraction (URLs, IPs, domains, emails, paths)
- Risk scoring and severity assessment
- Multi-format reports (JSON, Markdown, DOCX, PDF)

**Quick Start:**
```bash
cd tools
pip install -r requirements.txt
pip install -e .

# Analyze malware
byteXplorerStatic malware.exe --output ./reports --format all
```

See `tools/README.md` for full documentation.
