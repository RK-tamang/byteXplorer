# ByteXplorer

A collection of security and reverse engineering tools.

## Tools

### Static Malware Analyzer
A production-grade static analysis tool for Windows PE (Portable Executable) malware.

**Location:** `tool/staticAnalyser/`

**Features:**
- PE/DOS header parsing
- Hash computation (MD5, SHA1, SHA256, imphash)
- Section entropy analysis
- Suspicious API detection
- IOC extraction (URLs, IPs, domains, emails, paths)
- Risk scoring and severity assessment
- Multi-format reports (JSON, Markdown, DOCX, PDF)

See `tool/staticAnalyser/README.md` for full documentation.
