from pathlib import Path
from models.analysis import AnalysisResult, Severity, PackerStatus
from .base_reporter import BaseReporter

class MarkdownReporter(BaseReporter):
    def generate(self, output_path: Path):
        md_content = self._generate_markdown()
        output_file = str(output_path) + ".md"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
    
    def _generate_markdown(self) -> str:
        result = self.result
        sections = result.sections
        imports = result.imports
        
        md = f"""# Static Malware Analysis Report

## Executive Summary
{result.executive_summary}

**File**: {result.file_info.filename}
**Severity**: {result.assessment.severity.value if hasattr(result.assessment.severity, 'value') else result.assessment.severity}
**Packer Status**: {result.assessment.packer_status.value if hasattr(result.assessment.packer_status, 'value') else result.assessment.packer_status}
**Score**: {result.assessment.score:.1f}/100

## File Information
- **Filename**: {result.file_info.filename}
- **Size**: {result.file_info.size_bytes:,} bytes
- **Type**: {result.file_info.file_type}

## Hashes
```
MD5:    {result.hashes.md5}
SHA1:   {result.hashes.sha1}
SHA256: {result.hashes.sha256}
```
"""
        
        if result.pe_header:
            md += f"""
## PE Header
- Machine: {result.pe_header.machine_type}
- Timestamp: {result.pe_header.timestamp}
- Entry Point: 0x{result.pe_header.entry_point:X}
"""
        
        # Sections
        md += "## Sections Analysis\n"
        md += "| Name | Entropy | Size | Suspicious |\n|------|---------|------|------------|\n"
        for sec in sections:
            susp = "✅" if sec.suspicious else "❌"
            md += f"| {sec.name} | {sec.entropy:.2f} | {sec.raw_size:,} | {susp} |\n"
        
        # Imports
        if imports:
            md += "\n## Imports\n"
            for imp in imports:
                mark = "⚠️" if imp.suspicious else ""
                md += f"### {imp.dll}\n- " + "  \\n".join(imp.apis) + f"{mark}\n"
        
        md += f"""
## Assessment
**Severity**: {result.assessment.severity.value if hasattr(result.assessment.severity, 'value') else result.assessment.severity}
**Score**: {result.assessment.score:.1f}
**Reasons**: {', '.join(result.assessment.reasons) or 'None'}
"""
        
        if result.iocs:
            md += "\n## IOCs\n"
            for ioc in result.iocs:
                md += f"- **{ioc.type.upper()}**: {ioc.value}\n"
        
        if result.exports:
            md += "\n## Exports\n"
            for exp in result.exports:
                md += f"- {exp}\n"
        
        return md

