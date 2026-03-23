from pathlib import Path
from typing import List
from models.analysis import AnalysisResult
from utils.logger import setup_logger
from .json_reporter import JSONReporter
from .markdown_reporter import MarkdownReporter
from .docx_reporter import DOCXReporter
from .pdf_reporter import PDFReporter

class ReportGenerator:
    def __init__(self, result: AnalysisResult, output_dir: Path, logger=None):
        self.result = result
        self.output_dir = output_dir
        self.logger = logger or setup_logger()
        
        # Generate executive summary
        self.result.executive_summary = self._generate_executive_summary()
    
    def generate_reports(self, formats: List[str]):
        for fmt in formats:
            try:
                reporter = self._get_reporter(fmt)
                filename = self.result.file_info.filename
                if not filename:
                    filename = Path(self.result.file_info.full_path).name
                output_path = self.output_dir / filename
                reporter.generate(output_path)
                self.logger.info(f"Generated {fmt} report: {output_path}.{fmt}")
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")
    
    def _get_reporter(self, fmt: str):
        reporters = {
            "json": JSONReporter,
            "md": MarkdownReporter,
            "docx": DOCXReporter,
            "pdf": PDFReporter,
        }
        reporter_class = reporters.get(fmt)
        if not reporter_class:
            raise ValueError(f"Unknown format: {fmt}")
        return reporter_class(self.result, self.logger)
    
    def _generate_executive_summary(self) -> str:
        ass = self.result.assessment
        severity_lower = ass.severity.value.lower() if hasattr(ass.severity, 'value') else str(ass.severity).lower()
        return f"""Analyzed {self.result.file_info.filename} ({self.result.file_info.size_bytes:,} bytes).

The file shows {severity_lower} risk characteristics.
Score: {ass.score:.1f}/100 | Packer: {ass.packer_status.value if hasattr(ass.packer_status, 'value') else ass.packer_status}

Key findings:
- {'Suspicious sections detected' if any(s.suspicious for s in self.result.sections) else 'No anomalous sections'}
- {'Suspicious imports found' if any(i.suspicious for i in self.result.imports) else 'No suspicious APIs'}
"""

