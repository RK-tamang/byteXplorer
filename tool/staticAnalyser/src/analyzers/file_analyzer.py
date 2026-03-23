import magic
from pathlib import Path
from typing import Dict, Any
from models.analysis import AnalysisResult, FileInfo, Hashes, Severity, Assessment, PackerStatus
from utils.logger import setup_logger
from .hash_analyzer import HashAnalyzer
from .pe_analyzer import PEAnalyzer
from .string_analyzer import StringAnalyzer

class FileAnalyzer:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.logger = setup_logger()
        
    def analyze(self) -> AnalysisResult:
        self.logger.info("Starting analysis")
        
        # Basic file info
        file_info = self._get_file_info()
        
        # Hashes
        hashes = HashAnalyzer(self.file_path).analyze()
        
        analysis_data = {
            "file_info": file_info,
            "hashes": hashes,
            "sections": [],
            "imports": [],
            "exports": [],
            "suspicious_strings": [],
            "iocs": [],
        }
        
        # PE analysis if applicable
        if file_info.is_pe:
            pe_analyzer = PEAnalyzer(self.file_path)
            pe_data = pe_analyzer.analyze()
            analysis_data.update(pe_data)
        else:
            analysis_data["pe_header"] = None
        
        # String analysis
        string_analyzer = StringAnalyzer(self.file_path)
        suspicious_strings, iocs = string_analyzer.analyze()
        analysis_data["suspicious_strings"] = suspicious_strings
        analysis_data["iocs"] = iocs
        
        # Update assessment with suspicious strings
        if "assessment" in analysis_data and suspicious_strings:
            ass = analysis_data["assessment"]
            new_reasons = list(ass.reasons)
            new_score = ass.score
            
            cmd_strings = [s for s in suspicious_strings if any(x in s.lower() for x in ['cmd.exe', 'rundll32', 'powershell', 'wscript'])]
            if cmd_strings:
                new_score += min(len(cmd_strings) * 5, 15)
                new_reasons.append(f"{len(cmd_strings)} suspicious command strings")
            
            sys32_strings = [s for s in suspicious_strings if 'system32' in s.lower()]
            if sys32_strings:
                new_score += min(len(sys32_strings) * 3, 10)
                new_reasons.append(f"{len(sys32_strings)} System32 path references")
            
            if new_score > ass.score:
                new_severity = Severity.HIGH if new_score > 70 else Severity.MEDIUM if new_score > 30 else Severity.LOW
                new_packer = PackerStatus.LIKELY_PACKED if new_score > 40 else PackerStatus.POSSIBLY_PACKED if new_score > 20 else ass.packer_status
                analysis_data["assessment"] = Assessment(
                    packer_status=new_packer,
                    reasons=new_reasons,
                    severity=new_severity,
                    score=round(min(new_score, 100), 1),
                    explanation=f"Score based on {', '.join(new_reasons) or 'no major indicators'}."
                )
        
        if "assessment" not in analysis_data:
            analysis_data["assessment"] = Assessment(
                packer_status=PackerStatus.NOT_PACKED,
                reasons=[],
                severity=Severity.LOW,
                score=0.0,
                explanation="Non-PE file"
            )
        
        result = self._create_result(analysis_data)
        return result
    
    def _get_file_info(self) -> FileInfo:
        mime = magic.from_file(self.file_path, mime=True)
        file_type = magic.from_file(self.file_path)
        is_pe = "PE" in file_type or self.file_path.suffix.lower() in [".exe", ".dll"]
        return FileInfo(
            filename=self.file_path.name,
            full_path=str(self.file_path),
            size_bytes=self.file_path.stat().st_size,
            extension=self.file_path.suffix,
            mime_type=mime,
            file_type=file_type,
            is_pe=is_pe
        )
    
    def _create_result(self, data: Dict[str, Any]) -> AnalysisResult:
        # Placeholder scoring
        score = 0.0
        severity = Severity.LOW
        assessment = data.get('assessment') or Assessment(
            packer_status=PackerStatus.NOT_PACKED,
            reasons=[],
            severity=Severity.LOW,
            score=0.0,
            explanation="Analysis complete"
        )
        data['assessment'] = assessment
        data.setdefault('executive_summary', 'Static analysis complete.')
        return AnalysisResult(**data)

