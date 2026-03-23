from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from pathlib import Path
from models.analysis import AnalysisResult
from .base_reporter import BaseReporter

class PDFReporter(BaseReporter):
    def generate(self, output_path: Path):
        doc = SimpleDocTemplate(
            str(output_path) + ".pdf",
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("Static Malware Analysis Report", title_style))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Paragraph(self.result.executive_summary, styles['Normal']))
        story.append(Spacer(1, 12))
        
        # File Info Table
        data = [
            ['Attribute', 'Value'],
            ['Filename', self.result.file_info.filename],
            ['Full Path', self.result.file_info.full_path],
            ['Size', f"{self.result.file_info.size_bytes:,} bytes"],
            ['File Type', self.result.file_info.file_type],
        ]
        if self.result.pe_header:
            data += [
                ['Machine Type', self.result.pe_header.machine_type],
                ['Image Base', f"0x{self.result.pe_header.image_base:08X}"],
                ['Subsystem', self.result.pe_header.subsystem],
                ['Entry Point', f"0x{self.result.pe_header.entry_point:08X}"],
            ]
        data += [
            ['Severity', self.result.assessment.severity.value if hasattr(self.result.assessment.severity, 'value') else str(self.result.assessment.severity)],
            ['Score', f"{self.result.assessment.score:.1f}/100"],
        ]
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 12))
        
        # Hashes Table
        story.append(Paragraph("Hashes", styles['Heading2']))
        hashes_data = [
            ['Hash', 'Value'],
            ['MD5', self.result.hashes.md5],
            ['SHA1', self.result.hashes.sha1],
            ['SHA256', self.result.hashes.sha256],
        ]
        if self.result.hashes.imphash:
            hashes_data += [['imphash', self.result.hashes.imphash]]
        hashes_table = Table(hashes_data)
        hashes_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(hashes_table)
        story.append(Spacer(1, 12))
        
        # Sections Table
        story.append(Paragraph("Sections Analysis", styles['Heading2']))
        sections_data = [['Name', 'VA', 'Virtual Size', 'Raw Size', 'Entropy', 'Suspicious']]
        display_sections = self.result.sections[:20]
        for sec in display_sections:
            susp = 'Yes' if sec.suspicious else 'No'
            sections_data += [[sec.name, f"0x{sec.virtual_address:X}", f"{sec.virtual_size:,}", f"{sec.raw_size:,}", f"{sec.entropy:.2f}", susp]]
        if len(self.result.sections) > 20:
            sections_data += [['...', '...', f'and {len(self.result.sections) - 20} more', '', '', '']]
        sections_table = Table(sections_data)
        sections_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        story.append(sections_table)
        story.append(Spacer(1, 12))
        
        # Imports
        if self.result.imports:
            story.append(Paragraph("Imports", styles['Heading2']))
            for imp in self.result.imports:
                apis = imp.apis[:10]
                extra = f" and {len(imp.apis) - 10} more" if len(imp.apis) > 10 else ""
                imp_text = f"<b>{imp.dll.upper()}</b><br/>{', '.join(apis)}{extra}"
                if imp.suspicious:
                    imp_text += " <b style='color:red'>⚠️ SUSPICIOUS</b>"
                story.append(Paragraph(imp_text, styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Suspicious Strings
        if self.result.suspicious_strings:
            story.append(Paragraph("Suspicious Strings", styles['Heading2']))
            display_strings = self.result.suspicious_strings[:25]
            for s in display_strings:
                story.append(Paragraph(f"• {s}", styles['Normal']))
            if len(self.result.suspicious_strings) > 25:
                story.append(Paragraph(f"...and {len(self.result.suspicious_strings) - 25} more", styles['Normal']))
            story.append(Spacer(1, 12))
        
        # IOCs Table
        if self.result.iocs:
            story.append(Paragraph("Extracted IOCs", styles['Heading2']))
            iocs_data = [['Type', 'Value']]
            display_iocs = self.result.iocs[:30]
            for ioc in display_iocs:
                iocs_data += [[ioc.type.upper(), ioc.value]]
            if len(self.result.iocs) > 30:
                iocs_data += [['...', f'and {len(self.result.iocs) - 30} more IOCs']]
            iocs_table = Table(iocs_data)
            iocs_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
            ]))
            story.append(iocs_table)
            story.append(Spacer(1, 12))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", styles['Heading1']))
        ass_data = [
            ['Metric', 'Value'],
            ['Packer Status', self.result.assessment.packer_status.value if hasattr(self.result.assessment.packer_status, 'value') else str(self.result.assessment.packer_status)],
            ['Severity', self.result.assessment.severity.value if hasattr(self.result.assessment.severity, 'value') else str(self.result.assessment.severity)],
            ['Score', f"{self.result.assessment.score:.1f}/100"],
            ['Reasons', '; '.join(self.result.assessment.reasons) or 'None'],
        ]
        ass_table = Table(ass_data)
        ass_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(ass_table)
        
        doc.build(story)
