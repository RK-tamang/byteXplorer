#!/usr/bin/env python3
import argparse
import logging
import sys
import os
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR.parent))

from analyzers.file_analyzer import FileAnalyzer
from reporters.report_generator import ReportGenerator
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description="Static Malware Analyzer")
    parser.add_argument("file_path", help="Path to the file to analyze")
    parser.add_argument("--output", "-o", default="./reports", help="Output directory")
    parser.add_argument("--format", "-f", default="all", choices=["all", "json", "md", "docx", "pdf"], help="Report format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    logger = setup_logger(verbose=args.verbose)
    
    file_path = Path(args.file_path)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        sys.exit(1)
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    try:
        logger.info(f"Analyzing {file_path}")
        analyzer = FileAnalyzer(file_path)
        analysis_data = analyzer.analyze()
        
        generator = ReportGenerator(analysis_data, output_dir, logger)
        formats = args.format.split(",") if "," in args.format else [args.format]
        if "all" in formats:
            formats = ["json", "md", "docx", "pdf"]
        
        generator.generate_reports(formats)
        logger.info("Analysis complete. Reports saved to %s", output_dir)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
