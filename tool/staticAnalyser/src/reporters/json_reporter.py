import json
from pathlib import Path
from models.analysis import AnalysisResult
from .base_reporter import BaseReporter

class JSONReporter(BaseReporter):
    def generate(self, output_path: Path):
        output_file = str(output_path) + ".json"
        with open(output_file, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2, default=str)

