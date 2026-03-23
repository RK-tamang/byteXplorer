from abc import ABC, abstractmethod
from pathlib import Path
from models.analysis import AnalysisResult
from utils.logger import setup_logger

class BaseReporter(ABC):
    def __init__(self, result: AnalysisResult, logger=None):
        self.result = result
        self.logger = logger or setup_logger()
    
    @abstractmethod
    def generate(self, output_path: Path):
        """Generate report at given path stem (suffix added by subclasses)"""
        pass

