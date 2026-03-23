import hashlib
from pathlib import Path
from models.analysis import Hashes

class HashAnalyzer:
    def __init__(self, file_path: Path):
        self.file_path = file_path
    
    def analyze(self) -> Hashes:
        with open(self.file_path, "rb") as f:
            data = f.read()
        
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        
        # imphash requires pefile - compute later in PE analyzer
        
        return Hashes(md5=md5, sha1=sha1, sha256=sha256)

