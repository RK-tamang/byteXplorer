from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional, TypedDict
from enum import Enum

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class PackerStatus(str, Enum):
    NOT_PACKED = "Not Packed"
    POSSIBLY_PACKED = "Possibly Packed"
    LIKELY_PACKED = "Likely Packed"

@dataclass
class FileInfo:
    filename: str
    full_path: str
    size_bytes: int
    extension: str
    mime_type: str
    file_type: str
    is_pe: bool
    architecture: Optional[str] = None

@dataclass
class Hashes:
    md5: str
    sha1: str
    sha256: str
    imphash: Optional[str] = None

@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: List[str]
    entropy: float
    suspicious: bool
    reason: Optional[str] = None

@dataclass
class PEHeader:
    machine_type: str
    timestamp: str
    entry_point: int
    image_base: int
    subsystem: str
    dll_characteristics: List[str]
    num_sections: int

@dataclass
class Import:
    dll: str
    apis: List[str]
    suspicious: bool

@dataclass
class IOC:
    type: str  # url, ip, domain, email, etc.
    value: str

@dataclass
class Assessment:
    packer_status: PackerStatus
    reasons: List[str]
    severity: Severity
    score: float  # 0-100
    explanation: str

@dataclass
class AnalysisResult:
    file_info: FileInfo
    hashes: Hashes
    pe_header: Optional[PEHeader]
    sections: List[Section]
    imports: List[Import]
    exports: List[str]
    suspicious_strings: List[str]
    iocs: List[IOC]
    assessment: Assessment
    executive_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

