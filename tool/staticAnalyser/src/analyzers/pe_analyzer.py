import pefile
import re
from pathlib import Path
from typing import Dict, List, Any
from models.analysis import (
    PEHeader, Section, Import, Severity, PackerStatus, Assessment,
    FileInfo
)
from utils.entropy import calculate_entropy
from .hash_analyzer import HashAnalyzer
SUSPICIOUS_APIS = {
    "kernel32.dll": [
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile", "DeleteFileA", "MoveFileA", "GetTempPathA",
        "SetFileTime", "SetFileAttributes", "GetAdaptersInfo", "InternetOpenA",
        "InternetOpenUrlA", "InternetReadFile", "HttpSendRequestA",
    ],
    "advapi32.dll": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "StartServiceA", "StartServiceW", "LogonUserA", "LogonUserW",
        "CreateProcessWithLogonW", "CryptAcquireContextA", "CryptEncrypt",
    ],
    "ntdll.dll": [
        "NtQueryInformationProcess", "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "NtCreateThread", "NtOpenProcess", "NtQuerySystemInformation",
        "NtDelayExecution", "NtWaitForSingleObject", "RtlCreateUserThread",
    ],
    "user32.dll": [
        "FindWindowA", "FindWindowW", "SetWindowsHookExA", "UnhookWindowsHookEx",
        "GetAsyncKeyState", "GetKeyboardState", "SetForegroundWindow",
    ],
    "wininet.dll": [
        "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "HttpSendRequestA",
        "HttpSendRequestW", "InternetCrackUrlA", "InternetCrackUrlW",
    ],
    "ws2_32.dll": [
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "WSAStartup", "WSASocketA", "WSASocketW", "gethostbyname", "getaddrinfo",
    ],
    "urlmon.dll": [
        "URLDownloadToFileA", "URLDownloadToFileW", "URLOpenBlockingStreamA",
    ],
    "shlwapi.dll": [
        "URLDownloadToFileA", "PathCanonicalizeA", "PathCombineA",
    ],
    "ole32.dll": [
        "CoCreateInstance", "CoInitializeEx", "OleInitialize",
    ],
    "oleaut32.dll": [
        "SysFreeString", "VariantInit", "VariantClear",
    ],
}

class PEAnalyzer:
    def __init__(self, file_path: Path):
        self.pe = pefile.PE(file_path)
        self.file_path = file_path
        
    def analyze(self) -> Dict[str, Any]:
        data = {}
        
        # PE Header
        data["pe_header"] = self._parse_headers()
        
        # Sections
        data["sections"] = self._analyze_sections()
        
        # Imports
        data["imports"] = self._analyze_imports()
        
        # Exports
        data["exports"] = self._analyze_exports()
        
        # imphash
        hash_analyzer = HashAnalyzer(self.file_path)
        hashes = hash_analyzer.analyze()
        hashes.imphash = self.pe.get_imphash()
        
        data["hashes"] = hashes
        
        # Assessment
        data["assessment"] = self._assess_risk(data["sections"], data["imports"])
        
        return data
    
    def _parse_headers(self) -> PEHeader:
        opt = self.pe.OPTIONAL_HEADER
        dll_char = []
        if hasattr(opt, 'DllCharacteristics') and opt.DllCharacteristics:
            if isinstance(opt.DllCharacteristics, int):
                dll_char = [f"DllChar_{opt.DllCharacteristics:#x}"]
            else:
                dll_char = [str(c) for c in opt.DllCharacteristics]
        
        MACHINE_TYPES = {
            0x014c: "i386",
            0x8664: "x64",
            0x0200: "IA64",
            0x01c0: "ARM",
            0xaa64: "ARM64",
            0x01c4: "ARMNT",
        }
        machine = self.pe.FILE_HEADER.Machine
        machine_type = MACHINE_TYPES.get(machine, f"0x{machine:04X}")
        
        return PEHeader(
            machine_type=machine_type,
            timestamp=str(self.pe.FILE_HEADER.TimeDateStamp),
            entry_point=opt.AddressOfEntryPoint,
            image_base=opt.ImageBase,
            subsystem=str(opt.Subsystem),
            dll_characteristics=dll_char,
            num_sections=self.pe.FILE_HEADER.NumberOfSections
        )
    
    def _analyze_sections(self) -> List[Section]:
        sections = []
        SECTION_FLAGS = {
            0x00000020: "CODE",
            0x00000040: "INITIALIZED_DATA",
            0x00000080: "UNINITIALIZED_DATA",
            0x20000000: "EXECUTE",
            0x40000000: "READ",
            0x80000000: "WRITE",
        }
        
        for section in self.pe.sections:
            try:
                raw_data = section.get_data()
            except:
                raw_data = b''
            entropy = calculate_entropy(raw_data)
            
            char_flags = []
            raw_chars = section.Characteristics
            
            if isinstance(raw_chars, int):
                for flag_val, flag_name in SECTION_FLAGS.items():
                    if raw_chars & flag_val:
                        char_flags.append(flag_name)
            else:
                char_flags = [str(raw_chars)] if raw_chars else ["Unknown"]
            
            has_exec = any('EXECUTE' in f for f in char_flags)
            has_write = any('WRITE' in f for f in char_flags)
            
            suspicious = False
            reason = None
            if entropy > 7.5:
                suspicious = True
                reason = "High entropy"
            if has_exec and has_write:
                suspicious = True
                if reason:
                    reason += " | RWX section"
                else:
                    reason = "RWX section"
            
            sections.append(Section(
                name=section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                characteristics=char_flags if char_flags else ["Unknown"],
                entropy=round(entropy, 2),
                suspicious=suspicious,
                reason=reason
            ))
        return sections
    
    def _analyze_imports(self) -> List[Import]:
        imports = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            apis = [imp.name.decode() for imp in entry.imports if imp.name]
            suspicious = any(api.upper() in SUSPICIOUS_APIS.get(dll.lower(), []) for api in apis)
            imports.append(Import(dll=dll, apis=apis, suspicious=suspicious))
        return imports
    
    def _analyze_exports(self) -> List[str]:
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return [exp.name.decode() for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]
        return []
    
    def _assess_risk(self, sections: List[Section], imports: List[Import]) -> Assessment:
        score = 0.0
        reasons = []
        
        high_entropy_count = sum(1 for s in sections if s.entropy > 7.0)
        if high_entropy_count > 0:
            score += high_entropy_count * 10
            reasons.append(f"{high_entropy_count} high-entropy section{'s' if high_entropy_count > 1 else ''}")
        
        rwx_count = sum(1 for s in sections if s.suspicious and "RWX" in (s.reason or ""))
        if rwx_count > 0:
            score += 30
            reasons.append(f"{rwx_count} RWX section{'s' if rwx_count > 1 else ''}")
        
        suspicious_imports = sum(1 for imp in imports if imp.suspicious)
        if suspicious_imports > 0:
            score += min(suspicious_imports * 3, 25)
            reasons.append(f"{suspicious_imports} suspicious API{'s' if suspicious_imports > 1 else ''}")
        
        suspicious_strings_count = len(self._find_suspicious_strings())
        if suspicious_strings_count > 5:
            score += 10
            reasons.append(f"{suspicious_strings_count} suspicious strings")
        
        packer_status = PackerStatus.NOT_PACKED
        if high_entropy_count > 2 or score > 40:
            packer_status = PackerStatus.LIKELY_PACKED
        elif high_entropy_count > 1 or score > 20:
            packer_status = PackerStatus.POSSIBLY_PACKED
        
        severity = Severity.HIGH if score > 70 else Severity.MEDIUM if score > 30 else Severity.LOW
        
        return Assessment(
            packer_status=packer_status,
            reasons=reasons,
            severity=severity,
            score=round(min(score, 100), 1),
            explanation=f"Score based on {', '.join(reasons) or 'no major indicators'}."
        )
    
    def _find_suspicious_strings(self) -> List[str]:
        try:
            all_strings = []
            for section in self.pe.sections:
                data = section.get_data()
                for i in range(len(data)):
                    if 32 <= data[i] <= 126:
                        j = i
                        s = ''
                        while j < len(data) and 32 <= data[j] <= 126:
                            s += chr(data[j])
                            j += 1
                        if len(s) >= 4:
                            all_strings.append(s)
                        i = j
            
            patterns = [
                r'cmd\.exe|powershell\.exe|rundll32\.exe',
                r'\\windows\\system32',
                r'VirtualAlloc|CreateRemoteThread',
            ]
            return [s for s in all_strings if any(re.search(p, s, re.I) for p in patterns)]
        except:
            return []

