import re
from pathlib import Path
from typing import List, Tuple
from models.analysis import IOC
import binascii

class StringAnalyzer:
    def __init__(self, file_path: Path):
        self.file_path = file_path
    
    def analyze(self) -> Tuple[List[str], List[IOC]]:
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        # Extract strings (ASCII printable + UTF16)
        ascii_strings = self._extract_ascii(data)
        unicode_strings = self._extract_unicode(data)
        all_strings = ascii_strings + unicode_strings
        
        suspicious_strings = self._flag_suspicious(all_strings)
        iocs = self._extract_iocs(all_strings)
        
        return suspicious_strings, iocs
    
    def _extract_ascii(self, data: bytes) -> List[str]:
        strings = []
        current = ''
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += chr(byte)
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ''
        if len(current) >= 4:
            strings.append(current)
        return strings
    
    def _extract_unicode(self, data: bytes) -> List[str]:
        strings = []
        current = ''
        i = 0
        while i < len(data) - 1:
            if data[i] == 0 and 32 <= data[i+1] <= 126:
                current += chr(data[i+1])
                i += 2
            else:
                if len(current) >= 2:
                    strings.append(current)
                current = ''
                i += 1
        if len(current) >= 2:
            strings.append(current)
        return strings
    
    def _flag_suspicious(self, strings: List[str]) -> List[str]:
        suspicious_patterns = [
            r'cmd\.exe|powershell\.exe|rundll32\.exe|wscript\.exe|cscript\.exe|mshta\.exe',
            r'temp|appdata|startup|allusersprofile|localappdata',
            r'\\windows\\system32|\\windows\\syswow64',
            r'http[s]?://',
            r'\.(bat|vbs|js|scr|pif|cmd|ps1|vbe|jse|wsf|wsh|lnk)$',
            r'CreateProcess|VirtualAlloc|WriteProcessMemory|LoadLibrary|GetProcAddress',
            r'WinExec|ShellExecute|CreateRemoteThread',
        ]
        suspicious = []
        for s in strings:
            if any(re.search(pat, s, re.IGNORECASE) for pat in suspicious_patterns):
                suspicious.append(s)
        return suspicious
    
    def _extract_iocs(self, strings: List[str]) -> List[IOC]:
        common_tlds = {'com', 'net', 'org', 'io', 'co', 'info', 'biz', 'edu', 'gov', 'mil', 'ru', 'cn', 'de', 'uk', 'fr', 'br', 'in', 'au', 'jp', 'xyz', 'top', 'club', 'site', 'online', 'tech'}
        common_tlds |= {f'{c}{n}' for c in 'co uk'.split() for n in range(10)}
        
        patterns = {
            'url': r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+',
            'ip': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'domain': r'\b[a-zA-Z][a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,10}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'registry': r'HK[LU]\W*\\[^\\s]+',
            'path': r'[A-Za-z]:\\(?:[^<>:"|?*\\]+\\)*[^<>:"|?*\\]*',
        }
        
        def is_dotnet_namespace(value):
            dotnet_prefixes = (
                'system', 'windows', 'microsoft', 'visual', 'assembly', 'newtonsoft',
                'apollo', 'collections', 'compilerservices', 'costura', 'interop',
                'runtime', 'ystem', 'lquot', 'sl', 'zl', 'app', 'form', 'resources',
                'properties', 'tools', 'editors', 'object', 'io', 'design', 'configuration',
                'visualstudio'
            )
            first = value.split('.')[0].lower() if '.' in value else value.lower()
            second = value.split('.')[1].lower() if '.' in value and len(value.split('.')) > 1 else ''
            
            if first in dotnet_prefixes:
                return True
            if first in ('resources', 'properties', 'tools', 'editors', 'object') and second and len(second) > 1:
                return True
            if value.lower().startswith(('sl', 'zl', 'l', 'zs')) and '.' in value[1:]:
                second_word = value.split('.')[1].lower() if len(value.split('.')) > 1 else ''
                if second_word in dotnet_prefixes or len(second_word) > 3:
                    return True
            if first.startswith('visual') and second in dotnet_prefixes:
                return True
            return False
        
        def is_valid_ip(value):
            parts = value.split('.')
            if len(parts) != 4:
                return False
            for p in parts:
                try:
                    n = int(p)
                    if n < 0 or n > 255:
                        return False
                except:
                    return False
            nums = [int(p) for p in parts]
            if nums[0] in (1, 4, 5, 13, 14) and nums[1] == 0 and nums[2] == 0:
                return False
            if nums == [0, 0, 0, 0]:
                return False
            return True
        
        iocs = []
        for s in strings:
            for ioc_type, pat in patterns.items():
                matches = re.finditer(pat, s, re.IGNORECASE)
                for match in matches:
                    value = match.group()
                    if is_dotnet_namespace(value):
                        continue
                    if ioc_type == 'ip' and not is_valid_ip(value):
                        continue
                    if ioc_type == 'domain':
                        tld = value.split('.')[-1].lower()
                        if len(tld) < 2 or len(tld) > 10:
                            continue
                        if tld in ('exe', 'dll', 'sys', 'ocx', 'cpl', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'resources', 'properties', 'app'):
                            continue
                        if not any(c.isalpha() for c in value.split('.')[0]):
                            continue
                        if tld not in common_tlds and len(tld) < 3:
                            continue
                        if value.lower() in ('myapplication.app', 'app.resources'):
                            continue
                    iocs.append(IOC(type=ioc_type, value=value))
        return list({ioc.value: ioc for ioc in iocs}.values())

