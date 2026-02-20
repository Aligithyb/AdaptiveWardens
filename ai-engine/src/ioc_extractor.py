import re
import spacy
from typing import List, Dict, Set
import logging
from urllib.parse import urlparse
import hashlib

logger = logging.getLogger(__name__)

class IOCExtractor:
    """
    Extracts Indicators of Compromise from commands and outputs.
    Uses regex patterns and NER for comprehensive detection.
    """
    
    def __init__(self):
        # Try to load spaCy model, fall back to regex-only if not available
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except:
            logger.warning("spaCy model not available, using regex-only extraction")
            self.nlp = None
        
        # Compile regex patterns
        self.patterns = {
            'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            'domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b', re.IGNORECASE),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
            'sha1': re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE),
            'sha256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
            'filepath': re.compile(r'(?:/[\w\.-]+)+|(?:[A-Z]:\\(?:[\w\.-]+\\?)+)', re.IGNORECASE),
        }
        
        # Known malicious tool signatures
        self.malicious_tools = {
            'wget', 'curl', 'nc', 'ncat', 'netcat', 'socat', 
            'python', 'perl', 'ruby', 'php', 'bash', 'sh',
            'powershell', 'msfvenom', 'meterpreter', 'mimikatz',
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zmap',
            'hydra', 'medusa', 'john', 'hashcat', 'aircrack'
        }
        
        # Suspicious commands/patterns
        self.suspicious_patterns = {
            'base64': re.compile(r'base64\s+-d', re.IGNORECASE),
            'reverse_shell': re.compile(r'bash\s+-i.*?/tcp/|nc.*?-e\s*/bin/', re.IGNORECASE),
            'download': re.compile(r'wget|curl.*?-O|-o', re.IGNORECASE),
            'chmod_exec': re.compile(r'chmod\s+\+x', re.IGNORECASE),
        }
    
    def extract_all(self, text: str, context: str = '') -> Dict[str, List[Dict]]:
        """
        Extract all IOCs from text.
        
        Args:
            text: Command or output text to analyze
            context: Additional context (e.g., 'command', 'output')
        
        Returns:
            Dictionary of IOC type -> list of IOC entries
        """
        
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'hashes': [],
            'files': [],
            'tools': [],
            'suspicious': []
        }
        
        # Extract with regex
        iocs['ips'] = self._extract_ips(text, context)
        iocs['domains'] = self._extract_domains(text, context)
        iocs['urls'] = self._extract_urls(text, context)
        iocs['emails'] = self._extract_emails(text, context)
        iocs['hashes'] = self._extract_hashes(text, context)
        iocs['files'] = self._extract_files(text, context)
        iocs['tools'] = self._extract_tools(text, context)
        iocs['suspicious'] = self._extract_suspicious(text, context)
        
        # Use NER if available
        if self.nlp:
            ner_iocs = self._extract_with_ner(text, context)
            # Merge with regex results
            for ioc_type, items in ner_iocs.items():
                iocs[ioc_type].extend(items)
        
        # Deduplicate
        for ioc_type in iocs:
            iocs[ioc_type] = self._deduplicate_iocs(iocs[ioc_type])
        
        return iocs
    
    def _extract_ips(self, text: str, context: str) -> List[Dict]:
        """Extract IP addresses."""
        ips = []
        
        # IPv4
        for match in self.patterns['ipv4'].finditer(text):
            ip = match.group(0)
            # Filter out common false positives
            if not ip.startswith('127.') and not ip.startswith('0.'):
                ips.append({
                    'type': 'ip',
                    'value': ip,
                    'confidence': 0.9,
                    'context': context
                })
        
        # IPv6
        for match in self.patterns['ipv6'].finditer(text):
            ips.append({
                'type': 'ip',
                'value': match.group(0),
                'confidence': 0.9,
                'context': context
            })
        
        return ips
    
    def _extract_domains(self, text: str, context: str) -> List[Dict]:
        """Extract domain names."""
        domains = []
        
        for match in self.patterns['domain'].finditer(text):
            domain = match.group(0)
            # Filter common false positives
            if (not domain.endswith('.local') and 
                not domain.startswith('localhost') and
                '.' in domain):
                
                domains.append({
                    'type': 'domain',
                    'value': domain,
                    'confidence': 0.7,
                    'context': context
                })
        
        return domains
    
    def _extract_urls(self, text: str, context: str) -> List[Dict]:
        """Extract URLs."""
        urls = []
        
        for match in self.patterns['url'].finditer(text):
            url = match.group(0)
            parsed = urlparse(url)
            
            urls.append({
                'type': 'url',
                'value': url,
                'confidence': 0.95,
                'context': context,
                'metadata': {
                    'domain': parsed.netloc,
                    'path': parsed.path,
                    'scheme': parsed.scheme
                }
            })
        
        return urls
    
    def _extract_emails(self, text: str, context: str) -> List[Dict]:
        """Extract email addresses."""
        emails = []
        
        for match in self.patterns['email'].finditer(text):
            emails.append({
                'type': 'email',
                'value': match.group(0),
                'confidence': 0.8,
                'context': context
            })
        
        return emails
    
    def _extract_hashes(self, text: str, context: str) -> List[Dict]:
        """Extract file hashes (MD5, SHA1, SHA256)."""
        hashes = []
        
        for hash_type in ['md5', 'sha1', 'sha256']:
            for match in self.patterns[hash_type].finditer(text):
                hashes.append({
                    'type': 'hash',
                    'value': match.group(0),
                    'confidence': 0.85,
                    'context': context,
                    'metadata': {'hash_type': hash_type}
                })
        
        return hashes
    
    def _extract_files(self, text: str, context: str) -> List[Dict]:
        """Extract file paths."""
        files = []
        
        for match in self.patterns['filepath'].finditer(text):
            path = match.group(0)
            # Filter noise
            if len(path) > 3 and '/' in path:
                files.append({
                    'type': 'filename',
                    'value': path,
                    'confidence': 0.6,
                    'context': context
                })
        
        return files
    
    def _extract_tools(self, text: str, context: str) -> List[Dict]:
        """Extract known hacking tools."""
        tools = []
        
        words = text.lower().split()
        for word in words:
            # Clean word
            word = word.strip('.,;()[]{}')
            if word in self.malicious_tools:
                tools.append({
                    'type': 'command',
                    'value': word,
                    'confidence': 0.9,
                    'context': context,
                    'metadata': {'category': 'security_tool'}
                })
        
        return tools
    
    def _extract_suspicious(self, text: str, context: str) -> List[Dict]:
        """Extract suspicious patterns."""
        suspicious = []
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            if pattern.search(text):
                suspicious.append({
                    'type': 'command',
                    'value': text[:100],  # Truncate for storage
                    'confidence': 0.75,
                    'context': context,
                    'metadata': {'pattern': pattern_name}
                })
        
        return suspicious
    
    def _extract_with_ner(self, text: str, context: str) -> Dict:
        """Use spaCy NER to extract additional entities."""
        iocs = {
            'domains': [],
            'ips': []
        }
        
        try:
            doc = self.nlp(text)
            
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'GPE', 'PRODUCT']:
                    # Potential domain or organization
                    if '.' in ent.text:
                        iocs['domains'].append({
                            'type': 'domain',
                            'value': ent.text,
                            'confidence': 0.5,
                            'context': context,
                            'metadata': {'source': 'ner', 'label': ent.label_}
                        })
        except Exception as e:
            logger.error(f"NER extraction error: {e}")
        
        return iocs
    
    def _deduplicate_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs, keeping highest confidence."""
        seen = {}
        
        for ioc in iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen or ioc['confidence'] > seen[key]['confidence']:
                seen[key] = ioc
        
        return list(seen.values())
