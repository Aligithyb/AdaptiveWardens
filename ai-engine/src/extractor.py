import spacy
import re

# Load English NLP model for generic NER
try:
    nlp = spacy.load("en_core_web_sm")
except Exception as e:
    import logging
    logging.warning(f"Failed to load spacy model: {e}. IOC extraction might be degraded.")
    nlp = None

def extract_iocs(text: str) -> list:
    """
    Extract Indicators of Compromise from a text string.
    Returns a list of dicts: {"ioc_type": ..., "value": ..., "confidence": ...}
    """
    iocs = []
    
    # 1. Regex-based extraction (IPs, URLs, Hashes)
    
    # IPv4
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for match in re.finditer(ip_pattern, text):
        val = match.group()
        # ignore generic local IPs
        if not (val.startswith('127.') or val.startswith('10.') or val.startswith('192.168.')):
            iocs.append({"ioc_type": "ip", "value": val, "confidence": 0.95})
            
    # URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'
    for match in re.finditer(url_pattern, text):
        iocs.append({"ioc_type": "url", "value": match.group(), "confidence": 0.95})
        
    # Domains (basic)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b'
    for match in re.finditer(domain_pattern, text):
        val = match.group()
        # filter out simple extensions or common false positives if needed
        # only keep if it is not matched inside a url to avoid duplicates
        found_in_url = False
        for i in iocs:
            if i['ioc_type'] == 'url' and val in str(i['value']):
                found_in_url = True
                break
        if not found_in_url and val.lower().split('.')[-1] not in ["sh", "txt", "php", "py", "bash", "tar.gz", "system", "js", "conf", "log"]:
            iocs.append({"ioc_type": "domain", "value": val, "confidence": 0.85})
    
    # MD5 Hashes
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    for match in re.finditer(md5_pattern, text):
        iocs.append({"ioc_type": "hash:md5", "value": match.group(), "confidence": 0.99})

    # SHA256 Hashes
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    for match in re.finditer(sha256_pattern, text):
        iocs.append({"ioc_type": "hash:sha256", "value": match.group(), "confidence": 0.99})

    # File paths (simplistic realistic Linux paths from commands)
    path_pattern = r'(?:\s|^)(/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)\b'
    for match in re.finditer(path_pattern, text):
        iocs.append({"ioc_type": "filepath", "value": match.group(1), "confidence": 0.7})

    # 2. NER-based extraction (if spaCy is loaded)
    if nlp:
        doc = nlp(text)
        for ent in doc.ents:
            if ent.label_ in ["ORG", "PERSON", "GPE"]:
                val = ent.text.strip()
                # filter out very short junk
                if len(val) > 2:
                    iocs.append({"ioc_type": f"entity:{ent.label_.lower()}", "value": val, "confidence": 0.6})
                    
    # Remove obvious duplicates
    unique_iocs = []
    seen = set()
    for ioc in iocs:
        key = (ioc["ioc_type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
            
    return unique_iocs
