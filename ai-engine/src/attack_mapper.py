import re
from typing import List, Dict, Set, Tuple
import logging

logger = logging.getLogger(__name__)

class MITREAttackMapper:
    """
    Maps observed attacker behavior to MITRE ATT&CK techniques.
    Uses command pattern matching and behavioral analysis.
    """
    
    def __init__(self):
        # Define mapping rules: pattern -> (technique_id, technique_name, tactic, confidence)
        self.command_patterns = self._init_command_patterns()
        self.behavioral_patterns = self._init_behavioral_patterns()
    
    def _init_command_patterns(self) -> List[Tuple]:
        """
        Initialize command-based detection patterns.
        Returns list of (regex_pattern, technique_id, technique_name, tactic, base_confidence)
        """
        
        patterns = [
            # Reconnaissance
            (r'\b(whoami|id|groups)\b', 'T1033', 'System Owner/User Discovery', 'Discovery', 0.95),
            (r'\b(hostname|uname\s+-a)\b', 'T1082', 'System Information Discovery', 'Discovery', 0.95),
            (r'\b(ifconfig|ip\s+addr|ip\s+a)\b', 'T1016', 'System Network Configuration Discovery', 'Discovery', 0.90),
            (r'\b(ps\s+aux|ps\s+-ef|top|htop)\b', 'T1057', 'Process Discovery', 'Discovery', 0.90),
            (r'\b(ls|dir|find)\b', 'T1083', 'File and Directory Discovery', 'Discovery', 0.70),
            (r'\b(netstat|ss)\b', 'T1049', 'System Network Connections Discovery', 'Discovery', 0.90),
            (r'\b(cat\s+/etc/passwd|cat\s+/etc/shadow)\b', 'T1087.001', 'Account Discovery: Local Account', 'Discovery', 0.95),
            (r'\b(w|who|last|lastlog)\b', 'T1033', 'System Owner/User Discovery', 'Discovery', 0.85),
            
            # Execution
            (r'\b(bash|sh|zsh|ksh)\s+-[ic]', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell', 'Execution', 0.90),
            (r'\b(python|python3|perl|ruby|php)\b', 'T1059', 'Command and Scripting Interpreter', 'Execution', 0.80),
            (r'\b(wget|curl).*?http', 'T1105', 'Ingress Tool Transfer', 'Command and Control', 0.90),
            (r'\b(chmod\s+\+x|chmod\s+777)', 'T1222', 'File and Directory Permissions Modification', 'Defense Evasion', 0.85),
            
            # Persistence
            (r'\b(crontab|systemctl|service)\b', 'T1053', 'Scheduled Task/Job', 'Persistence', 0.80),
            (r'\.bashrc|\.bash_profile|\.profile', 'T1546.004', 'Event Triggered Execution: Unix Shell Configuration Modification', 'Persistence', 0.85),
            (r'/etc/rc\.|/etc/init\.d/', 'T1037', 'Boot or Logon Initialization Scripts', 'Persistence', 0.85),
            (r'ssh.*?authorized_keys', 'T1098.004', 'Account Manipulation: SSH Authorized Keys', 'Persistence', 0.90),
            
            # Privilege Escalation
            (r'\b(sudo|su\s+)', 'T1548.003', 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching', 'Privilege Escalation', 0.85),
            (r'\b(find.*?-perm|find.*?-user\s+root)', 'T1548', 'Abuse Elevation Control Mechanism', 'Privilege Escalation', 0.75),
            
            # Defense Evasion
            (r'\b(rm|shred|wipe).*?\.log', 'T1070.002', 'Indicator Removal on Host: Clear Linux or Mac System Logs', 'Defense Evasion', 0.90),
            (r'\b(history\s+-c|unset\s+HISTFILE)', 'T1070.003', 'Indicator Removal on Host: Clear Command History', 'Defense Evasion', 0.95),
            (r'\b(base64|xxd|openssl\s+enc)', 'T1027', 'Obfuscated Files or Information', 'Defense Evasion', 0.75),
            (r'\b(kill|killall|pkill)\b', 'T1489', 'Service Stop', 'Impact', 0.70),
            
            # Credential Access
            (r'\b(cat|grep|find).*?password', 'T1552.001', 'Unsecured Credentials: Credentials In Files', 'Credential Access', 0.80),
            (r'\b(mimikatz|lazagne|pwdump)', 'T1003', 'OS Credential Dumping', 'Credential Access', 0.95),
            
            # Lateral Movement
            (r'\b(ssh|scp|rsync)\s+', 'T1021.004', 'Remote Services: SSH', 'Lateral Movement', 0.80),
            (r'\b(nc|ncat|netcat).*?-e', 'T1059', 'Command and Scripting Interpreter', 'Execution', 0.90),
            
            # Collection
            (r'\b(tar|zip|gzip|7z)\s+', 'T1560', 'Archive Collected Data', 'Collection', 0.75),
            (r'\b(find).*?\.(pdf|doc|xls|txt)', 'T1005', 'Data from Local System', 'Collection', 0.70),
            
            # Exfiltration  
            (r'\b(scp|rsync|ftp|sftp)\b', 'T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 0.75),
            (r'\b(curl|wget).*?--(upload|data|form)', 'T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', 0.85),
            
            # Command and Control
            (r'\b(nc|ncat|netcat).*?(\d+\.\d+\.\d+\.\d+)', 'T1071', 'Application Layer Protocol', 'Command and Control', 0.85),
            (r'bash.*?/dev/tcp/', 'T1059.004', 'Unix Shell for C2', 'Command and Control', 0.95),
            
            # Impact
            (r'\b(rm\s+-rf\s+/|dd\s+if=/dev/zero)', 'T1485', 'Data Destruction', 'Impact', 0.90),
            (r'\b(iptables|ufw).*?(DROP|REJECT)', 'T1562.004', 'Impair Defenses: Disable or Modify System Firewall', 'Defense Evasion', 0.85),
        ]
        
        return [(re.compile(pattern, re.IGNORECASE), tid, name, tactic, conf) 
                for pattern, tid, name, tactic, conf in patterns]
    
    def _init_behavioral_patterns(self) -> Dict:
        """
        Initialize behavioral detection patterns (sequence-based).
        These detect attack patterns across multiple commands.
        """
        
        return {
            'enumeration_sequence': {
                'commands': ['whoami', 'uname', 'ifconfig', 'ps'],
                'technique_id': 'T1592',
                'technique_name': 'Gather Victim Host Information',
                'tactic': 'Reconnaissance',
                'threshold': 3,  # Need at least 3 of these commands
                'confidence': 0.85
            },
            'privilege_escalation_attempt': {
                'commands': ['sudo', 'su', 'find.*suid'],
                'technique_id': 'T1548',
                'technique_name': 'Abuse Elevation Control Mechanism',
                'tactic': 'Privilege Escalation',
                'threshold': 2,
                'confidence': 0.80
            },
            'persistence_setup': {
                'commands': ['crontab', '.bashrc', 'systemctl'],
                'technique_id': 'T1053',
                'technique_name': 'Scheduled Task/Job',
                'tactic': 'Persistence',
                'threshold': 1,
                'confidence': 0.85
            }
        }
    
    def analyze_command(self, command: str) -> List[Dict]:
        """
        Analyze a single command and return matched ATT&CK techniques.
        
        Args:
            command: The command to analyze
        
        Returns:
            List of detected techniques with confidence scores
        """
        
        techniques = []
        
        for pattern, tech_id, tech_name, tactic, base_conf in self.command_patterns:
            if pattern.search(command):
                techniques.append({
                    'technique_id': tech_id,
                    'technique_name': tech_name,
                    'tactic': tactic,
                    'confidence': base_conf,
                    'evidence': command,
                    'source': 'command_pattern'
                })
        
        return techniques
    
    def analyze_session(self, commands: List[str]) -> List[Dict]:
        """
        Analyze a sequence of commands for behavioral patterns.
        
        Args:
            commands: List of commands from a session
        
        Returns:
            List of detected techniques including behavioral patterns
        """
        
        all_techniques = []
        
        # Analyze each command individually
        for cmd in commands:
            all_techniques.extend(self.analyze_command(cmd))
        
        # Check for behavioral patterns
        cmd_text = ' '.join(commands).lower()
        
        for pattern_name, pattern_def in self.behavioral_patterns.items():
            match_count = 0
            
            for cmd_pattern in pattern_def['commands']:
                if re.search(cmd_pattern, cmd_text, re.IGNORECASE):
                    match_count += 1
            
            if match_count >= pattern_def['threshold']:
                all_techniques.append({
                    'technique_id': pattern_def['technique_id'],
                    'technique_name': pattern_def['technique_name'],
                    'tactic': pattern_def['tactic'],
                    'confidence': pattern_def['confidence'],
                    'evidence': f"Behavioral pattern: {pattern_name}",
                    'source': 'behavioral_analysis'
                })
        
        # Deduplicate techniques
        seen = {}
        for tech in all_techniques:
            key = tech['technique_id']
            if key not in seen or tech['confidence'] > seen[key]['confidence']:
                seen[key] = tech
        
        return list(seen.values())
    
    def get_tactic_coverage(self, techniques: List[Dict]) -> Dict[str, List[str]]:
        """
        Group techniques by tactic for heatmap visualization.
        
        Returns:
            Dictionary mapping tactic -> list of technique IDs
        """
        
        coverage = {}
        
        for tech in techniques:
            tactic = tech['tactic']
            if tactic not in coverage:
                coverage[tactic] = []
            
            if tech['technique_id'] not in coverage[tactic]:
                coverage[tactic].append(tech['technique_id'])
        
        return coverage
