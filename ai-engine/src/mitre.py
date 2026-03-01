import re

# Dictionary mapping regex patterns of commands to MITRE ATT&CK techniques
MITRE_MAPPING = [
    # --- RECONNAISSANCE ---
    {"pattern": r"nmap -sV", "technique_id": "T1595.002", "technique_name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance", "confidence": 0.95},
    {"pattern": r"masscan -p", "technique_id": "T1595.001", "technique_name": "Active Scanning: IP Addresses", "tactic": "Reconnaissance", "confidence": 0.95},
    {"pattern": r"zmap -p", "technique_id": "T1595.001", "technique_name": "Active Scanning: IP Addresses", "tactic": "Reconnaissance", "confidence": 0.95},
    {"pattern": r"\bnikto\b", "technique_id": "T1595.002", "technique_name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance", "confidence": 0.98},
    {"pattern": r"\bopenvas\b", "technique_id": "T1595.002", "technique_name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance", "confidence": 0.98},
    {"pattern": r"dmidecode -t system", "technique_id": "T1592", "technique_name": "Gather Victim Host Information", "tactic": "Reconnaissance", "confidence": 0.90},
    {"pattern": r"\blshw\b", "technique_id": "T1592", "technique_name": "Gather Victim Host Information", "tactic": "Reconnaissance", "confidence": 0.90},
    {"pattern": r"dpkg -l", "technique_id": "T1592.002", "technique_name": "Gather Victim Host Information: Software", "tactic": "Reconnaissance", "confidence": 0.85},
    {"pattern": r"rpm -qa", "technique_id": "T1592.002", "technique_name": "Gather Victim Host Information: Software", "tactic": "Reconnaissance", "confidence": 0.85},
    {"pattern": r"netstat -tuln", "technique_id": "T1590", "technique_name": "Gather Victim Network Information", "tactic": "Reconnaissance", "confidence": 0.90},
    {"pattern": r"ip route show", "technique_id": "T1590", "technique_name": "Gather Victim Network Information", "tactic": "Reconnaissance", "confidence": 0.90},
    {"pattern": r"ifconfig", "technique_id": "T1590.005", "technique_name": "Gather Victim Network Information: IP Addresses", "tactic": "Reconnaissance", "confidence": 0.85},
    {"pattern": r"ip addr show", "technique_id": "T1590.005", "technique_name": "Gather Victim Network Information: IP Addresses", "tactic": "Reconnaissance", "confidence": 0.85},

    # --- RESOURCE DEVELOPMENT ---
    {"pattern": r"gcc -o", "technique_id": "T1587.001", "technique_name": "Develop Capabilities: Malware", "tactic": "Resource Development", "confidence": 0.85},
    {"pattern": r"make\b", "technique_id": "T1587.001", "technique_name": "Develop Capabilities: Malware", "tactic": "Resource Development", "confidence": 0.75},
    {"pattern": r"go build", "technique_id": "T1587.001", "technique_name": "Develop Capabilities: Malware", "tactic": "Resource Development", "confidence": 0.85},
    {"pattern": r"ngrok http", "technique_id": "T1583", "technique_name": "Acquire Infrastructure", "tactic": "Resource Development", "confidence": 0.90},
    {"pattern": r"ssh -R \d+:", "technique_id": "T1583", "technique_name": "Acquire Infrastructure", "tactic": "Resource Development", "confidence": 0.90},

    # --- INITIAL ACCESS ---
    {"pattern": r"ssh .*@", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access", "confidence": 0.60},
    {"pattern": r"su - [a-zA-Z0-9]+", "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts", "tactic": "Initial Access", "confidence": 0.85},
    {"pattern": r"useradd -m attacker", "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts", "tactic": "Initial Access", "confidence": 0.98},
    {"pattern": r"sqlmap -u", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.98},
    {"pattern": r"exploit-db search", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.90},
    {"pattern": r"openvpn .*\.ovpn", "technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access", "confidence": 0.95},
    {"pattern": r"ssh -D \d+", "technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access", "confidence": 0.95},
    {"pattern": r"wget http.*payload", "technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "confidence": 0.90},

    # --- EXECUTION ---
    {"pattern": r"bash .*\.sh", "technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution", "confidence": 0.80},
    {"pattern": r"python .*\.py", "technique_id": "T1059.006", "technique_name": "Command and Scripting Interpreter: Python", "tactic": "Execution", "confidence": 0.80},
    {"pattern": r"sh -c '", "technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution", "confidence": 0.90},
    {"pattern": r"/bin/bash -i >& /dev/tcp/", "technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution", "confidence": 0.99},
    {"pattern": r"python -c 'import os; os.system\(", "technique_id": "T1059.006", "technique_name": "Command and Scripting Interpreter: Python", "tactic": "Execution", "confidence": 0.98},
    {"pattern": r"crontab -e", "technique_id": "T1053.003", "technique_name": "Scheduled Task/Job: Cron", "tactic": "Execution", "confidence": 0.95},
    {"pattern": r"echo \".*\" > /etc/crontab", "technique_id": "T1053.003", "technique_name": "Scheduled Task/Job: Cron", "tactic": "Execution", "confidence": 0.95},
    {"pattern": r"chmod \+x .*; \./", "technique_id": "T1204.002", "technique_name": "User Execution: Malicious File", "tactic": "Execution", "confidence": 0.90},
    {"pattern": r"dbus-send --system", "technique_id": "T1559", "technique_name": "Inter-Process Communication", "tactic": "Execution", "confidence": 0.90},

    # --- PERSISTENCE ---
    {"pattern": r"echo \".*\" > ~/.bashrc", "technique_id": "T1547.001", "technique_name": "Boot or Logon Autostart Execution: Shell Configuration Scripts", "tactic": "Persistence", "confidence": 0.95},
    {"pattern": r"echo .*Exec=.* > ~/.config/autostart/", "technique_id": "T1547.013", "technique_name": "Boot or Logon Autostart Execution: XDG Autostart Entries", "tactic": "Persistence", "confidence": 0.95},
    {"pattern": r"echo .* > /etc/init.d/", "technique_id": "T1037", "technique_name": "Boot or Logon Initialization Scripts", "tactic": "Persistence", "confidence": 0.95},
    {"pattern": r"systemd-run --on-active", "technique_id": "T1546", "technique_name": "Event Triggered Execution", "tactic": "Persistence", "confidence": 0.90},
    {"pattern": r"echo .* > \$PROFILE", "technique_id": "T1546.013", "technique_name": "Event Triggered Execution: PowerShell Profile", "tactic": "Persistence", "confidence": 0.90},
    {"pattern": r"usermod -aG sudo", "technique_id": "T1098", "technique_name": "Account Manipulation", "tactic": "Persistence", "confidence": 0.98},
    {"pattern": r"useradd -m persistent", "technique_id": "T1136", "technique_name": "Create Account", "tactic": "Persistence", "confidence": 0.95},

    # --- PRIVILEGE ESCALATION ---
    {"pattern": r"sudo exploit", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "confidence": 0.95},
    {"pattern": r"sudo -u root sh", "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "confidence": 0.98},
    {"pattern": r"sudo -l", "technique_id": "T1548.003", "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": "Privilege Escalation", "confidence": 0.95},
    {"pattern": r"gdb -p \d+ --batch", "technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Privilege Escalation", "confidence": 0.98},
    {"pattern": r"su - root", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Privilege Escalation", "confidence": 0.95},
    {"pattern": r"systemctl create .*\.service", "technique_id": "T1543", "technique_name": "Create or Modify System Process", "tactic": "Privilege Escalation", "confidence": 0.95},

    # --- DEFENSE EVASION ---
    {"pattern": r"base64 -d .* > ", "technique_id": "T1027.013", "technique_name": "Obfuscated Files or Information: Encrypted/Encoded File", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"openssl .* -d -in ", "technique_id": "T1027.013", "technique_name": "Obfuscated Files or Information: Encrypted/Encoded File", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"insmod .*\.ko", "technique_id": "T1014", "technique_name": "Rootkit", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"export LD_PRELOAD=", "technique_id": "T1014", "technique_name": "Rootkit", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"mkdir \.\./ ; cp .* \.\./", "technique_id": "T1036.005", "technique_name": "Masquerading: Execute from Masquerading Directory", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"rm ~/.bash_history", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"echo > ~/.bash_history", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"cat /dev/null > ~/.bash_history", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"ln -sf /dev/null ~/.bash_history", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"truncate -s 0 ~/.bash_history", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"history -c", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"unset HISTFILE", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"^\s+ls /etc", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"ssh -T .* '.*'", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.85},
    {"pattern": r"truncate -s 0 /var/lib/docker/containers/", "technique_id": "T1070.003", "technique_name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"python -c 'import base64;.*b64decode", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"perl -MMIME::Base64 -e", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"echo .* | base64 -d", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"echo .* | xxd -r -p", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"python -c 'exec\(bytes\.fromhex", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"systemctl disable systemd-journald", "technique_id": "T1562", "technique_name": "Impair Defenses", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"sed -i 's/LogLevel=info/LogLevel=error/'", "technique_id": "T1562", "technique_name": "Impair Defenses", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"touch -[amt] ", "technique_id": "T1070.006", "technique_name": "Indicator Removal: Timestomp", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"touch -r ", "technique_id": "T1070.006", "technique_name": "Indicator Removal: Timestomp", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"ping -c \d+ 127\.0\.0\.1", "technique_id": "T1497.003", "technique_name": "Virtualization/Sandbox Evasion: Time Based Evasion", "tactic": "Defense Evasion", "confidence": 0.85},
    {"pattern": r"ufw disable", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"iptables -F", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"systemctl stop ufw", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.99},
    {"pattern": r"ufw logging off", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"ufw allow ", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"iptables -A INPUT", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"echo \".*\" >> /etc/ufw/user.rules", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"iptables-save >", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"iptables -P INPUT ACCEPT", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"iptables -D INPUT", "technique_id": "T1562.004", "technique_name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"cp /var/mail/.* /tmp; rm", "technique_id": "T1070.008", "technique_name": "Indicator Removal: Clear Mailbox Data", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"shred -u ", "technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"mkfs -f ", "technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"dd if=.* of=.* bs=1 seek=1", "technique_id": "T1027.001", "technique_name": "Obfuscated Files or Information: Binary Padding", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"truncate -s \+\d+ ", "technique_id": "T1027.001", "technique_name": "Obfuscated Files or Information: Binary Padding", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"passwd -u ", "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"su - nobody", "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts", "tactic": "Defense Evasion", "confidence": 0.90},
    {"pattern": r"prctl --set-name ", "technique_id": "T1036.004", "technique_name": "Masquerading: Masquerade Task or Service", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"mount --bind /bin/true /proc/self/comm", "technique_id": "T1036.004", "technique_name": "Masquerading: Masquerade Task or Service", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"cron -f", "technique_id": "T1036.003", "technique_name": "Masquerading: Rename System Utilities", "tactic": "Defense Evasion", "confidence": 0.85},
    {"pattern": r"cp ca.crt /usr/local/share/ca-certificates/", "technique_id": "T1553.004", "technique_name": "Subvert Trust Controls: Install Root Certificate", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"auditctl -w /etc -p wa", "technique_id": "T1562.006", "technique_name": "Impair Defenses: Indicator Blocking", "tactic": "Defense Evasion", "confidence": 0.98},
    {"pattern": r"export HISTCONTROL=ignorespace", "technique_id": "T1562.003", "technique_name": "Impair Defenses: Impair Command History Logging", "tactic": "Defense Evasion", "confidence": 0.95},
    {"pattern": r"export HISTSIZE=0", "technique_id": "T1562.003", "technique_name": "Impair Defenses: Impair Command History Logging", "tactic": "Defense Evasion", "confidence": 0.98},

    # --- CREDENTIAL ACCESS ---
    {"pattern": r"cat /etc/passwd", "technique_id": "T1003.008", "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "Credential Access", "confidence": 0.95},
    {"pattern": r"cat /etc/shadow", "technique_id": "T1003.008", "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "Credential Access", "confidence": 0.98},
    {"pattern": r"unshadow\b", "technique_id": "T1003.008", "technique_name": "OS Credential Dumping", "tactic": "Credential Access", "confidence": 0.99},
    {"pattern": r"cat \.ssh/id_rsa", "technique_id": "T1552.004", "technique_name": "Unsecured Credentials: Private Keys", "tactic": "Credential Access", "confidence": 0.98},
    {"pattern": r"grep -r password", "technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "confidence": 0.85},
    {"pattern": r"\bjohn\b", "technique_id": "T1110.002", "technique_name": "Brute Force: Password Cracking", "tactic": "Credential Access", "confidence": 0.95},
    {"pattern": r"\bhashcat\b", "technique_id": "T1110.002", "technique_name": "Brute Force: Password Cracking", "tactic": "Credential Access", "confidence": 0.95},

    # --- DISCOVERY ---
    {"pattern": r"ls -la /etc", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery", "confidence": 0.70},
    {"pattern": r"find / -name \"\*\.conf\"", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery", "confidence": 0.85},
    {"pattern": r"du -sh \*", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery", "confidence": 0.70},
    {"pattern": r"ifconfig", "technique_id": "T1016", "technique_name": "System Network Configuration Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"ip addr", "technique_id": "T1016", "technique_name": "System Network Configuration Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"netstat -anp", "technique_id": "T1016", "technique_name": "System Network Configuration Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"ss -tuln", "technique_id": "T1016", "technique_name": "System Network Configuration Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"lsof -i", "technique_id": "T1049", "technique_name": "System Network Connections Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"ps aux", "technique_id": "T1057", "technique_name": "Process Discovery", "tactic": "Discovery", "confidence": 0.90},
    {"pattern": r"uname -a", "technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "confidence": 0.95},
    {"pattern": r"cat /etc/os-release", "technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "confidence": 0.95},
    {"pattern": r"lsb_release -a", "technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "confidence": 0.95},
    {"pattern": r"systemd-detect-virt", "technique_id": "T1497", "technique_name": "Virtualization/Sandbox Evasion", "tactic": "Discovery", "confidence": 0.98},

    # --- LATERAL MOVEMENT ---
    {"pattern": r"ssh .*@.* '.*'", "technique_id": "T1021.004", "technique_name": "Remote Services: SSH", "tactic": "Lateral Movement", "confidence": 0.85},
    {"pattern": r"scp .* .*@.*:", "technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement", "confidence": 0.85},
    {"pattern": r"ssh -D \d+ ", "technique_id": "T1090", "technique_name": "Proxy", "tactic": "Lateral Movement", "confidence": 0.90},

    # --- COLLECTION ---
    {"pattern": r"cat /etc/passwd", "technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection", "confidence": 0.85},
    {"pattern": r"find / -name \"\*key\*\"", "technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection", "confidence": 0.90},
    {"pattern": r"xclip -o", "technique_id": "T1115", "technique_name": "Clipboard Data", "tactic": "Collection", "confidence": 0.98},
    {"pattern": r"scrot\b", "technique_id": "T1113", "technique_name": "Screen Capture", "tactic": "Collection", "confidence": 0.98},

    # --- COMMAND AND CONTROL ---
    {"pattern": r"curl -d .* attacker\.com", "technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control", "confidence": 0.95},
    {"pattern": r"wget --post-data=.* attacker\.com", "technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control", "confidence": 0.95},
    {"pattern": r"nc -l -p \d+", "technique_id": "T1571", "technique_name": "Non-Standard Port", "tactic": "Command and Control", "confidence": 0.90},
    {"pattern": r"socat TCP-LISTEN:", "technique_id": "T1571", "technique_name": "Non-Standard Port", "tactic": "Command and Control", "confidence": 0.95},
    {"pattern": r"nc attacker \d+ -e /bin/sh", "technique_id": "T1095", "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control", "confidence": 0.99},
    {"pattern": r"wget .*attacker\.com/tool", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control", "confidence": 0.95},

    # --- EXFILTRATION ---
    {"pattern": r"curl -d @.* attacker\.com", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "confidence": 0.95},
    {"pattern": r"curl -F file=@.* attacker\.com", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "confidence": 0.95},

    # --- IMPACT ---
    {"pattern": r"shred -u sensitive.txt", "technique_id": "T1485", "technique_name": "Data Destruction", "tactic": "Impact", "confidence": 0.98},
    {"pattern": r"rm -rf /data", "technique_id": "T1485", "technique_name": "Data Destruction", "tactic": "Impact", "confidence": 0.95},
    {"pattern": r"systemctl stop backup.service", "technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact", "confidence": 0.99},
    {"pattern": r"openssl enc -aes-256-cbc", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact", "confidence": 0.90},
    {"pattern": r"xmrig -o ", "technique_id": "T1496", "technique_name": "Resource Hijacking", "tactic": "Impact", "confidence": 0.99},
]

def map_command_to_mitre(command: str) -> list:
    """
    Evaluates a command string against known MITRE ATT&CK patterns.
    Returns a list of matched techniques.
    """
    matched = []
    cmd_lower = command.lower()
    
    for mapping in MITRE_MAPPING:
        if re.search(str(mapping["pattern"]), cmd_lower):
            matched.append({
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
                "tactic": mapping["tactic"],
                "confidence": mapping["confidence"],
                "evidence": command[:200]  # truncate evidence if too long
            })
            
    return matched
