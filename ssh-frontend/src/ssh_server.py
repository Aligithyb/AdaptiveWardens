#!/usr/bin/env python3
"""SSH Honeypot - Database-Integrated Version"""
import asyncio
import asyncssh
import uuid
import os
import httpx
from datetime import datetime

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://localhost:8001")
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", None)
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
HOSTNAME = "api-prod-01"

SSH_BANNER = """Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 29 00:22:14 UTC 2026

  System load:  2.14               Processes:             187
  Usage of /:   24.2% of 38.60GB   Users logged in:       0
  Memory usage: 32%                IPv4 address for eth0: 10.0.1.45
  Swap usage:   0%

0 updates can be applied immediately.

This system is monitored. Unauthorized access will be prosecuted.
NexoPay Inc. — Payment Infrastructure — PCI-DSS Compliant Zone

Last login: Tue Apr 29 00:10:14 2026 from 10.0.1.5
"""

# High-value honeytoken file paths — accessing these triggers an alert
HONEYTOKEN_FILES = {
    '/root/.aws/credentials',
    '/root/.aws/config',
    '/opt/nexopay/config/stripe.env',
    '/opt/nexopay/config/auth.env',
    '/opt/nexopay/config/aws.env',
    '/opt/nexopay/config/database.env',
    '/root/.ssh/id_rsa',
    '/root/.git-credentials',
    '/root/.kube/config',
    '/root/.docker/config.json',
    '/root/.npmrc',
    '/var/backups/nexopay_db_2026-04-28.sql',
    '/var/backups/nexopay_db_2026-04-21.sql',
    '/home/deploy/.env',
    '/opt/nexopay/data/payments.db',
}

# Static responses for common commands (no AI/DB round-trip needed)
STATIC_RESPONSES = {
    "whoami":   lambda ctx: ctx.get("username", "root"),
    "id":       lambda ctx: f"uid=0(root) gid=0(root) groups=0(root),4(adm),27(sudo)",
    "hostname": lambda ctx: HOSTNAME,
    "uname -a": lambda ctx: f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname":    lambda ctx: "Linux",

    "ifconfig": lambda ctx: (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.1.45  netmask 255.255.255.0  broadcast 10.0.1.255\n"
        "        inet6 fe80::a00:1ff:fe2d:4501  prefixlen 64  scopeid 0x20<link>\n"
        "        RX packets 3456789  bytes 2345678901 (2.3 GB)\n"
        "        TX packets 1234567  bytes 987654321  (987.6 MB)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0"
    ),
    "ip addr": lambda ctx: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
        "    link/ether 02:00:01:2d:45:01 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 10.0.1.45/24 brd 10.0.1.255 scope global eth0"
    ),
    "ip a": lambda ctx: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 10.0.1.45/24 brd 10.0.1.255 scope global eth0"
    ),

    "df -h": lambda ctx: (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1        40G  8.8G   29G  24% /\n"
        "/dev/sdb1       100G  4.1G   91G   5% /opt\n"
        "tmpfs           7.9G     0  7.9G   0% /dev/shm"
    ),
    "df": lambda ctx: (
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/sda1       41251136  9234512  29875240  24% /\n"
        "/dev/sdb1      103080896  4234512  93534256   5% /opt\n"
        "tmpfs            8192000        0   8192000   0% /dev/shm"
    ),
    "free -m": lambda ctx: (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:           15999        5112        3030         100       7856       10498\n"
        "Swap:           2047           0        2047"
    ),
    "free": lambda ctx: (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:        16384000     5234512     3123412      102344     8026076    10876543\n"
        "Swap:        2097148           0     2097148"
    ),
    "uptime": lambda ctx: f" 00:22:14 up 18 days,  6:45,  1 user,  load average: 2.14, 1.98, 1.87",
    "lsblk": lambda ctx: (
        "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
        "sda      8:0    0   40G  0 disk\n└─sda1   8:1    0   40G  0 part /\n"
        "sdb      8:16   0  100G  0 disk\n└─sdb1   8:17   0  100G  0 part /opt"
    ),
    "mount": lambda ctx: (
        "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n"
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
        "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
        "/dev/sdb1 on /opt type ext4 (rw,relatime)"
    ),
    "pwd": lambda ctx: ctx.get("current_directory", "/root"),

    "history": lambda ctx: (
        "    1  systemctl status nexopay-api\n"
        "    2  kubectl get pods -n nexopay\n"
        "    3  cat /opt/nexopay/config/stripe.env\n"
        "    4  aws s3 ls s3://nexopay-backups-prod-us-east-1 --profile nexopay-prod\n"
        "    5  pg_dump -h db-primary.nexopay.internal -U nexopay_app nexopay_prod > /var/backups/nexopay_db_2026-04-28.sql\n"
        "    6  tail -f /opt/nexopay/logs/error.log\n"
        "    7  cat /opt/nexopay/config/database.env\n"
        "    8  redis-cli -h cache-01.nexopay.internal -a r3d1s_nxp_2025_pr0d ping\n"
        "    9  systemctl restart nexopay-api\n"
        "   10  kubectl rollout history deploy/nexopay-api -n nexopay\n"
        "   11  docker pull registry.nexopay.internal:5000/nexopay-api:v2.14.3\n"
        "   12  cat /root/.aws/credentials\n"
        "   13  aws sts get-caller-identity\n"
        "   14  ls -la /opt/nexopay/config/\n"
        "   15  less /opt/nexopay/logs/app.log"
    ),

    "netstat": lambda ctx: (
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n"
        f"tcp        0      0 10.0.1.45:22            10.0.1.5:43210          ESTABLISHED"
    ),
    "netstat -an": lambda ctx: (
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN"
    ),
    "netstat -tulpn": lambda ctx: (
        "Proto Recv-Q Send-Q Local Address      Foreign Address  State    PID/Program\n"
        "tcp        0      0 0.0.0.0:22         0.0.0.0:*        LISTEN   134/sshd\n"
        "tcp        0      0 0.0.0.0:80         0.0.0.0:*        LISTEN   892/nginx\n"
        "tcp        0      0 0.0.0.0:443        0.0.0.0:*        LISTEN   892/nginx\n"
        "tcp        0      0 127.0.0.1:3000     0.0.0.0:*        LISTEN   3100/node\n"
        "tcp        0      0 127.0.0.1:6379     0.0.0.0:*        LISTEN   2048/redis-server\n"
        "tcp6       0      0 :::5432            :::*             LISTEN   2150/postgres"
    ),
    "ss -tulpn": lambda ctx: (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n"
        "tcp   LISTEN 0      128    0.0.0.0:22           0.0.0.0:*         users:((\"sshd\",pid=134))\n"
        "tcp   LISTEN 0      511    0.0.0.0:80           0.0.0.0:*         users:((\"nginx\",pid=892))\n"
        "tcp   LISTEN 0      511    0.0.0.0:443          0.0.0.0:*         users:((\"nginx\",pid=892))\n"
        "tcp   LISTEN 0      511    127.0.0.1:3000       0.0.0.0:*         users:((\"node\",pid=3100))\n"
        "tcp   LISTEN 0      128    127.0.0.1:6379       0.0.0.0:*         users:((\"redis-server\",pid=2048))"
    ),

    "last": lambda ctx: (
        f"root     pts/0        10.0.1.5         Tue Apr 29 00:22   still logged in\n"
        f"deploy   pts/1        10.0.1.50        Mon Apr 28 18:32 - 18:45  (00:12)\n"
        f"root     pts/0        185.220.101.45   Mon Apr 28 00:22 - 00:35  (00:13)\n"
        f"root     pts/0        10.0.1.5         Sun Apr 27 22:10 - 22:48  (00:37)\n"
        f"reboot   system boot  5.15.0-91        Sun Apr 10 17:37   still running\n\n"
        f"wtmp begins Sun Apr 10 17:37:02 2026"
    ),

    "sudo -l": lambda ctx: (
        f"Matching Defaults entries for {ctx.get('username','root')} on {HOSTNAME}:\n"
        f"    env_reset, mail_badpass,\n"
        f"    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
        f"User {ctx.get('username','root')} may run the following commands on {HOSTNAME}:\n"
        f"    (ALL : ALL) ALL"
    ),

    "crontab -l": lambda ctx: (
        "# m h  dom mon dow   command\n"
        "0 3 * * * /etc/cron.daily/nexopay-backup >> /var/log/nexopay-backup.log 2>&1\n"
        "0 4 * * 0 /usr/sbin/certbot renew --quiet\n"
        "*/5 * * * * /usr/bin/node /opt/nexopay/scripts/health-check.js"
    ),

    "find / -name passwords": lambda ctx: (
        "find: '/proc/tty/driver': Permission denied\n"
        "find: '/root/.ssh': Permission denied"
    ),
    "find / -name '*.conf'": lambda ctx: (
        "/etc/ssh/sshd_config\n/etc/nginx/nginx.conf\n"
        "/etc/fail2ban/jail.local\n/etc/netplan/01-netcfg.yaml\n"
        "find: '/proc/tty/driver': Permission denied"
    ),
    "find / -name '*.env'": lambda ctx: (
        "/opt/nexopay/config/stripe.env\n/opt/nexopay/config/auth.env\n"
        "/opt/nexopay/config/database.env\n/opt/nexopay/config/aws.env\n"
        "/home/deploy/.env"
    ),
    "find / -name '*.env' 2>/dev/null": lambda ctx: (
        "/opt/nexopay/config/stripe.env\n/opt/nexopay/config/auth.env\n"
        "/opt/nexopay/config/database.env\n/opt/nexopay/config/aws.env\n"
        "/home/deploy/.env"
    ),
    "find / -name '*.db'": lambda ctx: "/opt/nexopay/data/payments.db",
    "find / -name '*.db' 2>/dev/null": lambda ctx: "/opt/nexopay/data/payments.db",
}

def get_fallback(cmd: str, ctx: dict) -> str:
    base = cmd.split()[0] if cmd.split() else cmd
    fallbacks = {"wget": "Connection refused.", "curl": "curl: (7) Failed to connect to host", "nmap": "Host seems down"}
    return fallbacks.get(base, f"bash: {base}: command not found")

class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, username, source_ip):
        self.session_id = str(uuid.uuid4())
        self.username = username
        self.source_ip = source_ip
        self.current_directory = "/root"
        self.context: dict = {"username": username, "current_directory": "/root"}
        self.http_client = httpx.AsyncClient(timeout=30.0)  # Increased timeout for AI
        self.session_ready = False
        self.command_history = []  # NEW: For AI context
    
    def connection_made(self, chan):
        self.chan = chan
    
    def shell_requested(self):
        return True
    
    def session_started(self):
        """Show prompt immediately, init DB in background"""
        self.chan.write(SSH_BANNER)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
        asyncio.create_task(self._init_db())
    
    async def _init_db(self):
        try:
            r = await self.http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": self.session_id, "source_ip": self.source_ip,
                "protocol": "ssh", "username": self.username, "password": "***"
            })
            if r.status_code == 200:
                print(f"✅ Session {self.session_id} created")
                self.session_ready = True
                state_r = await self.http_client.get(f"{SANDBOX_URL}/sessions/{self.session_id}/state")
                if state_r.status_code == 200:
                    self.context["environment"] = state_r.json().get("environment", {})
        except Exception as e:
            print(f"⚠️ DB init failed: {e}")
    
    async def _process_command_string(self, full_data):
        """Split by newline and process each command"""
        lines = full_data.split('\n')
        for raw_line in lines:
            raw_line = raw_line.strip()
            if not raw_line:
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue
            
            # Handle comments
            cmd = raw_line.split('#')[0].strip()
            if not cmd:
                # Just a comment - show prompt
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue
            
            if cmd in ["exit", "logout"]:
                self.chan.write("\nlogout\n")
                await self._close()
                self.chan.close()
                return

            # Normal command processing
            if cmd.startswith("cd "):
                self._handle_cd(cmd)
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            elif cmd.startswith("ls") or cmd.startswith("cat ") or cmd.startswith("touch ") or cmd.startswith("mkdir "):
                await self._handle_fs_command(cmd)
            elif cmd.startswith("ps"):
                await self._handle_ps_command(cmd)
            elif cmd in ("env", "printenv"):
                await self._handle_env_command()
            else:
                await self._handle_generic_command(cmd)

    def data_received(self, data, datatype):
        asyncio.create_task(self._process_command_string(data))
    
    async def _handle_generic_command(self, cmd: str):
        """Handle commands: sqlite3 → static → AI → fallback"""
        cmd_lower = cmd.lower().strip()
        output = None

        if cmd_lower.startswith("sqlite3"):
            output = self._handle_sqlite3(cmd)
            asyncio.create_task(self._alert_honeytoken("/opt/nexopay/data/payments.db"))
        else:
            for pattern, handler in STATIC_RESPONSES.items():
                if cmd_lower == pattern or cmd_lower.startswith(pattern + " "):
                    output = handler(self.context)
                    break

            if output is None and AI_ENGINE_URL:
                output = await self._get_ai_response(cmd)

            if output is None:
                output = get_fallback(cmd, self.context)

        if output:
            self.chan.write(output + "\n")

        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    def _handle_sqlite3(self, cmd: str) -> str:
        """Return canned sqlite3 output for the payments.db honeytoken database."""
        c = cmd.lower()
        if ".tables" in c:
            return "api_tokens  sessions  transactions  users  webhook_secrets"
        if ".schema" in c or ".dump" in c:
            return (
                "CREATE TABLE users (id varchar(26), email varchar(255), password_hash varchar(255), "
                "stripe_customer_id varchar(50), kyc_status varchar(20), created_at datetime);\n"
                "CREATE TABLE api_tokens (id varchar(26), user_id varchar(26), token varchar(64), "
                "token_hash varchar(128), scope varchar(255), last_used_at datetime, expires_at datetime);\n"
                "CREATE TABLE transactions (id varchar(26), user_id varchar(26), amount_cents integer, "
                "currency char(3), stripe_payment_intent_id varchar(66), status varchar(20), created_at datetime);\n"
                "CREATE TABLE webhook_secrets (merchant_id varchar(26), secret varchar(64), created_at datetime);"
            )
        if "api_tokens" in c:
            return (
                "tk_01HXA1B2C3D4E5|u_01HX4KP2QRSTUV|nxp_live_3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c|payments:read payments:write|2027-04-28\n"
                "tk_01HXA1B2C3D4F6|u_01HX4KP2WXYZAB|nxp_live_7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f|payments:read|2027-04-27\n"
                "tk_01HXA1B2C3D4G7|u_01HX4KP3CDEFGH|nxp_live_1z2y3x4w5v6u7t8s9r0q1p2o3n4m5l6k7j8i9h0g1f2e3d4c5b6a|payments:write|2027-04-25"
            )
        if "users" in c:
            return (
                "u_01HX4KP2QRSTUV|james.hartley@gmail.com|$2b$12$LJ3kQrPz8mVyNx...|cus_NxP3x4yA1b2c3|verified\n"
                "u_01HX4KP2WXYZAB|sarah.chen@techcorp.io|$2b$12$Kp9mNqRs3tUvWx...|cus_NxP5x6yB2c3d4|verified\n"
                "u_01HX4KP3CDEFGH|michael.torres@enterprise.com|$2b$12$Mn0oP1qR2sT3uV...|cus_NxP7x8yC3d4e5|verified"
            )
        if "transactions" in c:
            return (
                "txn_01HXB1C2D3E4F5|u_01HX4KP2QRSTUV|9999|USD|pi_3OxNpYLkdIwHu7ix1vQaXbZc|succeeded\n"
                "txn_01HXB1C2D3E4G6|u_01HX4KP2WXYZAB|4999|USD|pi_3OxNpYMkdIwHu7ix2wRbYcZd|succeeded\n"
                "txn_01HXB1C2D3E4H7|u_01HX4KP3CDEFGH|149900|USD|pi_3OxNpYNkdIwHu7ix3xScZdAe|processing"
            )
        if "webhook_secrets" in c:
            return (
                "m_3xNp4y1234ABCD|whsec_3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b|2025-10-01\n"
                "m_3xNp4y5678EFGH|whsec_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1|2025-11-15"
            )
        # Default: open DB — show prompt-like output
        return "SQLite version 3.37.2 2022-01-06 13:25:41\nEnter \".help\" for usage hints.\nsqlite>"

    async def _alert_honeytoken(self, path: str):
        """Record honeytoken access IOC and send urgent Slack alert."""
        print(f"🚨 HONEYTOKEN ACCESSED: {path} by {self.source_ip}")
        try:
            await self.http_client.post(f"{SANDBOX_URL}/iocs/{self.session_id}", json={
                "ioc_type": "honeytoken_access",
                "value": path,
                "confidence": 0.99,
                "context": f"High-value file accessed from {self.source_ip} (user: {self.username})"
            })
        except Exception:
            pass
        if SLACK_WEBHOOK_URL:
            try:
                await self.http_client.post(SLACK_WEBHOOK_URL, json={
                    "text": (
                        f":rotating_light: *HONEYTOKEN ACCESSED* :rotating_light:\n"
                        f"*File:* `{path}`\n"
                        f"*Attacker IP:* `{self.source_ip}`\n"
                        f"*Username:* `{self.username}`\n"
                        f"*Session:* `{self.session_id}`\n"
                        f"*Server:* `{HOSTNAME}` (NexoPay prod)"
                    )
                })
            except Exception:
                pass
    
    async def _get_ai_response(self, cmd: str) -> str | None:
        """NEW: Get AI-generated response"""
        try:
            r = await self.http_client.post(f"{AI_ENGINE_URL}/generate-response", json={
                "command": cmd,
                "context": self.context,
                "history": self.command_history[-10:]
            })
            
            if r.status_code == 200:
                data = r.json()
                cached = "🔄" if data.get("cached") else "🤖"
                print(f"{cached} AI response for: {cmd}")
                
                # Report extracted IOCs to Sandbox Store
                iocs = data.get("iocs", [])
                for ioc in iocs:
                    asyncio.create_task(self._record_ioc(ioc))
                    
                # Report MITRE techniques to Sandbox Store
                mitre_techniques = data.get("mitre_techniques", [])
                for technique in mitre_techniques:
                    asyncio.create_task(self._record_mitre_technique(technique))
                    
                return data.get("response", None)
        except Exception as e:
            print(f"⚠️ AI error: {e}")
        
        return None
    
    def _handle_cd(self, cmd: str):
        """Handle cd command"""
        parts = cmd.split()
        if len(parts) == 1:
            self.current_directory = "/root"
        else:
            new_dir = parts[1]
            if new_dir.startswith("/"):
                self.current_directory = new_dir
            elif new_dir == "..":
                if self.current_directory != "/":
                    self.current_directory = "/".join(self.current_directory.rstrip("/").split("/")[:-1]) or "/"
            elif new_dir == ".":
                pass
            else:
                self.current_directory = f"{self.current_directory.rstrip('/')}/{new_dir}"
        self.context["current_directory"] = self.current_directory
    
    async def _handle_fs_command(self, cmd: str):
        """Handle filesystem commands using database"""
        output = ""
        
        if not self.session_ready:
            output = "bash: filesystem not ready"
        elif cmd.startswith("ls"):
            parts = cmd.split()
            path = parts[1] if len(parts) > 1 else self.current_directory
            if not path.startswith("/"):
                path = f"{self.current_directory.rstrip('/')}/{path}"
            
            try:
                r = await self.http_client.get(f"{SANDBOX_URL}/files/{self.session_id}/list", params={"path": path})
                if r.status_code == 200:
                    entries = r.json().get("entries", [])
                    if "-la" in cmd or "-al" in cmd:
                        for e in entries:
                            output += f"{e['permissions']} {e['owner']} {e['group']} {e['size']:>8} {e['name']}\n"
                    else:
                        output = "  ".join([e['name'] for e in entries])
                else:
                    output = f"ls: cannot access '{path}': No such file or directory"
            except Exception as e:
                output = f"ls: error: {e}"
        
        elif cmd.startswith("cat "):
            parts = cmd.split()
            if len(parts) < 2:
                output = "cat: missing operand"
            else:
                path = parts[1]
                if not path.startswith("/"):
                    path = f"{self.current_directory.rstrip('/')}/{path}"
                
                try:
                    r = await self.http_client.get(f"{SANDBOX_URL}/files/{self.session_id}", params={"path": path})
                    if r.status_code == 200:
                        output = r.json().get("content", "")
                        if path in HONEYTOKEN_FILES:
                            asyncio.create_task(self._alert_honeytoken(path))
                    else:
                        output = f"cat: {path}: No such file or directory"
                except Exception as e:
                    output = f"cat: error: {e}"
        
        elif cmd.startswith("touch "):
            parts = cmd.split()
            if len(parts) < 2:
                output = "touch: missing operand"
            else:
                path = parts[1]
                if not path.startswith("/"):
                    path = f"{self.current_directory.rstrip('/')}/{path}"
                
                try:
                    r = await self.http_client.post(f"{SANDBOX_URL}/files/{self.session_id}", json={
                        "path": path,
                        "content": "",
                        "permissions": "644"
                    })
                    if r.status_code == 200:
                        output = ""
                    else:
                        output = f"touch: cannot touch '{path}'"
                except Exception as e:
                    output = f"touch: error: {e}"
        
        elif cmd.startswith("mkdir "):
            output = ""
        
        if output:
            self.chan.write(output + "\n")
        
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
    
    async def _handle_ps_command(self, cmd: str):
        """Handle ps command using database"""
        output = ""
        
        if not self.session_ready:
            output = "bash: process list not ready"
        else:
            try:
                r = await self.http_client.get(f"{SANDBOX_URL}/processes/{self.session_id}")
                if r.status_code == 200:
                    processes = r.json().get("processes", [])
                    if "aux" in cmd:
                        output = "USER  PID %CPU %MEM    VSZ   RSS TTY STAT START   TIME COMMAND\n"
                        for p in processes:
                            output += f"{p['username']:<6} {p['pid']:>5} {p['cpu_percent']:>4.1f} {p['mem_percent']:>4.1f}      0     0 ?   {p['status'][:2].upper()}      0   0:00 {p['name']}\n"
                    else:
                        output = "  PID TTY          TIME CMD\n"
                        for p in processes[:5]:
                            output += f"{p['pid']:>5} pts/0    00:00:00 {p['name']}\n"
            except Exception as e:
                output = f"ps: error: {e}"
        
        if output:
            self.chan.write(output)
        
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
    
    async def _handle_env_command(self):
        """Handle env command using database"""
        output = ""
        
        if self.context.get("environment"):
            for key, value in self.context["environment"].items():
                output += f"{key}={value}\n"
        else:
            output = (
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "HOME=/root\nUSER=root\nSHELL=/bin/bash\nTERM=xterm-256color\n"
                "NODE_ENV=production\nNODE_VERSION=20.11.0\n"
                "AWS_DEFAULT_REGION=us-east-1\nAWS_ACCESS_KEY_ID=AKIAVLQNEXOPAY1PROD7\n"
                "STRIPE_SECRET_KEY=" + 'sk_live_' + "51HxY8zKjHnxpay4QmK9p2LrTjY8bZfGbCeAiUoS9pX\n"
                "DB_HOST=db-primary.nexopay.internal\nDB_NAME=nexopay_prod\n"
                "NEXOPAY_VERSION=v2.14.3"
            )
        
        self.chan.write(output + "\n")
        self.command_history.append({"command": "env", "output": output})
        asyncio.create_task(self._record("env", output))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
    
    async def _record(self, cmd: str, out: str):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/commands/{self.session_id}",
                json={"command": cmd, "output": out, "exit_code": 0, "duration_ms": 10})
        except: pass
        
    async def _record_ioc(self, ioc: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/iocs/{self.session_id}",
                json={
                    "ioc_type": ioc.get("ioc_type"),
                    "value": ioc.get("value"),
                    "confidence": ioc.get("confidence", 0.5),
                    "context": "AI extracted from command/response"
                })
        except Exception as e:
            print(f"⚠️ Failed to report IOC: {e}")
            
    async def _record_mitre_technique(self, technique: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/attack-techniques/{self.session_id}",
                json={
                    "technique_id": technique.get("technique_id"),
                    "technique_name": technique.get("technique_name"),
                    "tactic": technique.get("tactic"),
                    "confidence": technique.get("confidence", 0.5),
                    "evidence": technique.get("evidence", "")
                })
        except Exception as e:
            print(f"⚠️ Failed to report MITRE technique: {e}")
    
    async def _close(self):
        try:
            await self.http_client.delete(f"{SANDBOX_URL}/sessions/{self.session_id}")
            print(f"🔒 Session {self.session_id} closed")
        except: pass
        await self.http_client.aclose()

class HoneypotServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None
    
    def connection_made(self, conn):
        self._conn = conn
        print(f"🔌 Connection from {conn.get_extra_info('peername')[0]}")
    
    def connection_lost(self, exc):
        print("🔌 Connection closed")
    
    def begin_auth(self, username):
        print(f"🔐 Auth: {username}")
        return True
    
    def password_auth_supported(self):
        return True
    
    def validate_password(self, username, password):
      HONEYPOT_PASSWORD = "root123"  # Change this to whatever you want
      print(f"🔑 Login attempt: {username}/{password}")
      if password == HONEYPOT_PASSWORD:
        print(f"✅ Accepted: {username}")
        return True
      else:
        print(f"❌ Rejected: {username}/{password}")
        return False
    
    def session_requested(self):
        username = self._conn.get_extra_info('username') or "root"
        source_ip = self._conn.get_extra_info('peername')[0]
        return HoneypotSession(username, source_ip)

async def start_server():
    ai_status = "🤖 AI-Enhanced" if AI_ENGINE_URL else "📝 Static"
    print(f"🍯 SSH Honeypot ({ai_status})")
    print(f"📍 Port {LISTEN_PORT}\n")
    
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{SANDBOX_URL}/health")
            print("✅ Sandbox reachable" if r.status_code == 200 else "⚠️ Sandbox issue")
    except:
        print("⚠️ Sandbox unreachable")
    
    print("🚀 Starting...\n")
    
    await asyncssh.create_server(HoneypotServer, LISTEN_HOST, LISTEN_PORT,
                                 server_host_keys=['ssh_host_key'], process_factory=None)
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\n👋 Bye")
    except Exception as e:
        print(f"❌ Error: {e}")
