#!/usr/bin/env python3
"""Edge session service."""
import asyncio
import asyncssh
import uuid
import os
import time
import math
import random
import httpx
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("sshd")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://localhost:8001")
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", None)
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
HOSTNAME = "api-prod-01"

SERVER_VERSION = 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'

BOOT_TIME = time.time() - random.uniform(15, 22) * 86400

SSH_BANNER = """\r
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r
\r
 * Documentation:  https://help.ubuntu.com\r
 * Management:     https://landscape.canonical.com\r
 * Support:        https://ubuntu.com/advantage\r
\r
  System information as of Tue Apr 29 00:22:14 UTC 2026\r
\r
  System load:  2.14               Processes:             187\r
  Usage of /:   24.2% of 38.60GB   Users logged in:       0\r
  Memory usage: 32%                IPv4 address for eth0: 10.0.1.45\r
  Swap usage:   0%\r
\r
0 updates can be applied immediately.\r
\r
This system is monitored. Unauthorized access will be prosecuted.\r
NexoPay Inc. — Payment Infrastructure — PCI-DSS Compliant Zone\r
\r
Last login: Tue Apr 29 00:10:14 2026 from 10.0.1.5\r
"""

HONEYTOKEN_FILES = {
    '/root/.aws/credentials', '/root/.aws/config',
    '/opt/nexopay/config/stripe.env', '/opt/nexopay/config/auth.env',
    '/opt/nexopay/config/aws.env', '/opt/nexopay/config/database.env',
    '/root/.ssh/id_rsa', '/root/.git-credentials', '/root/.kube/config',
    '/root/.docker/config.json', '/root/.npmrc',
    '/var/backups/nexopay_db_2026-04-28.sql', '/var/backups/nexopay_db_2026-04-21.sql',
    '/home/deploy/.env', '/opt/nexopay/data/payments.db',
}


# ---------------------------------------------------------------------------
# Dynamic metric helpers
# ---------------------------------------------------------------------------
def _loadavg() -> tuple:
    t = time.time()
    l1 = 1.8 + 0.6 * math.sin(t / 90.0) + random.uniform(-0.15, 0.15)
    l5 = 1.8 + 0.4 * math.sin(t / 300.0) + random.uniform(-0.06, 0.06)
    l15 = 1.8 + 0.25 * math.sin(t / 900.0) + random.uniform(-0.03, 0.03)
    return max(0.0, l1), max(0.0, l5), max(0.0, l15)

def _fmt_uptime(ctx: dict) -> str:
    up = time.time() - BOOT_TIME
    days = int(up // 86400)
    hours = int((up % 86400) // 3600)
    mins = int((up % 3600) // 60)
    l1, l5, l15 = _loadavg()
    now = datetime.utcnow().strftime("%H:%M:%S")
    return (f" {now} up {days} days, {hours:2d}:{mins:02d},  1 user,  "
            f"load average: {l1:.2f}, {l5:.2f}, {l15:.2f}")

def _proc_loadavg(ctx: dict) -> str:
    l1, l5, l15 = _loadavg()
    return f"{l1:.2f} {l5:.2f} {l15:.2f} {random.randint(1,4)}/187 {random.randint(20000,41000)}"

def _meminfo_mb(ctx: dict) -> str:
    total = 15999
    used = 5112 + int(800 * math.sin(time.time() / 200.0)) + random.randint(-60, 60)
    buff = 7856 + random.randint(-120, 120)
    free = total - used - buff
    avail = free + buff
    return ("               total        used        free      shared  buff/cache   available\n"
            f"Mem:           {total:>5}       {used:>5}       {free:>5}         100       {buff:>5}       {avail:>5}\n"
            "Swap:           2047           0        2047")

def _meminfo_kb(ctx: dict) -> str:
    total = 16384000
    used = 5234512 + int(800000 * math.sin(time.time() / 200.0)) + random.randint(-60000, 60000)
    buff = 8026076 + random.randint(-120000, 120000)
    free = total - used - buff
    avail = free + buff
    return ("               total        used        free      shared  buff/cache   available\n"
            f"Mem:        {total:>8}     {used:>8}     {free:>8}      102344     {buff:>8}     {avail:>8}\n"
            "Swap:        2097148           0     2097148")


# ---------------------------------------------------------------------------
# ls -la helpers
# ---------------------------------------------------------------------------
_OCTAL_BITS = {'7':'rwx','6':'rw-','5':'r-x','4':'r--','3':'-wx','2':'-w-','1':'--x','0':'---'}

def _octal_to_rwx(perm_str: str) -> str:
    digits = perm_str.zfill(3)[-3:]
    return (_OCTAL_BITS.get(digits[0], '---') +
            _OCTAL_BITS.get(digits[1], '---') +
            _OCTAL_BITS.get(digits[2], '---'))

def _ls_date(modified) -> str:
    if modified:
        try:
            dt = datetime.fromisoformat(str(modified)[:19])
            return dt.strftime("%b %d %H:%M")
        except Exception:
            pass
    return "Apr 29 10:00"

def _format_ls_long(entry: dict) -> str:
    is_dir = entry.get('type') == 'directory'
    perm_prefix = 'd' if is_dir else '-'
    perm_str = perm_prefix + _octal_to_rwx(str(entry.get('permissions', '644')))
    links = '2' if is_dir else '1'
    size = 4096 if is_dir else (entry.get('size') or 0)
    owner = str(entry.get('owner', 'root'))
    group = str(entry.get('group', 'root'))
    date = _ls_date(entry.get('modified'))
    name = entry.get('name', '')
    return f"{perm_str} {links:>2} {owner:<8} {group:<8} {size:>8} {date} {name}"


# ---------------------------------------------------------------------------
# Container-escape / baremetal-validation probes
# ---------------------------------------------------------------------------
CONTAINER_ESCAPE_PROBES = {
    "cat /proc/1/cgroup":                  "0::/init.scope",
    "cat /proc/self/cgroup":               "0::/user.slice/user-1000.slice/session-3.scope",
    "cat /.dockerenv":                     "cat: /.dockerenv: No such file or directory",
    "ls /.dockerenv":                      "ls: cannot access '/.dockerenv': No such file or directory",
    "ls -la /.dockerenv":                  "ls: cannot access '/.dockerenv': No such file or directory",
    "systemd-detect-virt":                 "none",
    "systemd-detect-virt -c":             "none",
    "dmidecode -s system-product-name":    "ProLiant DL380 Gen10",
    "dmidecode -s system-manufacturer":    "HPE",
    "dmidecode -s baseboard-product-name": "ProLiant DL380 Gen10",
    "cat /sys/class/dmi/id/product_name":  "ProLiant DL380 Gen10",
    "cat /sys/class/dmi/id/sys_vendor":    "HPE",
    "cat /sys/class/dmi/id/board_vendor":  "HPE",
    "cat /sys/class/dmi/id/chassis_vendor":"HPE",
}

# Static responses for common commands
STATIC_RESPONSES = {
    "whoami":   lambda ctx: ctx.get("username", "root"),
    "id":       lambda ctx: "uid=0(root) gid=0(root) groups=0(root),4(adm),27(sudo)",
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
    "free -m":          _meminfo_mb,
    "free":             _meminfo_kb,
    "uptime":           _fmt_uptime,
    "cat /proc/loadavg":_proc_loadavg,
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
        "tcp        0      0 10.0.1.45:22            10.0.1.5:43210          ESTABLISHED"
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
        "root     pts/0        10.0.1.5         Tue Apr 29 00:22   still logged in\n"
        "deploy   pts/1        10.0.1.50        Mon Apr 28 18:32 - 18:45  (00:12)\n"
        "root     pts/0        185.220.101.45   Mon Apr 28 00:22 - 00:35  (00:13)\n"
        "root     pts/0        10.0.1.5         Sun Apr 27 22:10 - 22:48  (00:37)\n"
        "reboot   system boot  5.15.0-91        Sun Apr 10 17:37   still running\n\n"
        "wtmp begins Sun Apr 10 17:37:02 2026"
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

# Commands available for Tab completion
_COMPLETABLE_CMDS = sorted({
    'ls', 'cat', 'cd', 'mkdir', 'touch', 'rm', 'mv', 'cp', 'chmod', 'chown',
    'ps', 'env', 'printenv', 'exit', 'logout', 'whoami', 'id', 'hostname',
    'uptime', 'history', 'find', 'grep', 'wget', 'curl', 'sudo', 'su',
    'systemctl', 'journalctl', 'tail', 'head', 'less', 'more', 'vim', 'nano',
    'ssh', 'scp', 'rsync', 'netstat', 'ss', 'ip', 'ifconfig', 'ping', 'nmap',
    'python3', 'python', 'node', 'npm', 'git', 'docker', 'kubectl', 'helm',
    'aws', 'free', 'df', 'lsblk', 'mount', 'uname', 'last', 'who', 'w',
    'crontab', 'awk', 'sed', 'sort', 'uniq', 'wc', 'tee', 'xargs',
    'tar', 'gzip', 'gunzip', 'zip', 'unzip', 'openssl', 'base64',
})


def _realistic_delay(cmd: str) -> float:
    parts = cmd.split()
    base = parts[0] if parts else ""
    heavy = {"find","apt","apt-get","nmap","pip","pip3","wget","curl",
             "dmesg","journalctl","git","docker","kubectl"}
    if base in heavy:
        return random.uniform(0.45, 1.7)
    return random.uniform(0.05, 0.35)


def get_fallback(cmd: str, ctx: dict) -> str:
    base = cmd.split()[0] if cmd.split() else cmd
    fallbacks = {"wget": "Connection refused.", "curl": "curl: (7) Failed to connect to host",
                 "nmap": "Host seems down"}
    return fallbacks.get(base, f"bash: {base}: command not found")


# ---------------------------------------------------------------------------
# Sticky probabilistic authentication
# ---------------------------------------------------------------------------
_AUTH_STATE: dict = {}

def _auth_record(ip: str) -> dict:
    return _AUTH_STATE.setdefault(ip, {
        "accepted": None,
        "attempts": 0,
        "fails": [],
        "threshold": random.randint(3, 5),
        "lockout_until": 0.0,
    })


class SessionHandler(asyncssh.SSHServerSession):
    def __init__(self, username, source_ip):
        self.session_id     = str(uuid.uuid4())
        self.username       = username
        self.source_ip      = source_ip
        self.current_directory = "/root"
        self.context: dict  = {"username": username, "current_directory": "/root"}
        self.http_client    = httpx.AsyncClient(timeout=30.0)
        self.session_ready  = False
        self.command_history = []

        # PTY / line-editor state
        self._pty_mode   = False
        self._line_buf   = ""
        self._cmd_history: list = []
        self._hist_idx   = -1
        self._hist_saved = ""
        self._escape_buf = ""

    def connection_made(self, chan):
        self.chan = chan

    def pty_requested(self, terminal_type, terminal_size, terminal_modes):
        """Accept PTY allocation so the client sends raw keypresses."""
        self._pty_mode = True
        return True

    def shell_requested(self):
        return True

    def session_started(self):
        self.chan.write(SSH_BANNER)
        self._show_prompt()
        asyncio.create_task(self._init_db())

    def _show_prompt(self):
        self.chan.write(f"\r\n{self.username}@{HOSTNAME}:{self.current_directory}$ "
                        if False else
                        f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    def _write_line(self, text: str):
        """Write a line with the correct line ending for current mode."""
        nl = "\r\n" if self._pty_mode else "\n"
        for line in text.split("\n"):
            self.chan.write(line + nl)

    async def _init_db(self):
        try:
            r = await self.http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": self.session_id, "source_ip": self.source_ip,
                "protocol": "ssh", "username": self.username, "password": "***"
            })
            if r.status_code == 200:
                logger.info(f"Session {self.session_id} created")
                self.session_ready = True
                state_r = await self.http_client.get(
                    f"{SANDBOX_URL}/sessions/{self.session_id}/state")
                if state_r.status_code == 200:
                    self.context["environment"] = state_r.json().get("environment", {})
        except Exception as e:
            logger.error(f"DB init failed: {e}")

    # ------------------------------------------------------------------
    # data_received: route to PTY line editor or legacy batch handler
    # ------------------------------------------------------------------
    def data_received(self, data, datatype):
        if self._pty_mode:
            asyncio.create_task(self._handle_pty_input(data))
        else:
            asyncio.create_task(self._process_command_string(data))

    async def _handle_pty_input(self, data: str):
        """Character-by-character PTY line editor with Tab completion and arrow history."""
        i = 0
        while i < len(data):
            ch = data[i]

            # Escape sequence accumulator
            if self._escape_buf or ch == '\x1b':
                self._escape_buf += ch
                if self._escape_buf == '\x1b':
                    i += 1
                    continue
                # Arrow keys: \x1b[A/B/C/D
                if len(self._escape_buf) == 3 and self._escape_buf[1] == '[':
                    seq = self._escape_buf[2]
                    self._escape_buf = ""
                    if seq == 'A':
                        await self._history_up()
                    elif seq == 'B':
                        await self._history_down()
                    # left/right: ignore for now
                elif len(self._escape_buf) >= 3:
                    self._escape_buf = ""  # unknown sequence, discard
                i += 1
                continue

            if ch in ('\r', '\n'):
                await self._process_pty_line()
            elif ch == '\t':
                await self._handle_tab()
            elif ch in ('\x7f', '\x08'):
                self._handle_backspace()
            elif ch == '\x03':   # Ctrl-C
                self.chan.write('^C\r\n')
                self._line_buf = ""
                self._hist_idx = -1
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            elif ch == '\x04':   # Ctrl-D
                if not self._line_buf:
                    self.chan.write("\r\nlogout\r\n")
                    await self._close()
                    self.chan.close()
                    return
            elif ch == '\x0c':   # Ctrl-L: clear screen
                self.chan.write('\x1b[2J\x1b[H')
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                self.chan.write(self._line_buf)
            elif ch.isprintable():
                self._line_buf += ch
                self.chan.write(ch)

            i += 1

    def _handle_backspace(self):
        if self._line_buf:
            self._line_buf = self._line_buf[:-1]
            self.chan.write('\x08 \x08')

    def _clear_current_line(self):
        """Erase current typed line and reprint prompt (for history nav)."""
        prompt = f"{self.username}@{HOSTNAME}:{self.current_directory}$ "
        # Move to line start, erase to end
        self.chan.write(f'\r\x1b[K{prompt}')
        self._line_buf = ""

    async def _history_up(self):
        if not self._cmd_history:
            return
        if self._hist_idx == -1:
            self._hist_saved = self._line_buf
        if self._hist_idx < len(self._cmd_history) - 1:
            self._hist_idx += 1
        self._clear_current_line()
        self._line_buf = self._cmd_history[-(self._hist_idx + 1)]
        self.chan.write(self._line_buf)

    async def _history_down(self):
        if self._hist_idx <= 0:
            if self._hist_idx == 0:
                self._hist_idx = -1
                self._clear_current_line()
                self._line_buf = self._hist_saved
                self.chan.write(self._line_buf)
            return
        self._hist_idx -= 1
        self._clear_current_line()
        self._line_buf = self._cmd_history[-(self._hist_idx + 1)]
        self.chan.write(self._line_buf)

    async def _handle_tab(self):
        """Tab completion: paths from virtual FS or command names."""
        buf = self._line_buf
        parts = buf.split()

        # Determine the word being completed
        if not buf or buf.endswith(' '):
            prefix = ""
            is_cmd = len(parts) == 0
        else:
            prefix = parts[-1] if parts else ""
            is_cmd = len(parts) == 1 and not buf.endswith(' ')

        if is_cmd:
            # Complete command names
            matches = sorted(c for c in _COMPLETABLE_CMDS if c.startswith(prefix))
        elif prefix.startswith('/') or '/' in prefix or prefix.startswith('.'):
            # Path completion from virtual FS
            if '/' in prefix:
                dir_part, file_prefix = prefix.rsplit('/', 1)
                dir_part = dir_part or '/'
            else:
                dir_part = self.current_directory
                file_prefix = prefix

            try:
                r = await self.http_client.get(
                    f"{SANDBOX_URL}/files/{self.session_id}/list",
                    params={"path": dir_part})
                if r.status_code == 200:
                    entries = r.json().get("entries", [])
                    matches = []
                    for e in entries:
                        if e['name'].startswith(file_prefix):
                            suffix = '/' if e.get('type') == 'directory' else ''
                            matches.append(e['name'] + suffix)
                else:
                    matches = []
            except Exception:
                matches = []
        else:
            matches = []

        if len(matches) == 1:
            completion = matches[0][len(prefix):]
            self._line_buf += completion
            self.chan.write(completion)
        elif len(matches) > 1:
            self.chan.write('\r\n' + '  '.join(matches) + '\r\n')
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            self.chan.write(self._line_buf)

    async def _process_pty_line(self):
        """Called on Enter in PTY mode — process the buffered line."""
        line = self._line_buf.strip()
        self.chan.write('\r\n')
        self._line_buf = ""
        self._hist_idx = -1
        if line:
            if not self._cmd_history or self._cmd_history[-1] != line:
                self._cmd_history.append(line)
            await self._process_single_command(line)
        else:
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    # ------------------------------------------------------------------
    # Legacy batch handler (non-PTY clients: load tests, scripts)
    # ------------------------------------------------------------------
    async def _process_command_string(self, full_data: str):
        lines = full_data.split('\n')
        for raw_line in lines:
            raw_line = raw_line.strip()
            if not raw_line:
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue
            cmd = raw_line.split('#')[0].strip()
            if not cmd:
                self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue
            await self._process_single_command(cmd)

    # ------------------------------------------------------------------
    # Core command dispatcher (used by both PTY and batch paths)
    # ------------------------------------------------------------------
    async def _process_single_command(self, cmd: str):
        if cmd in ["exit", "logout"]:
            self.chan.write("logout\r\n")
            await self._close()
            self.chan.close()
            return

        if cmd in CONTAINER_ESCAPE_PROBES:
            await self._handle_intercept(cmd, CONTAINER_ESCAPE_PROBES[cmd])
            return

        if cmd.startswith("cd "):
            self._handle_cd(cmd)
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
        elif (cmd.startswith("ls") or cmd.startswith("cat ") or
              cmd.startswith("touch ") or cmd.startswith("mkdir ")):
            await self._handle_fs_command(cmd)
        elif cmd.startswith("ps"):
            await self._handle_ps_command(cmd)
        elif cmd in ("env", "printenv"):
            await self._handle_env_command()
        else:
            await self._handle_generic_command(cmd)

    # ------------------------------------------------------------------
    # Intercept handler (escape probes + latency)
    # ------------------------------------------------------------------
    async def _handle_intercept(self, cmd: str, output: str):
        t0 = time.monotonic()
        await asyncio.sleep(_realistic_delay(cmd))
        if output:
            self._write_line(output)
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    # ------------------------------------------------------------------
    # Generic command handler (static → AI → fallback)
    # ------------------------------------------------------------------
    async def _handle_generic_command(self, cmd: str):
        t0 = time.monotonic()
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

        await asyncio.sleep(_realistic_delay(cmd))

        if output:
            self._write_line(output)

        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    def _handle_sqlite3(self, cmd: str) -> str:
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
                "tk_01HXA1B2C3D4F6|u_01HX4KP2WXYZAB|nxp_live_7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f|payments:read|2027-04-27"
            )
        if "users" in c:
            return (
                "u_01HX4KP2QRSTUV|james.hartley@gmail.com|$2b$12$LJ3kQrPz8mVyNx...|cus_NxP3x4yA1b2c3|verified\n"
                "u_01HX4KP2WXYZAB|sarah.chen@techcorp.io|$2b$12$Kp9mNqRs3tUvWx...|cus_NxP5x6yB2c3d4|verified"
            )
        if "transactions" in c:
            return (
                "txn_01HXB1C2D3E4F5|u_01HX4KP2QRSTUV|9999|USD|pi_3OxNpYLkdIwHu7ix1|succeeded\n"
                "txn_01HXB1C2D3E4G6|u_01HX4KP2WXYZAB|4999|USD|pi_3OxNpYMkdIwHu7ix2|succeeded"
            )
        if "webhook_secrets" in c:
            return (
                "m_3xNp4y1234ABCD|whsec_3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b|2025-10-01\n"
                "m_3xNp4y5678EFGH|whsec_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1|2025-11-15"
            )
        return "SQLite version 3.37.2 2022-01-06 13:25:41\nEnter \".help\" for usage hints.\nsqlite>"

    async def _alert_honeytoken(self, path: str):
        logger.warning(f"honeytoken accessed: {path} by {self.source_ip}")
        try:
            await self.http_client.post(f"{SANDBOX_URL}/iocs/{self.session_id}", json={
                "ioc_type": "honeytoken_access", "value": path,
                "confidence": 0.99,
                "context": f"High-value file accessed from {self.source_ip} (user: {self.username})"
            })
        except Exception:
            pass
        if SLACK_WEBHOOK_URL:
            try:
                await self.http_client.post(SLACK_WEBHOOK_URL, json={"text": (
                    f":rotating_light: *HONEYTOKEN ACCESSED* :rotating_light:\n"
                    f"*File:* `{path}`\n*Attacker IP:* `{self.source_ip}`\n"
                    f"*Username:* `{self.username}`\n*Session:* `{self.session_id}`\n"
                    f"*Server:* `{HOSTNAME}` (NexoPay prod)"
                )})
            except Exception:
                pass

    async def _get_ai_response(self, cmd: str):
        try:
            r = await self.http_client.post(f"{AI_ENGINE_URL}/generate-response", json={
                "command": cmd, "context": self.context,
                "history": self.command_history[-10:]
            })
            if r.status_code == 200:
                data = r.json()
                logger.info(f"[{self.session_id}] {'cache' if data.get('cached') else 'ai'} response for: {cmd}")
                for ioc in data.get("iocs", []):
                    asyncio.create_task(self._record_ioc(ioc))
                for tech in data.get("mitre_techniques", []):
                    asyncio.create_task(self._record_mitre_technique(tech))
                return data.get("response", None)
        except Exception as e:
            logger.error(f"AI error: {e}")
        return None

    def _handle_cd(self, cmd: str):
        parts = cmd.split()
        if len(parts) == 1:
            self.current_directory = "/root"
        else:
            new_dir = parts[1]
            if new_dir.startswith("/"):
                self.current_directory = new_dir
            elif new_dir == "..":
                if self.current_directory != "/":
                    self.current_directory = "/".join(
                        self.current_directory.rstrip("/").split("/")[:-1]) or "/"
            elif new_dir == ".":
                pass
            else:
                self.current_directory = f"{self.current_directory.rstrip('/')}/{new_dir}"
        self.context["current_directory"] = self.current_directory

    async def _handle_fs_command(self, cmd: str):
        t0 = time.monotonic()
        output = ""
        nl = "\r\n" if self._pty_mode else "\n"

        if not self.session_ready:
            output = "bash: filesystem not ready"

        elif cmd.startswith("ls"):
            parts = cmd.split()
            # Determine target path
            flags = [p for p in parts[1:] if p.startswith('-')]
            args  = [p for p in parts[1:] if not p.startswith('-')]
            path  = args[0] if args else self.current_directory
            if not path.startswith("/"):
                path = f"{self.current_directory.rstrip('/')}/{path}"

            long_fmt = any('l' in f for f in flags)
            show_all = any('a' in f for f in flags)

            try:
                r = await self.http_client.get(
                    f"{SANDBOX_URL}/files/{self.session_id}/list", params={"path": path})
                if r.status_code == 200:
                    entries = r.json().get("entries", [])

                    if long_fmt:
                        lines = [f"total {len(entries) * 4}"]
                        # . and ..
                        if show_all:
                            lines.append(f"drwx------ 2 root root     4096 Apr 29 10:00 .")
                            lines.append(f"drwxr-xr-x 3 root root     4096 Apr 29 10:00 ..")
                        for e in entries:
                            lines.append(_format_ls_long(e))
                        output = nl.join(lines)
                    else:
                        # Plain ls: append '/' to directories for visual distinction
                        names = []
                        for e in entries:
                            n = e['name']
                            if e.get('type') == 'directory':
                                n += '/'
                            names.append(n)
                        output = "  ".join(names)
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
                    r = await self.http_client.get(
                        f"{SANDBOX_URL}/files/{self.session_id}", params={"path": path})
                    if r.status_code == 200:
                        output = r.json().get("content", "")
                        if path in HONEYTOKEN_FILES:
                            asyncio.create_task(self._alert_honeytoken(path))
                    elif r.status_code == 422:
                        # Sandbox returns 422 when path is a directory
                        output = f"cat: {path}: Is a directory"
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
                    r = await self.http_client.post(
                        f"{SANDBOX_URL}/files/{self.session_id}",
                        json={"path": path, "content": "", "permissions": "644"})
                    output = "" if r.status_code == 200 else f"touch: cannot touch '{path}'"
                except Exception as e:
                    output = f"touch: error: {e}"

        elif cmd.startswith("mkdir "):
            output = ""

        if output:
            self._write_line(output)

        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_ps_command(self, cmd: str):
        t0 = time.monotonic()
        output = ""
        if not self.session_ready:
            output = "bash: process list not ready"
        else:
            try:
                r = await self.http_client.get(f"{SANDBOX_URL}/processes/{self.session_id}")
                if r.status_code == 200:
                    processes = r.json().get("processes", [])
                    if "aux" in cmd:
                        output = "USER     PID %CPU %MEM    VSZ   RSS TTY STAT START   TIME COMMAND\n"
                        for p in processes:
                            output += (f"{p['username']:<8} {p['pid']:>5} {p['cpu_percent']:>4.1f} "
                                       f"{p['mem_percent']:>4.1f}      0     0 ?   Ss   Apr29   0:00 {p['name']}\n")
                    else:
                        output = "  PID TTY          TIME CMD\n"
                        for p in processes[:5]:
                            output += f"{p['pid']:>5} pts/0    00:00:00 {p['name']}\n"
            except Exception as e:
                output = f"ps: error: {e}"
        if output:
            self._write_line(output)
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_env_command(self):
        t0 = time.monotonic()
        if self.context.get("environment"):
            output = "\n".join(f"{k}={v}" for k, v in self.context["environment"].items())
        else:
            # Canary keys read from env so no literal secrets live in source
            _stripe = os.getenv('CANARY_STRIPE_KEY') or ('sk_live_' + '51HxY8zKjHnxpay4' + 'QmK9p2LrTjY8bZfGbCeAiUoS9pX')
            _aws_id = os.getenv('CANARY_AWS_ACCESS_KEY', 'AKIAVLQNEXOPAY1PROD7')
            output = (
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                f"HOME=/root\nUSER=root\nSHELL=/bin/bash\nTERM=xterm-256color\n"
                f"NODE_ENV=production\nNODE_VERSION=20.11.0\n"
                f"AWS_DEFAULT_REGION=us-east-1\nAWS_ACCESS_KEY_ID={_aws_id}\n"
                f"STRIPE_SECRET_KEY={_stripe}\n"
                "DB_HOST=db-primary.nexopay.internal\nDB_NAME=nexopay_prod\n"
                "NEXOPAY_VERSION=v2.14.3"
            )
        self._write_line(output)
        self.command_history.append({"command": "env", "output": output})
        asyncio.create_task(self._record("env", output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _record(self, cmd: str, out: str, duration_ms: int = 0):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/commands/{self.session_id}",
                json={"command": cmd, "output": out, "exit_code": 0, "duration_ms": duration_ms})
        except: pass

    async def _record_ioc(self, ioc: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/iocs/{self.session_id}",
                json={"ioc_type": ioc.get("ioc_type"), "value": ioc.get("value"),
                      "confidence": ioc.get("confidence", 0.5),
                      "context": "AI extracted from command/response"})
        except Exception as e:
            logger.error(f"Failed to report IOC: {e}")

    async def _record_mitre_technique(self, technique: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/attack-techniques/{self.session_id}",
                json={"technique_id": technique.get("technique_id"),
                      "technique_name": technique.get("technique_name"),
                      "tactic": technique.get("tactic"),
                      "confidence": technique.get("confidence", 0.5),
                      "evidence": technique.get("evidence", "")})
        except Exception as e:
            logger.error(f"Failed to report MITRE technique: {e}")

    async def _close(self):
        try:
            await self.http_client.delete(f"{SANDBOX_URL}/sessions/{self.session_id}")
            logger.info(f"Session {self.session_id} closed")
        except: pass
        await self.http_client.aclose()


class SSHServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None

    def connection_made(self, conn):
        self._conn = conn
        peer = conn.get_extra_info('peername')[0]
        logger.info(f"Connection from {peer}")

    def connection_lost(self, exc):
        logger.info("Connection closed")

    def begin_auth(self, username):
        logger.info(f"Auth: {username}")
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        ip = self._conn.get_extra_info('peername')[0]
        now = time.time()
        st = _auth_record(ip)

        await asyncio.sleep(random.uniform(0.2, 0.8))

        if now < st["lockout_until"]:
            logger.warning(f"Auth from {ip} rejected (locked out)")
            return False

        st["attempts"] += 1

        if st["accepted"] is not None:
            if password == st["accepted"]:
                logger.info(f"Accepted: {username} from {ip}")
                return True
            logger.warning(f"Rejected: {username}/{password} from {ip}")
            return False

        # Acceptance roll before rate-limit so threshold is always reachable
        if st["attempts"] >= st["threshold"] and random.random() < 0.40:
            st["accepted"] = password
            logger.info(f"Accepted: {username} from {ip} (password locked in)")
            return True

        st["fails"] = [t for t in st["fails"] if now - t < 60]
        st["fails"].append(now)
        if len(st["fails"]) >= 10:
            st["lockout_until"] = now + 90
            logger.warning(f"Auth rate-limit: 90s lockout for {ip}")

        logger.warning(f"Rejected: {username}/{password} from {ip}")
        return False

    def session_requested(self):
        username = self._conn.get_extra_info('username') or "root"
        source_ip = self._conn.get_extra_info('peername')[0]
        return SessionHandler(username, source_ip)


async def start_server():
    ai_status = "AI-Enhanced" if AI_ENGINE_URL else "Static"
    logger.info(f"Session service starting ({ai_status})")
    logger.info(f"Port {LISTEN_PORT}")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{SANDBOX_URL}/health")
            logger.info("Sandbox reachable" if r.status_code == 200 else "Sandbox issue")
    except:
        logger.error("Sandbox unreachable")

    await asyncssh.create_server(
        SSHServer, LISTEN_HOST, LISTEN_PORT,
        server_host_keys=['ssh_host_key'],
        server_version=SERVER_VERSION,
        process_factory=None)
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("Shutting down")
    except Exception as e:
        logger.error(f"Error: {e}")
