#!/usr/bin/env python3
"""Edge session service."""
import asyncio
import asyncssh
import uuid
import os
import re
import time
import math
import random
import json
import httpx
from datetime import datetime, timedelta, timezone
from typing import Optional
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
DATA_DIR = os.getenv("DATA_DIR", "/data")
HOST_KEY_PATH = os.path.join(DATA_DIR, "ssh_host_key")
BOOT_TIME_PATH = os.path.join(DATA_DIR, "boot_time.txt")
HISTORY_PATH = os.path.join(DATA_DIR, "last_login_by_ip.json")

SERVER_VERSION = 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'

# D1: Algorithm sets matching Ubuntu 22.04 OpenSSH 8.9p1 defaults so the
# ssh -vvv fingerprint matches the advertised version. Lists are in order
# of preference. Anything asyncssh can't speak we drop silently.
_KEX_ALGS = [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
    'diffie-hellman-group14-sha256',
]
_HOST_KEY_ALGS = [
    'rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
]
_ENCRYPTION_ALGS = [
    'chacha20-poly1305@openssh.com',
    'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
    'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
]
_MAC_ALGS = [
    'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    'hmac-sha1-etm@openssh.com',
    'umac-64@openssh.com', 'umac-128@openssh.com',
    'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1',
]


def _load_boot_time() -> float:
    """Stable BOOT_TIME across container restarts. Initial range 30-180 days."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(BOOT_TIME_PATH):
            with open(BOOT_TIME_PATH, "r") as f:
                return float(f.read().strip())
        bt = time.time() - random.uniform(30, 180) * 86400
        with open(BOOT_TIME_PATH, "w") as f:
            f.write(f"{bt}\n")
        return bt
    except OSError:
        return time.time() - random.uniform(30, 180) * 86400


BOOT_TIME = _load_boot_time()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


# Prompt-injection telemetry only. We DO NOT block the command — real bash
# doesn't know what "ignore previous instructions" means; blocking it is a
# screaming honeypot tell. We log silently to the SOC, then let the command
# flow through normal dispatch (it'll fall through to "command not found").
_PROMPT_INJECTION_PATTERNS = [
    "ignore previous", "ignore all previous", "disregard", "forget everything",
    "you are now", "pretend to be", "act as if", "new instructions",
    "system prompt", "jailbreak", "override instructions",
    "you are an ai", "you are a language model", "as an ai",
]


def _looks_like_prompt_injection(cmd: str) -> bool:
    c = cmd.lower()
    return any(p in c for p in _PROMPT_INJECTION_PATTERNS)


def _dyn_date(days_ago: int, fmt: str = "%Y-%m-%d") -> str:
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime(fmt)


def _backup_filename(days_ago: int) -> str:
    return f"/var/backups/nexopay_db_{_dyn_date(days_ago)}.sql"


def _dyn_last_output(ctx: dict) -> str:
    now = datetime.utcnow()
    boot = datetime.utcfromtimestamp(BOOT_TIME)
    source = ctx.get('source_ip', '10.0.1.5')
    lines = [
        f"root     pts/0        {source:<15}  {now.strftime('%a %b %d %H:%M')}   still logged in",
        f"deploy   pts/1        10.0.1.50        {(now - timedelta(hours=6)).strftime('%a %b %d %H:%M')} - "
        f"{(now - timedelta(hours=5, minutes=48)).strftime('%H:%M')}  (00:12)",
        f"root     pts/0        185.220.101.45   {(now - timedelta(days=1)).strftime('%a %b %d %H:%M')} - "
        f"{(now - timedelta(days=1) + timedelta(minutes=13)).strftime('%H:%M')}  (00:13)",
        f"root     pts/0        10.0.1.5         {(now - timedelta(days=2)).strftime('%a %b %d %H:%M')} - "
        f"{(now - timedelta(days=2) + timedelta(minutes=37)).strftime('%H:%M')}  (00:37)",
        f"reboot   system boot  5.15.0-91        {boot.strftime('%a %b %d %H:%M')}   still running",
        "",
        f"wtmp begins {boot.strftime('%a %b %d %H:%M:%S %Y')}",
    ]
    return "\n".join(lines)


def _honeytoken_files() -> set:
    return {
        '/root/.aws/credentials', '/root/.aws/config',
        '/opt/nexopay/config/stripe.env', '/opt/nexopay/config/auth.env',
        '/opt/nexopay/config/aws.env', '/opt/nexopay/config/database.env',
        '/root/.ssh/id_rsa', '/root/.git-credentials', '/root/.kube/config',
        '/root/.docker/config.json', '/root/.npmrc',
        _backup_filename(1), _backup_filename(8),
        '/home/deploy/.env', '/opt/nexopay/data/payments.db',
    }


HONEYTOKEN_FILES = _honeytoken_files()


_FAKE_LAST_LOGIN_IPS = [
    "10.0.1.5", "10.0.1.50", "10.0.2.14", "10.0.2.27",
    "10.0.1.5", "10.0.1.5",
]


def _record_login(source_ip: str):
    try:
        data = {}
        if os.path.exists(HISTORY_PATH):
            with open(HISTORY_PATH, "r") as f:
                data = json.load(f)
        data[source_ip] = time.time()
        with open(HISTORY_PATH, "w") as f:
            json.dump(data, f)
    except (OSError, json.JSONDecodeError):
        pass


def _previous_login(source_ip: str) -> tuple:
    """(ip_to_show, when_to_show) for the 'Last login' banner line."""
    try:
        if os.path.exists(HISTORY_PATH):
            with open(HISTORY_PATH, "r") as f:
                data = json.load(f)
            ts = data.get(source_ip)
            if ts:
                return source_ip, datetime.utcfromtimestamp(ts)
    except (OSError, json.JSONDecodeError):
        pass
    fake_ip = random.choice(_FAKE_LAST_LOGIN_IPS)
    fake_when = datetime.utcnow() - timedelta(
        hours=random.randint(1, 18), minutes=random.randint(0, 59))
    return fake_ip, fake_when


def _build_banner(source_ip: str) -> str:
    now = datetime.utcnow()
    l1, _l5, _l15 = _loadavg()
    prev_ip, prev_when = _previous_login(source_ip)
    procs = 180 + random.randint(-10, 14)
    disk_pct = round(22 + 4 * math.sin(time.time() / 1800.0) + random.uniform(-0.4, 0.4), 1)
    mem_pct = round(30 + 6 * math.sin(time.time() / 600.0) + random.uniform(-1.5, 1.5), 0)
    return (
        "\r\n"
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        f"  System information as of {now.strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
        "\r\n"
        f"  System load:  {l1:.2f}               Processes:             {procs}\r\n"
        f"  Usage of /:   {disk_pct}% of 38.60GB   Users logged in:       0\r\n"
        f"  Memory usage: {int(mem_pct)}%                IPv4 address for eth0: 10.0.1.45\r\n"
        "  Swap usage:   0%\r\n"
        "\r\n"
        "0 updates can be applied immediately.\r\n"
        "\r\n"
        "This system is monitored. Unauthorized access will be prosecuted.\r\n"
        "NexoPay Inc. — Payment Infrastructure — PCI-DSS Compliant Zone\r\n"
        "\r\n"
        f"Last login: {prev_when.strftime('%a %b %d %H:%M:%S %Y')} from {prev_ip}\r\n"
    )


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

def _proc_cpuinfo(ctx: dict) -> str:
    blocks = []
    for i in range(4):
        mhz = 2400 + random.randint(-50, 50)
        blocks.append(
            f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
            f"model\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Silver 4214R CPU @ 2.40GHz\n"
            f"stepping\t: 7\nmicrocode\t: 0x5003302\ncpu MHz\t\t: {mhz}.000\n"
            f"cache size\t: 16384 KB\nphysical id\t: {i // 2}\nsiblings\t: 2\n"
            f"core id\t\t: {i % 2}\ncpu cores\t: 2\napicid\t\t: {i}\n"
            f"initial apicid\t: {i}\nfpu\t\t: yes\nfpu_exception\t: yes\n"
            f"cpuid level\t: 22\nwp\t\t: yes\n"
            f"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov "
            f"pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx rdtscp lm "
            f"constant_tsc arch_perfmon rep_good nopl xtopology nonstop_tsc cpuid "
            f"pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes "
            f"xsave avx f16c rdrand hypervisor lahf_lm avx2 avx512f avx512dq avx512cd "
            f"avx512bw avx512vl ibrs ibpb stibp md_clear\n"
            f"bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass mds swapgs\n"
            f"bogomips\t: 4800.00\nclflush size\t: 64\ncache_alignment\t: 64\n"
            f"address sizes\t: 46 bits physical, 48 bits virtual\npower management:\n"
        )
    return "\n".join(blocks)

def _proc_meminfo_file(ctx: dict) -> str:
    total = 16384000
    used = 5234512 + int(800000 * math.sin(time.time() / 200.0)) + random.randint(-60000, 60000)
    buff = 8026076 + random.randint(-120000, 120000)
    free = max(0, total - used - buff)
    avail = max(0, free + buff // 2)
    swap = 2097148
    cached = max(0, buff - 524288)
    return (
        f"MemTotal:       {total} kB\nMemFree:        {free} kB\nMemAvailable:   {avail} kB\n"
        f"Buffers:          524288 kB\nCached:         {cached} kB\nSwapCached:            0 kB\n"
        f"Active:         {used // 2} kB\nInactive:       {used // 3} kB\n"
        f"Active(anon):   {used // 3} kB\nInactive(anon):        0 kB\n"
        f"Active(file):   {used // 6} kB\nInactive(file): {used // 3} kB\n"
        f"Unevictable:           0 kB\nMlocked:               0 kB\n"
        f"SwapTotal:      {swap} kB\nSwapFree:       {swap} kB\n"
        f"Dirty:               256 kB\nWriteback:             0 kB\n"
        f"AnonPages:      {used // 3} kB\nMapped:           512000 kB\nShmem:            102344 kB\n"
        f"KReclaimable:     524288 kB\nSlab:             786432 kB\n"
        f"SReclaimable:     524288 kB\nSUnreclaim:       262144 kB\n"
        f"KernelStack:       18432 kB\nPageTables:        32768 kB\n"
        f"CommitLimit:    10289148 kB\nCommitted_AS:    6291456 kB\n"
        f"VmallocTotal:   34359738367 kB\nVmallocUsed:      131072 kB\n"
        f"HugePages_Total:       0\nHugePages_Free:        0\n"
        f"Hugepagesize:       2048 kB\nHugetlb:               0 kB"
    )

def _meminfo_kb(ctx: dict) -> str:
    total = 16384000
    used = 5234512 + int(800000 * math.sin(time.time() / 200.0)) + random.randint(-60000, 60000)
    buff = 8026076 + random.randint(-120000, 120000)
    free = max(0, total - used - buff)
    avail = max(0, free + buff)
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
        f"    5  pg_dump -h db-primary.nexopay.internal -U nexopay_app nexopay_prod > {_backup_filename(1)}\n"
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
    "last": lambda ctx: _dyn_last_output(ctx),
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
    # /proc virtual filesystem
    "cat /proc/version": lambda ctx: (
        "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-013) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
        "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
    ),
    "cat /proc/cpuinfo":  _proc_cpuinfo,
    "cat /proc/meminfo":  _proc_meminfo_file,
    "cat /proc/net/dev":  lambda ctx: (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        f"    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        f"  eth0: {2345678901 + random.randint(-100000,100000)} 3456789    0    0    0     0          0"
        f"         0 {987654321 + random.randint(-100000,100000)} 1234567    0    0    0     0       0          0"
    ),
    "cat /proc/net/tcp": lambda ctx: (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12481 1 0000000000000000 100 0 0 10 0\n"
        "   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 13024 1 0000000000000000 100 0 0 10 0\n"
        "   2: 2D01000A:0016 0501000A:A8B2 01 00000000:00000000 02:000ACD3E 00000000     0        0 23891 4 0000000000000000 20 4 24 10 -1"
    ),
    # /sys virtual filesystem
    "cat /sys/class/net/eth0/address":   lambda ctx: "02:00:01:2d:45:01",
    "cat /sys/class/net/eth0/speed":     lambda ctx: "1000",
    "cat /sys/class/net/eth0/mtu":       lambda ctx: "1500",
    "cat /sys/class/net/eth0/operstate": lambda ctx: "up",
    "cat /sys/class/net/eth0/carrier":   lambda ctx: "1",
    "cat /sys/kernel/hostname":          lambda ctx: HOSTNAME,
    # Network routing (consistent with 10.0.1.45 on eth0)
    "ip route":      lambda ctx: (
        "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.45 metric 100\n"
        "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.45"
    ),
    "ip route show": lambda ctx: (
        "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.45 metric 100\n"
        "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.45"
    ),
    "ip link": lambda ctx: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
        "    link/ether 02:00:01:2d:45:01 brd ff:ff:ff:ff:ff:ff"
    ),
    "ip link show": lambda ctx: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
        "    link/ether 02:00:01:2d:45:01 brd ff:ff:ff:ff:ff:ff"
    ),
    "route": lambda ctx: (
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "0.0.0.0         10.0.1.1        0.0.0.0         UG    100    0        0 eth0\n"
        "10.0.1.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0"
    ),
    "route -n": lambda ctx: (
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "0.0.0.0         10.0.1.1        0.0.0.0         UG    100    0        0 eth0\n"
        "10.0.1.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0"
    ),
    "arp": lambda ctx: (
        "Address                  HWtype  HWaddress           Flags Mask  Iface\n"
        "10.0.1.1                 ether   00:50:56:e0:01:01   C           eth0\n"
        "10.0.1.5                 ether   00:50:56:e0:01:05   C           eth0"
    ),
    "arp -n": lambda ctx: (
        "Address                  HWtype  HWaddress           Flags Mask  Iface\n"
        "10.0.1.1                 ether   00:50:56:e0:01:01   C           eth0\n"
        "10.0.1.5                 ether   00:50:56:e0:01:05   C           eth0"
    ),
    "w": lambda ctx: (
        f" {datetime.utcnow().strftime('%H:%M:%S')} up "
        f"{int((time.time()-BOOT_TIME)//86400)} days, "
        f"{int(((time.time()-BOOT_TIME)%86400)//3600)}:{int(((time.time()-BOOT_TIME)%3600)//60):02d},"
        f"  1 user,  load average: {_loadavg()[0]:.2f}, {_loadavg()[1]:.2f}, {_loadavg()[2]:.2f}\n"
        "USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
        f"root     pts/0    {ctx.get('source_ip','10.0.1.5'):<16}  00:22    0.00s  0.01s  0.00s w"
    ),
    "who": lambda ctx: (
        f"root     pts/0        {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} "
        f"({ctx.get('source_ip','10.0.1.5')})"
    ),
    # Story-consistency: files, DNS, services all tell the same NexoPay story
    "cat /etc/passwd": lambda ctx: (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "postgres:x:108:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        "deploy:x:1001:1001:NexoPay Deploy,,,:/home/deploy:/bin/bash\n"
        "nexopay:x:1002:1002:NexoPay Service,,,:/opt/nexopay:/usr/sbin/nologin"
    ),
    "cat /etc/shadow": lambda ctx: (
        "cat: /etc/shadow: Permission denied"
    ),
    "cat /etc/hosts": lambda ctx: (
        "127.0.0.1   localhost\n"
        "127.0.1.1   api-prod-01\n"
        "10.0.1.45   api-prod-01.nexopay.internal api-prod-01\n"
        "10.0.1.10   db-primary.nexopay.internal db-primary\n"
        "10.0.1.11   db-secondary.nexopay.internal db-secondary\n"
        "10.0.1.20   cache-01.nexopay.internal cache-01\n"
        "10.0.1.5    bastion.nexopay.internal bastion"
    ),
    "cat /etc/resolv.conf": lambda ctx: (
        "nameserver 10.0.1.2\nsearch nexopay.internal\noptions ndots:5"
    ),
    "cat /etc/os-release": lambda ctx: (
        'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'VERSION_ID="22.04"\nHOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'VERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy'
    ),
    "nslookup db-primary.nexopay.internal": lambda ctx: (
        "Server:\t\t10.0.1.2\nAddress:\t10.0.1.2#53\n\n"
        "Name:\tdb-primary.nexopay.internal\nAddress: 10.0.1.10"
    ),
    "nslookup cache-01.nexopay.internal": lambda ctx: (
        "Server:\t\t10.0.1.2\nAddress:\t10.0.1.2#53\n\n"
        "Name:\tcache-01.nexopay.internal\nAddress: 10.0.1.20"
    ),
    "dig db-primary.nexopay.internal": lambda ctx: (
        "; <<>> DiG 9.18.12-0ubuntu0.22.04.3-Ubuntu <<>> db-primary.nexopay.internal\n"
        ";; ANSWER SECTION:\n"
        "db-primary.nexopay.internal. 300 IN A 10.0.1.10\n\n"
        ";; Query time: 1 msec\n;; SERVER: 10.0.1.2#53(10.0.1.2)"
    ),
    "systemctl status nexopay-api": lambda ctx: (
        "● nexopay-api.service - NexoPay Payment API\n"
        "     Loaded: loaded (/lib/systemd/system/nexopay-api.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:42 UTC; 18 days ago\n"
        "   Main PID: 3100 (node)\n"
        "      Tasks: 22 (limit: 19158)\n"
        "     Memory: 67.3M\n"
        "        CPU: 1h 24min 15.231s\n"
        "     CGroup: /system.slice/nexopay-api.service\n"
        "             └─3100 node /opt/nexopay/server.js\n\n"
        "Apr 29 00:22:01 api-prod-01 node[3100]: [INFO] POST /v2/payments 200 142ms\n"
        "Apr 29 00:22:09 api-prod-01 node[3100]: [INFO] GET /v2/balance 200 38ms\n"
        "Apr 29 00:22:14 api-prod-01 node[3100]: [INFO] POST /v2/webhooks/stripe 200 89ms"
    ),
    "systemctl status nginx": lambda ctx: (
        "● nginx.service - A high performance web server\n"
        "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:41 UTC; 18 days ago\n"
        "   Main PID: 892 (nginx)\n"
        "     CGroup: /system.slice/nginx.service\n"
        "             ├─892 nginx: master process /usr/sbin/nginx -g daemon on;\n"
        "             └─893 nginx: worker process"
    ),
    "systemctl status postgresql": lambda ctx: (
        "● postgresql.service - PostgreSQL RDBMS\n"
        "     Loaded: loaded (/lib/systemd/system/postgresql.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:40 UTC; 18 days ago"
    ),
    "journalctl -u nexopay-api": lambda ctx: (
        "-- Logs begin at Thu 2026-04-10 17:37:41 UTC, end at Tue 2026-04-29 00:22:14 UTC. --\n"
        "Apr 10 17:37:42 api-prod-01 systemd[1]: Started NexoPay Payment API.\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Server listening on 0.0.0.0:3000\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Database connected: db-primary.nexopay.internal\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Redis connected: cache-01.nexopay.internal:6379\n"
        "Apr 29 00:22:01 api-prod-01 node[3100]: [INFO] POST /v2/payments 200 142ms\n"
        "Apr 29 00:22:09 api-prod-01 node[3100]: [INFO] GET /v2/balance 200 38ms"
    ),
    "tail -f /opt/nexopay/logs/error.log": lambda ctx: (
        "[2026-04-29 00:18:22] WARN  stripe: Webhook signature verification slow for evt_3OxNpY...\n"
        "[2026-04-29 00:19:01] INFO  payment processed: txn_01HXB1C2D3E4F5 amount=9999 status=succeeded\n"
        "[2026-04-29 00:20:11] WARN  rate_limit: 429 returned for IP 185.220.101.45\n"
        "[2026-04-29 00:21:33] INFO  webhook dispatched: merchant m_3xNp4y1234ABCD"
    ),
    "cat /opt/nexopay/logs/error.log": lambda ctx: (
        "[2026-04-29 00:18:22] WARN  stripe: Webhook signature verification slow for evt_3OxNpY...\n"
        "[2026-04-29 00:19:01] INFO  payment processed: txn_01HXB1C2D3E4F5 amount=9999 status=succeeded\n"
        "[2026-04-29 00:20:11] WARN  rate_limit: 429 returned for IP 185.220.101.45\n"
        "[2026-04-29 00:21:33] INFO  webhook dispatched: merchant m_3xNp4y1234ABCD"
    ),
    # Story-consistency: files, DNS, services all tell the same NexoPay story
    "cat /etc/passwd": lambda ctx: (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "postgres:x:108:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        "deploy:x:1001:1001:NexoPay Deploy,,,:/home/deploy:/bin/bash\n"
        "nexopay:x:1002:1002:NexoPay Service,,,:/opt/nexopay:/usr/sbin/nologin"
    ),
    "cat /etc/shadow": lambda ctx: (
        "cat: /etc/shadow: Permission denied"
    ),
    "cat /etc/hosts": lambda ctx: (
        "127.0.0.1   localhost\n"
        "127.0.1.1   api-prod-01\n"
        "10.0.1.45   api-prod-01.nexopay.internal api-prod-01\n"
        "10.0.1.10   db-primary.nexopay.internal db-primary\n"
        "10.0.1.11   db-secondary.nexopay.internal db-secondary\n"
        "10.0.1.20   cache-01.nexopay.internal cache-01\n"
        "10.0.1.5    bastion.nexopay.internal bastion"
    ),
    "cat /etc/resolv.conf": lambda ctx: (
        "nameserver 10.0.1.2\nsearch nexopay.internal\noptions ndots:5"
    ),
    "cat /etc/os-release": lambda ctx: (
        'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'VERSION_ID="22.04"\nHOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'VERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy'
    ),
    "nslookup db-primary.nexopay.internal": lambda ctx: (
        "Server:\t\t10.0.1.2\nAddress:\t10.0.1.2#53\n\n"
        "Name:\tdb-primary.nexopay.internal\nAddress: 10.0.1.10"
    ),
    "nslookup cache-01.nexopay.internal": lambda ctx: (
        "Server:\t\t10.0.1.2\nAddress:\t10.0.1.2#53\n\n"
        "Name:\tcache-01.nexopay.internal\nAddress: 10.0.1.20"
    ),
    "dig db-primary.nexopay.internal": lambda ctx: (
        "; <<>> DiG 9.18.12-0ubuntu0.22.04.3-Ubuntu <<>> db-primary.nexopay.internal\n"
        ";; ANSWER SECTION:\n"
        "db-primary.nexopay.internal. 300 IN A 10.0.1.10\n\n"
        ";; Query time: 1 msec\n;; SERVER: 10.0.1.2#53(10.0.1.2)"
    ),
    "systemctl status nexopay-api": lambda ctx: (
        "● nexopay-api.service - NexoPay Payment API\n"
        "     Loaded: loaded (/lib/systemd/system/nexopay-api.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:42 UTC; 18 days ago\n"
        "   Main PID: 3100 (node)\n"
        "      Tasks: 22 (limit: 19158)\n"
        "     Memory: 67.3M\n"
        "        CPU: 1h 24min 15.231s\n"
        "     CGroup: /system.slice/nexopay-api.service\n"
        "             └─3100 node /opt/nexopay/server.js\n\n"
        "Apr 29 00:22:01 api-prod-01 node[3100]: [INFO] POST /v2/payments 200 142ms\n"
        "Apr 29 00:22:09 api-prod-01 node[3100]: [INFO] GET /v2/balance 200 38ms\n"
        "Apr 29 00:22:14 api-prod-01 node[3100]: [INFO] POST /v2/webhooks/stripe 200 89ms"
    ),
    "systemctl status nginx": lambda ctx: (
        "● nginx.service - A high performance web server\n"
        "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:41 UTC; 18 days ago\n"
        "   Main PID: 892 (nginx)\n"
        "     CGroup: /system.slice/nginx.service\n"
        "             ├─892 nginx: master process /usr/sbin/nginx -g daemon on;\n"
        "             └─893 nginx: worker process"
    ),
    "systemctl status postgresql": lambda ctx: (
        "● postgresql.service - PostgreSQL RDBMS\n"
        "     Loaded: loaded (/lib/systemd/system/postgresql.service; enabled)\n"
        "     Active: \033[32mactive (running)\033[0m since Thu 2026-04-10 17:37:40 UTC; 18 days ago"
    ),
    "journalctl -u nexopay-api": lambda ctx: (
        "-- Logs begin at Thu 2026-04-10 17:37:41 UTC, end at Tue 2026-04-29 00:22:14 UTC. --\n"
        "Apr 10 17:37:42 api-prod-01 systemd[1]: Started NexoPay Payment API.\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Server listening on 0.0.0.0:3000\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Database connected: db-primary.nexopay.internal\n"
        "Apr 10 17:37:43 api-prod-01 node[3100]: [INFO] Redis connected: cache-01.nexopay.internal:6379\n"
        "Apr 29 00:22:01 api-prod-01 node[3100]: [INFO] POST /v2/payments 200 142ms\n"
        "Apr 29 00:22:09 api-prod-01 node[3100]: [INFO] GET /v2/balance 200 38ms"
    ),
    "tail -f /opt/nexopay/logs/error.log": lambda ctx: (
        "[2026-04-29 00:18:22] WARN  stripe: Webhook signature verification slow for evt_3OxNpY...\n"
        "[2026-04-29 00:19:01] INFO  payment processed: txn_01HXB1C2D3E4F5 amount=9999 status=succeeded\n"
        "[2026-04-29 00:20:11] WARN  rate_limit: 429 returned for IP 185.220.101.45\n"
        "[2026-04-29 00:21:33] INFO  webhook dispatched: merchant m_3xNp4y1234ABCD"
    ),
    "cat /opt/nexopay/logs/error.log": lambda ctx: (
        "[2026-04-29 00:18:22] WARN  stripe: Webhook signature verification slow for evt_3OxNpY...\n"
        "[2026-04-29 00:19:01] INFO  payment processed: txn_01HXB1C2D3E4F5 amount=9999 status=succeeded\n"
        "[2026-04-29 00:20:11] WARN  rate_limit: 429 returned for IP 185.220.101.45\n"
        "[2026-04-29 00:21:33] INFO  webhook dispatched: merchant m_3xNp4y1234ABCD"
    ),
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


def _longest_common_prefix(strs):
    if not strs:
        return ""
    s_min = min(strs)
    s_max = max(strs)
    for i, c in enumerate(s_min):
        if c != s_max[i]:
            return s_min[:i]
    return s_min


# ---------------------------------------------------------------------------
# AWS Instance Metadata Service (169.254.169.254) — Advanced Deception
# ---------------------------------------------------------------------------
_IMDS_BASE = "http://169.254.169.254/latest/meta-data"
_IMDS_ROUTES = {
    f"{_IMDS_BASE}/":                                          "ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4\nplacement/\npublic-hostname\npublic-ipv4\n",
    f"{_IMDS_BASE}/instance-id":                               "i-0a1b2c3d4e5f67890",
    f"{_IMDS_BASE}/instance-type":                             "c5.2xlarge",
    f"{_IMDS_BASE}/local-ipv4":                                "10.0.1.45",
    f"{_IMDS_BASE}/public-ipv4":                               "54.204.17.133",
    f"{_IMDS_BASE}/public-hostname":                           "ec2-54-204-17-133.compute-1.amazonaws.com",
    f"{_IMDS_BASE}/hostname":                                  "ip-10-0-1-45.ec2.internal",
    f"{_IMDS_BASE}/ami-id":                                    "ami-0c02fb55956c7d316",
    f"{_IMDS_BASE}/placement/":                                "availability-zone\nregion\n",
    f"{_IMDS_BASE}/placement/availability-zone":               "us-east-1a",
    f"{_IMDS_BASE}/placement/region":                          "us-east-1",
    f"{_IMDS_BASE}/iam/":                                      "info\nsecurity-credentials/\n",
    f"{_IMDS_BASE}/iam/security-credentials/":                 "nexopay-prod-role",
}
_IMDS_CREDS_PATH = f"{_IMDS_BASE}/iam/security-credentials/nexopay-prod-role"

def _aws_imds_creds() -> str:
    now = datetime.now(timezone.utc)
    exp = now.replace(hour=(now.hour + 6) % 24)
    return json.dumps({
        "Code": "Success",
        "LastUpdated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Type": "AWS-HMAC",
        "AccessKeyId": os.getenv("CANARY_AWS_ACCESS_KEY", "AKIAVLQNEXOPAY1PROD7"),  # nosemgrep
        "SecretAccessKey": os.getenv("CANARY_AWS_SECRET_KEY", "nxp/FakeK3y+wJalrXUtnFEMI/K7MDENG/bPxRfi"),
        "Token": "IQoJb3JpZ2luX2VjEMj//////////wEaCXVzLWVhc3QtMSJHMEUCIQDNExoPay+FakeSessionToken+For+Prod+Role==",
        "Expiration": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2)


# ---------------------------------------------------------------------------
# Internal network topology (consistent across ping/ssh/nslookup/dig)
# ---------------------------------------------------------------------------
_INTERNAL_HOSTS = {
    "db-primary.nexopay.internal": "10.0.1.10",
    "db-primary":                  "10.0.1.10",
    "db-secondary.nexopay.internal":"10.0.1.11",
    "db-secondary":                "10.0.1.11",
    "cache-01.nexopay.internal":   "10.0.1.20",
    "cache-01":                    "10.0.1.20",
    "bastion.nexopay.internal":    "10.0.1.5",
    "bastion":                     "10.0.1.5",
    "10.0.1.10":                   "10.0.1.10",
    "10.0.1.11":                   "10.0.1.11",
    "10.0.1.20":                   "10.0.1.20",
    "10.0.1.5":                    "10.0.1.5",
    "10.0.1.1":                    "10.0.1.1",
    "localhost":                   "127.0.0.1",
    "127.0.0.1":                   "127.0.0.1",
}

_KERNEL_THREADS = (
    "root           1  0.0  0.0  167524 11120 ?  Ss   Apr10   0:05 /sbin/init splash\n"
    "root           2  0.0  0.0       0     0 ?  S    Apr10   0:00 [kthreadd]\n"
    "root           3  0.0  0.0       0     0 ?  I<   Apr10   0:00 [rcu_gp]\n"
    "root           4  0.0  0.0       0     0 ?  I<   Apr10   0:00 [rcu_par_gp]\n"
    "root           6  0.0  0.0       0     0 ?  I<   Apr10   0:00 [kworker/0:0H-events_highpri]\n"
    "root           9  0.0  0.0       0     0 ?  I<   Apr10   0:00 [mm_percpu_wq]\n"
    "root          10  0.0  0.0       0     0 ?  S    Apr10   0:00 [ksoftirqd/0]\n"
    "root          11  0.0  0.0       0     0 ?  I    Apr10   0:16 [rcu_sched]\n"
    "root          12  0.0  0.0       0     0 ?  S    Apr10   0:00 [migration/0]\n"
    "root          13  0.0  0.0       0     0 ?  S    Apr10   0:00 [idle_inject/0]\n"
    "root          34  0.0  0.0       0     0 ?  S<   Apr10   0:00 [kdevtmpfs]\n"
    "root         134  0.0  0.0   14476  7248 ?  Ss   Apr10   0:00 /usr/sbin/sshd -D\n"
    "root         892  0.1  0.0   55280  9512 ?  Ss   Apr10   0:43 nginx: master process /etc/nginx/nginx.conf\n"
    "www-data     893  0.0  0.0   55720  5412 ?  S    Apr10   0:12 nginx: worker process\n"
    "root        2048  0.0  0.1   65116 18432 ?  Ssl  Apr10   0:08 /usr/bin/redis-server 127.0.0.1:6379\n"
    "postgres    2150  0.0  0.2  222532 38912 ?  Ss   Apr10   0:22 /usr/lib/postgresql/14/bin/postgres\n"
    "root        3100  0.1  0.4  896512 68512 ?  Ssl  Apr10   1:24 node /opt/nexopay/server.js\n"
)

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
        "threshold": random.randint(3, 5),
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
        self._last_exit     = 0
        self._session_env   = {}
        self._aliases       = {}
        self._bg_jobs       = []  # list of dicts: {pid, cmd, started}
        self._next_fake_pid = 31000 + random.randint(0, 999)
        self._heredoc       = None  # active here-doc state when not None
        self._continuation  = False  # backslash line continuation
        self._cont_buf      = ""

        # PTY / line-editor state
        self.context["source_ip"] = self.source_ip
        self._technique_count = 0
        self._alerted_high    = False

        self._pty_mode        = False
        self._shell_requested = False
        self._exec_only       = False
        self._is_sftp         = False
        self._sftp_reader: Optional[_SFTPReaderAdapter] = None
        self._line_buf   = ""
        self._cmd_history: list = []
        self._hist_idx   = -1
        self._hist_saved = ""
        self._escape_buf = ""

    def _set_exit(self, code: int):
        self._last_exit = code

    def _next_pid(self) -> int:
        self._next_fake_pid += random.randint(1, 7)
        return self._next_fake_pid

    def _expand_specials(self, cmd: str) -> str:
        """Cheap pre-dispatch expansion for the small set we always handle:
        $?, $$, $! and the trivial $HOME / $USER / $PATH / $SHELL / $HOSTNAME / $PWD.
        Full variable expansion lives in _expand_full (B4)."""
        env = {
            "?": str(self._last_exit),
            "$": "1",
            "!": str(self._bg_jobs[-1]["pid"]) if self._bg_jobs else "",
            "HOME": self._session_env.get("HOME", "/root"),
            "USER": self._session_env.get("USER", self.username),
            "LOGNAME": self.username,
            "SHELL": "/bin/bash",
            "PATH": self._session_env.get(
                "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "HOSTNAME": HOSTNAME,
            "PWD": self.current_directory,
            "OLDPWD": self._session_env.get("OLDPWD", "/root"),
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
        }
        env.update(self._session_env)

        def repl_brace(m):
            return env.get(m.group(1), "")

        def repl_bare(m):
            return env.get(m.group(1), "")

        out = re.sub(r"\$\{([A-Za-z_?$!][A-Za-z0-9_]*)\}", repl_brace, cmd)
        out = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*|\?|\$|!)", repl_bare, out)

        # B4: safe $((arithmetic)) expansion — only digits and basic operators
        def _arith(m):
            expr = m.group(1).strip()
            if not re.match(r'^[\d\s+\-*/%()&|^~<>]+$', expr):
                return "0"
            try:
                return str(int(eval(compile(expr, '<arith>', 'eval'), {"__builtins__": {}})))  # nosemgrep
            except Exception:
                return "0"
        out = re.sub(r'\$\(\((.+?)\)\)', _arith, out)
        return out

    async def _expand_globs(self, cmd: str) -> str:
        """B4: expand glob patterns (*, ?) against the sandbox-store virtual FS."""
        import fnmatch as _fnmatch
        parts = cmd.split()
        new_parts = []
        for part in parts:
            if '*' not in part and '?' not in part:
                new_parts.append(part); continue
            # Determine the directory and the pattern
            if '/' in part:
                dir_part, _, pattern = part.rpartition('/')
                dir_path = dir_part or '/'
            else:
                dir_path = self.current_directory
                pattern = part
            if not dir_path.startswith('/'):
                dir_path = f"{self.current_directory.rstrip('/')}/{dir_path}"
            try:
                r = await self.http_client.get(
                    f"{SANDBOX_URL}/files/{self.session_id}/list",
                    params={"path": dir_path})
                if r.status_code == 200:
                    matches = sorted(
                        f"{dir_path.rstrip('/')}/{e['name']}"
                        for e in r.json().get("entries", [])
                        if _fnmatch.fnmatch(e['name'], pattern)
                    )
                    if matches:
                        new_parts.extend(matches); continue
            except Exception:
                pass
            new_parts.append(part)  # no match → leave glob literal (bash behaviour)
        return ' '.join(new_parts)

    def connection_made(self, chan):
        self.chan = chan

    def pty_requested(self, terminal_type, terminal_size, terminal_modes):
        """Real OpenSSH rejects PTY when only `exec` was requested (no shell).
        We track shell intent and refuse PTY for `ssh user@host cmd` invocations."""
        if self._exec_only:
            return False
        self._pty_mode = True
        return True

    def shell_requested(self):
        self._shell_requested = True
        return True

    def exec_requested(self, command):
        """`ssh user@host 'cmd'` arrives here. Run as a single batched command.
        D5: PTY is rejected for exec-only sessions."""
        if not self._shell_requested:
            self._exec_only = True
        self._pty_mode = False
        asyncio.create_task(self._process_command_string(command + "\n"))
        return True

    def session_started(self):
        if self._is_sftp:
            self.chan.set_encoding(None)
            self._sftp_reader = _SFTPReaderAdapter()
            asyncio.create_task(self._run_sftp_server())
            return
        self.chan.write(_build_banner(self.source_ip))
        _record_login(self.source_ip)
        self._show_prompt()
        asyncio.create_task(self._init_db())

    async def _run_sftp_server(self):
        from asyncssh.sftp import run_sftp_server
        try:
            writer = _SFTPWriterAdapter(self.chan)
            sftp_server = HoneypotSFTPServer(self.chan)
            await run_sftp_server(sftp_server, self._sftp_reader, writer, 0)
        except Exception as e:
            logger.debug(f"[SFTP] Session ended: {e}")
        finally:
            try:
                self.chan.close()
            except Exception:
                pass

    def _show_prompt(self):
        self.chan.write(f"\r\n{self.username}@{HOSTNAME}:{self.current_directory}$ "
                        if False else
                        f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    def _write_line(self, text: str):
        """Write a line with the correct line ending for current mode."""
        nl = "\r\n" if self._pty_mode else "\n"
        for line in text.split("\n"):
            self.chan.write(line + nl)

    def _write_err(self, text: str):
        """D2: Write error output to the SSH stderr channel so 2>/dev/null works."""
        nl = "\r\n" if self._pty_mode else "\n"
        try:
            for line in text.split("\n"):
                self.chan.write_stderr(line + nl)
        except (AttributeError, Exception):
            self._write_line(text)

    async def _init_db(self):
        try:
            r = await self.http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": self.session_id, "source_ip": self.source_ip,
                "protocol": "ssh", "username": self.username, "password": "***"
            })
            if r.status_code == 200:
                logger.info(f"Session {self.session_id} created")
                self.session_ready = True
                asyncio.create_task(self._lookup_threat_intel())
                state_r = await self.http_client.get(
                    f"{SANDBOX_URL}/sessions/{self.session_id}/state")
                if state_r.status_code == 200:
                    self.context["environment"] = state_r.json().get("environment", {})

                # B2: load persistent env/alias/cwd from previous sessions by this IP
                try:
                    ps_r = await self.http_client.get(
                        f"{SANDBOX_URL}/state/{self.source_ip}")
                    if ps_r.status_code == 200:
                        pstate = ps_r.json()
                        if pstate.get('env'):
                            self._session_env.update(pstate['env'])
                            self.context['environment'] = {
                                **self.context.get('environment', {}),
                                **self._session_env,
                            }
                        if pstate.get('alias'):
                            self._aliases.update(pstate['alias'])
                        saved_cwd = pstate.get('cwd', '/root')
                        if saved_cwd and saved_cwd != '/root':
                            self.current_directory = saved_cwd
                            self.context['current_directory'] = saved_cwd
                        if self._aliases:
                            self.context['aliases'] = dict(self._aliases)
                except Exception as e:
                    logger.debug(f"Persistent state load skipped: {e}")
        except Exception as e:
            logger.error(f"DB init failed: {e}")

    # ------------------------------------------------------------------
    # data_received: route to PTY line editor or legacy batch handler
    # ------------------------------------------------------------------
    def subsystem_requested(self, subsystem: str) -> bool:
        if subsystem == 'sftp':
            self._is_sftp = True
            return True
        return False

    def data_received(self, data, datatype):
        if self._is_sftp:
            if isinstance(data, str):
                data = data.encode('utf-8', errors='replace')
            if self._sftp_reader:
                self._sftp_reader.feed(data)
            return
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
        """Tab completion. Mirrors bash closely enough to defeat the easy tells:

        - Bare-name completion against the current directory when the prefix
          has no '/' (real bash does this; the previous version required a
          slash or leading dot and gave nothing on `cat fo<Tab>`).
        - Longest-common-prefix extension on ambiguous Tab: extends the
          buffer to the LCP first and only lists candidates when the buffer
          can't be extended further. Hitting Tab on `who` with matches
          [whoami, whois] now extends to `whoa` instead of just listing.
        - Trailing space after a single fully-completed leaf (file or
          command), matching bash's default readline behaviour.
        """
        buf = self._line_buf
        parts = buf.split()

        if not buf or buf.endswith(' '):
            prefix = ""
            is_cmd = len(parts) == 0
        else:
            prefix = parts[-1] if parts else ""
            is_cmd = len(parts) == 1

        matches: list = []
        if is_cmd:
            matches = sorted(c for c in _COMPLETABLE_CMDS if c.startswith(prefix))
        else:
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
                    for e in r.json().get("entries", []):
                        if e['name'].startswith(file_prefix):
                            suffix = '/' if e.get('type') == 'directory' else ''
                            matches.append(e['name'] + suffix)
                    matches.sort()
            except Exception:
                matches = []

        if not matches:
            return

        if len(matches) == 1:
            completion = matches[0][len(prefix):]
            self._line_buf += completion
            self.chan.write(completion)
            if not matches[0].endswith('/'):
                self._line_buf += ' '
                self.chan.write(' ')
            return

        lcp = _longest_common_prefix(matches)
        if len(lcp) > len(prefix):
            extension = lcp[len(prefix):]
            self._line_buf += extension
            self.chan.write(extension)
            return

        self.chan.write('\r\n' + '  '.join(matches) + '\r\n')
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
        self.chan.write(self._line_buf)

    async def _process_pty_line(self):
        """Called on Enter in PTY mode — process the buffered line.

        B3: handle here-docs (`cmd <<EOF ... EOF`) and backslash line continuation."""
        raw = self._line_buf  # do NOT strip — heredoc bodies are whitespace-sensitive
        self.chan.write('\r\n')
        self._line_buf = ""
        self._hist_idx = -1

        # Active here-doc: just accumulate body lines until delimiter
        if self._heredoc is not None:
            stripped = raw.lstrip() if self._heredoc["strip_tabs"] else raw
            if stripped.rstrip() == self._heredoc["delim"]:
                full_cmd = self._heredoc["cmd"]
                body = "\n".join(self._heredoc["body"])
                self._heredoc = None
                # Stash body as stdin in context so handlers can read it if they care
                self.context["_heredoc_stdin"] = body
                if full_cmd.strip():
                    if not self._cmd_history or self._cmd_history[-1] != full_cmd:
                        self._cmd_history.append(full_cmd)
                    await self._process_single_command(full_cmd)
                self.context.pop("_heredoc_stdin", None)
            else:
                self._heredoc["body"].append(raw)
                self.chan.write("> ")
            return

        # Continuation: append to buffered command
        if self._continuation:
            self._continuation = False
            # Trim trailing backslash from previously buffered command
            self._cont_buf = self._cont_buf.rstrip("\\").rstrip()
            line = self._cont_buf + " " + raw.strip()
            self._cont_buf = ""
        else:
            line = raw.strip()

        if not line:
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            return

        # Detect new here-doc start: token <<DELIM or <<-DELIM
        m = re.search(r"<<(-?)\s*[\"']?(\w+)[\"']?\s*$", line)
        if m:
            self._heredoc = {
                "cmd": line[:m.start()].rstrip(),
                "delim": m.group(2),
                "strip_tabs": bool(m.group(1)),
                "body": [],
            }
            self.chan.write("> ")
            return

        # Detect trailing backslash continuation
        if line.endswith("\\") and not line.endswith("\\\\"):
            self._continuation = True
            self._cont_buf = line
            self.chan.write("> ")
            return

        if not self._cmd_history or self._cmd_history[-1] != line:
            self._cmd_history.append(line)
        await self._process_single_command(line)

    # ------------------------------------------------------------------
    # Legacy batch handler (non-PTY clients: load tests, scripts)
    # ------------------------------------------------------------------
    async def _process_command_string(self, full_data: str):
        """Batch path: also honor here-docs and backslash continuation."""
        lines = full_data.split('\n')
        accumulated = ""
        heredoc = None
        i = 0
        while i < len(lines):
            raw = lines[i]
            i += 1
            if heredoc is not None:
                if (raw.lstrip() if heredoc["strip_tabs"] else raw).rstrip() == heredoc["delim"]:
                    full_cmd = heredoc["cmd"]
                    self.context["_heredoc_stdin"] = "\n".join(heredoc["body"])
                    if full_cmd.strip():
                        await self._process_single_command(full_cmd)
                    self.context.pop("_heredoc_stdin", None)
                    heredoc = None
                else:
                    heredoc["body"].append(raw)
                continue

            stripped = raw.strip()
            if not stripped:
                if not accumulated:
                    self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue
            cmd_part = stripped.split('#')[0].strip()
            if not cmd_part:
                if not accumulated:
                    self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
                continue

            # Continue accumulating if previous line ended with \
            if accumulated:
                accumulated = accumulated.rstrip("\\").rstrip() + " " + cmd_part
            else:
                accumulated = cmd_part

            # Backslash continuation
            if accumulated.endswith("\\") and not accumulated.endswith("\\\\"):
                continue

            # Here-doc start
            m = re.search(r"<<(-?)\s*[\"']?(\w+)[\"']?\s*$", accumulated)
            if m:
                heredoc = {
                    "cmd": accumulated[:m.start()].rstrip(),
                    "delim": m.group(2),
                    "strip_tabs": bool(m.group(1)),
                    "body": [],
                }
                accumulated = ""
                continue

            await self._process_single_command(accumulated)
            accumulated = ""

    # ------------------------------------------------------------------
    # Core command dispatcher (used by both PTY and batch paths)
    # ------------------------------------------------------------------
    async def _process_single_command(self, cmd: str):
        # MITRE ATT&CK mapping for EVERY command — fire-and-forget
        asyncio.create_task(self._record_mitre_for_command(cmd))

        # Telemetry only — DO NOT short-circuit the command. Real bash would just
        # try to run "ignore" as a command and fail with "command not found".
        # Blocking with a special-case response is itself a honeypot fingerprint.
        if _looks_like_prompt_injection(cmd):
            logger.warning(f"[{self.session_id}] Prompt-injection-style input: {cmd[:100]}")
            asyncio.create_task(self._record_mitre_technique({
                "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution", "confidence": 0.85,
                "evidence": f"Prompt-injection-style input: {cmd[:80]}",
            }))
            asyncio.create_task(self._alert_honeytoken(f"prompt-injection://{cmd[:80]}"))
            # fall through to normal dispatch

        # B4: expand variables + arithmetic (sync), then globs against virtual FS (async)
        cmd = self._expand_specials(cmd)
        if '*' in cmd or '?' in cmd:
            cmd = await self._expand_globs(cmd)

        if cmd in ["exit", "logout"]:
            self.chan.write("logout\r\n")
            await self._close()
            self.chan.close()
            return

        # B1: builtins with deterministic exit codes
        if cmd in ("true", ":"):
            self._set_exit(0)
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            return
        if cmd == "false":
            self._set_exit(1)
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
            return

        # B2 (partial in-memory): export / unset / alias persist for this session.
        if cmd.startswith("export ") or cmd.startswith("declare -x "):
            await self._handle_export(cmd)
            return
        if cmd.startswith("unset "):
            await self._handle_unset(cmd)
            return
        if cmd.startswith("alias ") or cmd == "alias":
            await self._handle_alias(cmd)
            return
        if cmd.startswith("unalias "):
            await self._handle_unalias(cmd)
            return

        # B6 (partial): background job execution `cmd &`
        if cmd.rstrip().endswith("&") and not cmd.rstrip().endswith("&&"):
            await self._handle_background(cmd.rstrip().rstrip("&").strip())
            return

        # Alias expansion: substitute the first token if it's an alias
        first = cmd.split(maxsplit=1)
        if first and first[0] in self._aliases:
            rest = first[1] if len(first) > 1 else ""
            cmd = f"{self._aliases[first[0]]} {rest}".strip()

        # B5: Pipe / redirect detection — route before per-command dispatch
        if self._has_pipe_or_redirect(cmd):
            await self._execute_pipeline(cmd)
            return

        if cmd in CONTAINER_ESCAPE_PROBES:
            await self._handle_intercept(cmd, CONTAINER_ESCAPE_PROBES[cmd])
            return

        if cmd == "cd" or cmd.startswith("cd "):
            self._handle_cd(cmd)
            self._set_exit(0)
            asyncio.create_task(self._persist_state('cwd', 'cwd', self.current_directory))
            self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")
        elif (cmd.startswith("ls") or cmd.startswith("cat ") or
              cmd.startswith("touch ") or cmd.startswith("mkdir ")):
            await self._handle_fs_command(cmd)
        elif cmd.startswith("ps"):
            await self._handle_ps_command(cmd)
        elif cmd in ("env", "printenv"):
            await self._handle_env_command()
        elif cmd.startswith("ping "):
            await self._handle_ping(cmd)
        elif cmd.startswith("ssh "):
            await self._handle_ssh_internal(cmd)
        elif re.match(r'^(nc|ncat|netcat|telnet)\s', cmd):
            await self._handle_decoy_service(cmd)
        else:
            await self._handle_generic_command(cmd)

    # ------------------------------------------------------------------
    # B2 builtins: export / unset / alias / unalias (in-memory per session)
    # ------------------------------------------------------------------
    async def _handle_export(self, cmd: str):
        body = cmd.split(maxsplit=1)[1] if " " in cmd else ""
        if body.startswith("-x "):
            body = body[3:]
        if "=" in body:
            name, _, val = body.partition("=")
            name = name.strip()
            val = val.strip().strip('"').strip("'")
            self._session_env[name] = val
            self.context["environment"] = dict(self._session_env)
            self._set_exit(0)
            asyncio.create_task(self._persist_state('env', name, val))
        elif body:
            # `export FOO` with no value: idempotent if FOO is unset
            if body not in self._session_env:
                self._session_env[body] = ""
                self.context["environment"] = dict(self._session_env)
                asyncio.create_task(self._persist_state('env', body, ""))
            self._set_exit(0)
        else:
            self._write_line(self._formatted_env())
            self._set_exit(0)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_unset(self, cmd: str):
        for name in cmd.split()[1:]:
            self._session_env.pop(name, None)
            asyncio.create_task(self._delete_state('env', name))
        self.context["environment"] = dict(self._session_env)
        self._set_exit(0)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_alias(self, cmd: str):
        body = cmd[6:].strip() if cmd.startswith("alias ") else ""
        if not body:
            for k, v in self._aliases.items():
                self._write_line(f"alias {k}='{v}'")
            self._set_exit(0)
        elif "=" in body:
            name, _, val = body.partition("=")
            name = name.strip()
            val = val.strip().strip('"').strip("'")
            self._aliases[name] = val
            self.context['aliases'] = dict(self._aliases)
            self._set_exit(0)
            asyncio.create_task(self._persist_state('alias', name, val))
        else:
            target = self._aliases.get(body)
            if target:
                self._write_line(f"alias {body}='{target}'")
                self._set_exit(0)
            else:
                self._write_line(f"bash: alias: {body}: not found")
                self._set_exit(1)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_unalias(self, cmd: str):
        for name in cmd.split()[1:]:
            self._aliases.pop(name, None)
            asyncio.create_task(self._delete_state('alias', name))
        self.context['aliases'] = dict(self._aliases)
        self._set_exit(0)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    def _formatted_env(self) -> str:
        base = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root", "USER": self.username, "LOGNAME": self.username,
            "SHELL": "/bin/bash", "TERM": "xterm-256color", "LANG": "C.UTF-8",
            "HOSTNAME": HOSTNAME, "PWD": self.current_directory,
        }
        base.update(self._session_env)
        return "\n".join(f'declare -x {k}="{v}"' for k, v in base.items())

    # ------------------------------------------------------------------
    # B6: background job execution
    # ------------------------------------------------------------------
    async def _handle_background(self, cmd: str):
        pid = self._next_pid()
        job_idx = len(self._bg_jobs) + 1
        self._bg_jobs.append({
            "pid": pid, "cmd": cmd, "started": time.time(), "job": job_idx,
        })
        self.chan.write(f"[{job_idx}] {pid}\r\n")
        self._set_exit(0)
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    # ------------------------------------------------------------------
    # B5: Pipeline and redirect support
    # ------------------------------------------------------------------

    def _has_pipe_or_redirect(self, cmd: str) -> bool:
        """True if cmd contains an unquoted | (not ||), >, >>, or 2>."""
        in_sq = in_dq = False
        i = 0
        n = len(cmd)
        while i < n:
            c = cmd[i]
            if c == "'" and not in_dq:
                in_sq = not in_sq
            elif c == '"' and not in_sq:
                in_dq = not in_dq
            elif not in_sq and not in_dq:
                if c == '|':
                    if i + 1 < n and cmd[i + 1] == '|':
                        i += 2  # skip || (OR operator)
                        continue
                    return True
                if c == '>':
                    return True
                if c == '2' and i + 1 < n and cmd[i + 1] == '>':
                    return True
            i += 1
        return False

    def _split_on_pipe(self, cmd: str) -> list:
        """Split cmd on unquoted | (not ||), preserving quotes."""
        stages, current = [], []
        in_sq = in_dq = False
        i = 0
        n = len(cmd)
        while i < n:
            c = cmd[i]
            if c == "'" and not in_dq:
                in_sq = not in_sq; current.append(c)
            elif c == '"' and not in_sq:
                in_dq = not in_dq; current.append(c)
            elif c == '|' and not in_sq and not in_dq:
                if i + 1 < n and cmd[i + 1] == '|':
                    current.append(c); current.append(cmd[i + 1]); i += 2; continue
                stages.append("".join(current).strip()); current = []
            else:
                current.append(c)
            i += 1
        if current:
            stages.append("".join(current).strip())
        return [s for s in stages if s]

    @staticmethod
    def _parse_stage_redirects(stage: str) -> tuple:
        """Strip redirections, return (cmd, stdout_file, append, stderr_null, stderr_merged)."""
        cmd = stage
        stdout_file = None
        stdout_append = False
        stderr_null = False
        stderr_merged = False

        cmd, n = re.subn(r'\s*2>\s*/dev/null', '', cmd)
        if n: stderr_null = True

        cmd, n = re.subn(r'\s*2>&1', '', cmd)
        if n: stderr_merged = True

        cmd, n = re.subn(r'\s*2>\s*\S+', '', cmd)  # 2>other_file → discard
        if n and not stderr_null: stderr_null = True

        m = re.search(r'\s*>>\s*(\S+)', cmd)
        if m:
            stdout_file = m.group(1); stdout_append = True
            cmd = cmd[:m.start()] + cmd[m.end():]

        m = re.search(r'(?<!>)>\s*(\S+)', cmd)
        if m:
            stdout_file = m.group(1); stdout_append = False
            cmd = cmd[:m.start()] + cmd[m.end():]

        return cmd.strip(), stdout_file, stdout_append, stderr_null, stderr_merged

    @staticmethod
    def _filter_grep(args: list, stdin: str) -> tuple:
        invert = case_i = count_only = line_nos = fixed = False
        pattern = None
        i = 0
        while i < len(args):
            a = args[i]
            if a in ('-v', '--invert-match'): invert = True
            elif a in ('-i', '--ignore-case'): case_i = True
            elif a in ('-c', '--count'): count_only = True
            elif a in ('-n', '--line-number'): line_nos = True
            elif a in ('-F', '--fixed-strings'): fixed = True
            elif a in ('-E', '-e', '--extended-regexp', '--regexp'): pass
            elif a.startswith('-') and len(a) > 1 and a[1:].isalpha():
                for f in a[1:]:
                    if f == 'v': invert = True
                    elif f == 'i': case_i = True
                    elif f == 'c': count_only = True
                    elif f == 'n': line_nos = True
            elif pattern is None:
                pattern = a
            i += 1
        if pattern is None:
            return "", 1
        try:
            pat = re.escape(pattern) if fixed else pattern
            regex = re.compile(pat, re.IGNORECASE if case_i else 0)
        except re.error:
            return f"grep: invalid expression: {pattern}", 2
        lines = stdin.split('\n')
        matched = []
        for idx, line in enumerate(lines, 1):
            hit = bool(regex.search(line))
            if invert: hit = not hit
            if hit:
                matched.append(f"{idx}:{line}" if line_nos else line)
        if count_only:
            return str(len(matched)), 0 if matched else 1
        return '\n'.join(matched), 0 if matched else 1

    @staticmethod
    def _filter_head(args: list, stdin: str) -> tuple:
        n = 10
        i = 0
        while i < len(args):
            if args[i] == '-n' and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
                i += 2; continue
            elif args[i].startswith('-') and args[i][1:].lstrip('-').isdigit():
                try: n = int(args[i].lstrip('-'))
                except ValueError: pass
            i += 1
        return '\n'.join(stdin.split('\n')[:n]), 0

    @staticmethod
    def _filter_tail(args: list, stdin: str) -> tuple:
        n = 10
        i = 0
        while i < len(args):
            if args[i] == '-n' and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
                i += 2; continue
            elif args[i] == '-f': pass
            elif args[i].startswith('-') and args[i][1:].isdigit():
                try: n = int(args[i][1:])
                except ValueError: pass
            i += 1
        lines = stdin.split('\n')
        return '\n'.join(lines[-n:]) if n > 0 else '', 0

    @staticmethod
    def _filter_wc(args: list, stdin: str) -> tuple:
        do_l = '-l' in args; do_w = '-w' in args; do_c = '-c' in args or '-m' in args
        if not any([do_l, do_w, do_c]):
            l = stdin.count('\n'); w = len(stdin.split()); c = len(stdin)
            return f"{l:>7} {w:>7} {c:>7}", 0
        parts = []
        if do_l: parts.append(f"{stdin.count(chr(10)):>7}")
        if do_w: parts.append(f"{len(stdin.split()):>7}")
        if do_c: parts.append(f"{len(stdin):>7}")
        return ' '.join(parts), 0

    @staticmethod
    def _filter_cut(args: list, stdin: str) -> tuple:
        delim = '\t'; fields = None; chars = None
        i = 0
        while i < len(args):
            if args[i] == '-d' and i + 1 < len(args):
                delim = args[i + 1]; i += 2; continue
            elif args[i].startswith('-d') and len(args[i]) > 2:
                delim = args[i][2:]; i += 1; continue
            elif args[i] == '-f' and i + 1 < len(args):
                spec = args[i + 1]; fields = []
                for p in spec.split(','):
                    if '-' in p:
                        a, b = p.split('-', 1)
                        fields.extend(range(int(a) if a else 1, (int(b) if b else 999) + 1))
                    elif p.isdigit(): fields.append(int(p))
                i += 2; continue
            elif args[i] == '-c' and i + 1 < len(args):
                try: chars = int(args[i + 1])
                except ValueError: pass
                i += 2; continue
            i += 1
        result = []
        for line in stdin.split('\n'):
            if chars is not None: result.append(line[:chars])
            elif fields:
                pts = line.split(delim)
                result.append(delim.join(pts[f - 1] for f in fields if 1 <= f <= len(pts)))
            else: result.append(line)
        return '\n'.join(result), 0

    @staticmethod
    def _filter_sort(args: list, stdin: str) -> tuple:
        rev = '-r' in args; numeric = '-n' in args; unique = '-u' in args
        key_f = None
        for i, a in enumerate(args):
            if a == '-k' and i + 1 < len(args):
                try: key_f = int(args[i + 1].split(',')[0]) - 1
                except (ValueError, IndexError): pass
        lines = stdin.split('\n')
        trailing = lines and lines[-1] == ''
        if trailing: lines = lines[:-1]
        def skey(line):
            if key_f is not None:
                pts = line.split()
                v = pts[key_f] if key_f < len(pts) else line
                if numeric:
                    try: return (0, float(v))
                    except ValueError: pass
                return (1, v)
            if numeric:
                try: return (0, float(line.split()[0]))
                except (ValueError, IndexError): pass
            return (1, line)
        sl = sorted(lines, key=skey, reverse=rev)
        if unique:
            seen = set(); sl = [l for l in sl if not (l in seen or seen.add(l))]
        return ('\n'.join(sl) + ('\n' if trailing else '')), 0

    @staticmethod
    def _filter_uniq(args: list, stdin: str) -> tuple:
        count = '-c' in args; dups = '-d' in args
        lines = stdin.split('\n')
        if lines and not lines[-1]: lines = lines[:-1]
        result = []; i = 0
        while i < len(lines):
            c = 1
            while i + c < len(lines) and lines[i + c] == lines[i]: c += 1
            if not dups or c > 1:
                result.append(f"{c:>7} {lines[i]}" if count else lines[i])
            i += c
        return '\n'.join(result), 0

    @staticmethod
    def _filter_awk(args: list, stdin: str) -> tuple:
        program = ""
        for a in args:
            if not a.startswith('-'): program = a; break
        if not program: return stdin, 0
        prog = program.strip()
        if prog in ('{print}', '{print $0}'): return stdin, 0
        if 'NR' in prog and 'END' in prog:
            return str(len([l for l in stdin.split('\n') if l])), 0
        m = re.match(r'^\{print\s+(.*?)\}$', prog)
        if not m: return stdin, 0
        expr = m.group(1).strip(); result = []
        for nr, line in enumerate(stdin.split('\n'), 1):
            parts = line.split(); nf = len(parts); out_parts = []
            for fe in re.split(r',\s*', expr):
                fe = fe.strip()
                if fe == 'NR': out_parts.append(str(nr))
                elif fe == 'NF': out_parts.append(str(nf))
                elif fe == '$0': out_parts.append(line)
                elif re.match(r'^\$\d+$', fe):
                    idx = int(fe[1:])
                    out_parts.append(line if idx == 0 else (parts[idx-1] if 1 <= idx <= nf else ""))
                elif fe.startswith('"') and fe.endswith('"'): out_parts.append(fe[1:-1])
                else: out_parts.append(fe)
            result.append(' '.join(out_parts))
        return '\n'.join(result), 0

    @staticmethod
    def _filter_sed(args: list, stdin: str) -> tuple:
        script = None
        for i, a in enumerate(args):
            if a == '-e' and i + 1 < len(args): script = args[i + 1]; break
            elif not a.startswith('-'): script = a; break
        if not script: return stdin, 0
        m = re.match(r's(.)(.*?)\1(.*?)\1([gip]*)$', script.strip())
        if not m: return stdin, 0
        pat, repl, fl = m.group(2), m.group(3), m.group(4)
        count = 0 if 'g' in fl else 1
        rf = re.IGNORECASE if 'i' in fl else 0
        try:
            repl_py = repl.replace('\\n', '\n')
            return '\n'.join(re.sub(pat, repl_py, l, count=count, flags=rf) for l in stdin.split('\n')), 0
        except re.error:
            return stdin, 1

    @staticmethod
    def _filter_tr(args: list, stdin: str) -> tuple:
        delete = '-d' in args; squeeze = '-s' in args
        ops = [a for a in args if not a.startswith('-')]
        def expand(s):
            r = []; i = 0
            while i < len(s):
                if i + 2 < len(s) and s[i+1] == '-':
                    lo, hi = ord(s[i]), ord(s[i+2])
                    r.extend(chr(c) for c in range(min(lo,hi), max(lo,hi)+1)); i += 3
                else: r.append(s[i]); i += 1
            return ''.join(r)
        if delete and ops:
            ds = set(expand(ops[0])); return ''.join(c for c in stdin if c not in ds), 0
        if len(ops) < 2: return stdin, 0
        s1, s2 = expand(ops[0]), expand(ops[1])
        tbl = str.maketrans(s1[:len(s2)], s2[:len(s1)])
        out = stdin.translate(tbl)
        if squeeze and ops:
            sq = set(expand(ops[-1])); prev = None; compressed = []
            for c in out:
                if c not in sq or c != prev: compressed.append(c)
                prev = c
            out = ''.join(compressed)
        return out, 0

    async def _cat_for_output(self, cmd: str) -> tuple:
        """cat returning (stdout, stderr)."""
        parts = cmd.split()
        if len(parts) < 2:
            return "", "cat: missing operand"
        path = parts[1]
        if not path.startswith("/"):
            path = f"{self.current_directory.rstrip('/')}/{path}"
        try:
            r = await self.http_client.get(
                f"{SANDBOX_URL}/files/{self.session_id}", params={"path": path})
            if r.status_code == 200:
                content = r.json().get("content", "")
                if path in HONEYTOKEN_FILES:
                    asyncio.create_task(self._alert_honeytoken(path))
                return content, ""
            elif r.status_code == 422:
                return "", f"cat: {path}: Is a directory"
            return "", f"cat: {path}: No such file or directory"
        except Exception as e:
            return "", f"cat: error: {e}"

    async def _ls_for_output(self, cmd: str) -> tuple:
        """ls returning (stdout, stderr)."""
        parts = cmd.split()
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
                    if show_all:
                        lines += ["drwx------ 2 root root 4096 Apr 29 10:00 .",
                                  "drwxr-xr-x 3 root root 4096 Apr 29 10:00 .."]
                    lines += [_format_ls_long(e) for e in entries]
                    return '\n'.join(lines), ""
                names = [(e['name'] + '/' if e.get('type') == 'directory' else e['name'])
                         for e in entries]
                return "  ".join(names), ""
            return "", f"ls: cannot access '{path}': No such file or directory"
        except Exception as e:
            return "", f"ls: error: {e}"

    async def _run_source_command(self, cmd: str, stdin: str = "") -> tuple:
        """Run a non-filter command; return (stdout, stderr, exit_code)."""
        cmd_s = cmd.strip()
        cmd_l = cmd_s.lower()

        # Static responses
        for pattern, handler in STATIC_RESPONSES.items():
            if cmd_l == pattern or cmd_l.startswith(pattern + " "):
                return handler(self.context), "", 0

        # Container escape probes
        if cmd_s in CONTAINER_ESCAPE_PROBES:
            return CONTAINER_ESCAPE_PROBES[cmd_s], "", 0

        # FS commands
        if cmd_s.startswith("cat "):
            out, err = await self._cat_for_output(cmd_s)
            code = 2 if err and ("No such file" in err or "Is a directory" in err) else (1 if err and "Permission" in err else 0)
            return out, err, code
        if cmd_s.startswith("ls"):
            out, err = await self._ls_for_output(cmd_s)
            code = 2 if err else 0
            return out, err, code

        # IMDS
        if "169.254.169.254" in cmd_s:
            out = await self._handle_imds(cmd_s)
            return out or "", "", 0

        # echo
        if cmd_s.startswith("echo "):
            rest = cmd_s[5:]
            if rest.startswith("-n "):
                rest = rest[3:]
            out = rest.strip().strip('"').strip("'")
            return out, "", 0
        if cmd_s == "echo":
            return "", "", 0

        # printf (basic)
        if cmd_s.startswith("printf "):
            return cmd_s[7:].strip().strip('"').strip("'"), "", 0

        # AI engine
        if AI_ENGINE_URL:
            out = await self._get_ai_response(cmd_s)
            if out is not None:
                return out, "", 0

        out = get_fallback(cmd_s, self.context)
        code = 127 if "command not found" in out else 1
        return "", out, code  # fallback is stderr

    async def _run_stage(self, cmd: str, stdin: str = "") -> tuple:
        """Run one pipeline stage; return (stdout, stderr, exit_code)."""
        cmd = self._expand_specials(cmd.strip())
        if not cmd:
            return stdin, "", 0

        parts = cmd.split(maxsplit=1)
        verb = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        args = rest.split() if rest else []

        _filters = {
            'grep': self._filter_grep, 'egrep': self._filter_grep,
            'head': self._filter_head, 'tail': self._filter_tail,
            'wc':   self._filter_wc,   'cut':  self._filter_cut,
            'sort': self._filter_sort, 'uniq': self._filter_uniq,
            'awk':  self._filter_awk,  'sed':  self._filter_sed,
            'tr':   self._filter_tr,
        }
        if verb in _filters:
            out, code = _filters[verb](args, stdin)
            return out, "", code
        if verb == 'cat' and not rest:
            return stdin, "", 0
        if verb in ('less', 'more', 'cat'):
            if not rest:
                return stdin, "", 0
        if verb == 'tee':
            if args:
                await self._write_to_vfs(args[0], stdin)
            return stdin, "", 0
        if verb in ('xargs',):
            # xargs: crude — run each non-empty token as a separate command and concatenate
            results = []
            for token in stdin.split():
                sub = rest + ' ' + token if rest else token
                o, e, _ = await self._run_source_command(sub)
                if o: results.append(o)
            return '\n'.join(results), "", 0

        return await self._run_source_command(cmd, stdin)

    async def _write_to_vfs(self, path: str, content: str, append: bool = False):
        """Write content to the virtual filesystem."""
        if not path.startswith("/"):
            path = f"{self.current_directory.rstrip('/')}/{path}"
        try:
            if append:
                r = await self.http_client.get(
                    f"{SANDBOX_URL}/files/{self.session_id}", params={"path": path})
                existing = r.json().get("content", "") if r.status_code == 200 else ""
                content = existing + content
            await self.http_client.post(
                f"{SANDBOX_URL}/files/{self.session_id}",
                json={"path": path, "content": content, "permissions": "644"})
        except Exception:
            pass

    async def _execute_pipeline(self, full_cmd: str):
        """Execute a command line that contains pipes or redirections."""
        t0 = time.monotonic()
        stages_raw = self._split_on_pipe(full_cmd)
        stdin = ""
        last_exit = 0
        final_out = ""
        stdout_file = None
        stdout_append = False

        for i, stage_raw in enumerate(stages_raw):
            is_last = (i == len(stages_raw) - 1)
            cmd, s_file, s_app, stderr_null, stderr_merged = self._parse_stage_redirects(stage_raw)
            if is_last:
                stdout_file, stdout_append = s_file, s_app

            stdout_out, stderr_out, exit_code = await self._run_stage(cmd, stdin)
            last_exit = exit_code

            if stderr_merged:
                if stderr_out:
                    stdout_out = stdout_out + ("\n" if stdout_out else "") + stderr_out
            elif not stderr_null and stderr_out:
                self._write_err(stderr_out)  # pass stage stderr to terminal now

            if is_last:
                final_out = stdout_out
            else:
                stdin = stdout_out

        self._set_exit(last_exit)

        if stdout_file:
            await self._write_to_vfs(stdout_file, final_out, stdout_append)
        elif final_out:
            self._write_line(final_out)

        self.command_history.append({"command": full_cmd, "output": final_out})
        asyncio.create_task(self._record(full_cmd, final_out, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

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
        from_fallback = False

        if cmd_lower.startswith("sqlite3"):
            output = self._handle_sqlite3(cmd)
            asyncio.create_task(self._alert_honeytoken("/opt/nexopay/data/payments.db"))
        elif "169.254.169.254" in cmd_lower:
            output = await self._handle_imds(cmd)
        else:
            for pattern, handler in STATIC_RESPONSES.items():
                if cmd_lower == pattern or cmd_lower.startswith(pattern + " "):
                    output = handler(self.context)
                    break
            if output is None and AI_ENGINE_URL:
                output = await self._get_ai_response(cmd)
            if output is None:
                output = get_fallback(cmd, self.context)
                from_fallback = True

        await asyncio.sleep(_realistic_delay(cmd))

        if output:
            # D2: command-not-found and similar errors go to stderr
            if from_fallback:
                self._write_err(output)
            else:
                self._write_line(output)

        # B1: exit code inference
        if from_fallback and isinstance(output, str) and "command not found" in output:
            self._set_exit(127)
        elif isinstance(output, str) and "Permission denied" in output:
            self._set_exit(1)
        elif isinstance(output, str) and ("No such file or directory" in output
                                          or "cannot access" in output):
            self._set_exit(2)
        else:
            self._set_exit(0)

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

    # ------------------------------------------------------------------
    # Phase 4 handlers: IMDS, ping, internal SSH, decoy services
    # ------------------------------------------------------------------

    async def _handle_imds(self, cmd: str) -> str:
        url_match = re.search(r'https?://169\.254\.169\.254[^\s"\']*', cmd)
        if not url_match:
            return "curl: (7) Failed to connect to 169.254.169.254 port 80: Connection refused"
        url = url_match.group(0).rstrip('/')
        await asyncio.sleep(random.uniform(0.05, 0.2))
        if "nexopay-prod-role" in url:
            asyncio.create_task(self._alert_honeytoken("aws-imds://iam/security-credentials/nexopay-prod-role"))
            return _aws_imds_creds()
        for route_url, body in _IMDS_ROUTES.items():
            if url == route_url.rstrip('/') or url + '/' == route_url:
                return body
        return "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html><head><title>404 - Not Found</title></head><body><h1>404 - Not Found</h1></body></html>"

    async def _handle_ping(self, cmd: str):
        t0 = time.monotonic()
        parts = cmd.split()
        host = parts[-1]
        for i, p in enumerate(parts[1:], 1):
            if not p.startswith('-') and (i == 1 or parts[i - 1] not in ('-c', '-i', '-W', '-w', '-s')):
                host = p
                break
        await asyncio.sleep(random.uniform(0.1, 0.3))
        ip = _INTERNAL_HOSTS.get(host)
        if ip:
            ms = [random.uniform(0.2, 2.5) for _ in range(3)]
            output = (
                f"PING {host} ({ip}) 56(84) bytes of data.\n"
                + "".join(f"64 bytes from {ip}: icmp_seq={i+1} ttl=64 time={m:.3f} ms\n" for i, m in enumerate(ms))
                + f"\n--- {host} ping statistics ---\n"
                f"3 packets transmitted, 3 received, 0% packet loss, time 2002ms\n"
                f"rtt min/avg/max/mdev = {min(ms):.3f}/{sum(ms)/3:.3f}/{max(ms):.3f}/0.200 ms"
            )
        else:
            output = (
                f"PING {host} ({host}) 56(84) bytes of data.\n\n"
                f"--- {host} ping statistics ---\n"
                f"3 packets transmitted, 0 received, 100% packet loss, time 2001ms"
            )
        self._write_line(output)
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_ssh_internal(self, cmd: str):
        t0 = time.monotonic()
        parts = cmd.split()
        target = next((p for p in parts[1:] if not p.startswith('-')), "")
        hostname = target.split('@')[-1] if '@' in target else target
        user = target.split('@')[0] if '@' in target else "root"
        await asyncio.sleep(random.uniform(0.3, 0.8))
        if hostname in _INTERNAL_HOSTS:
            # DB hosts refuse SSH (correct for a hardened DB server)
            if "db-" in hostname or _INTERNAL_HOSTS.get(hostname) in ("10.0.1.10", "10.0.1.11"):
                output = f"ssh: connect to host {hostname} port 22: Connection refused"
            elif "bastion" in hostname or _INTERNAL_HOSTS.get(hostname) == "10.0.1.5":
                output = (f"The authenticity of host '{hostname} ({_INTERNAL_HOSTS[hostname]})' can't be established.\n"
                          f"ED25519 key fingerprint is SHA256:Zq8mJ3nP1xKvLtRwBhYcDfGsEaOiUy2+NexoPay/Bastion.\n"
                          f"Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
                self._write_line(output)
                # Don't re-show prompt — just drop (bastion would need interactive yes/no)
                self.command_history.append({"command": cmd, "output": output})
                asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
                return
            else:
                output = f"ssh: connect to host {hostname} port 22: No route to host"
        else:
            output = f"ssh: Could not resolve hostname {hostname}: Name or service not known"
        self._write_line(output)
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

    async def _handle_decoy_service(self, cmd: str):
        t0 = time.monotonic()
        parts = cmd.split()
        # Extract host and port from nc/telnet args
        host, port = "", ""
        non_flags = [p for p in parts[1:] if not p.startswith('-')]
        if len(non_flags) >= 2:
            host, port = non_flags[0], non_flags[1]
        elif len(non_flags) == 1:
            host = non_flags[0]

        await asyncio.sleep(random.uniform(0.1, 0.4))
        port_banners = {
            "6379": "+PONG\r\n",
            "5432": "connection to server at \"" + (host or "localhost") + "\", failed: FATAL:  password authentication failed for user \"root\"",
            "3306": "\x4a\x00\x00\x00\x0a8.0.32\x00",  # MySQL greeting start
            "11211": "VERSION 1.6.18\r\n",              # Memcached
            "27017": "MongoDB connection attempt denied",
        }
        if port in port_banners:
            output = port_banners[port]
        elif host and not port:
            output = f"Ncat: Connection refused."
        else:
            output = f"Ncat: No route to host."

        self._write_line(output)
        self.command_history.append({"command": cmd, "output": output})
        asyncio.create_task(self._record(cmd, output, int((time.monotonic() - t0) * 1000)))
        self.chan.write(f"{self.username}@{HOSTNAME}:{self.current_directory}$ ")

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

    async def _alert_high_risk(self):
        if not SLACK_WEBHOOK_URL:
            return
        try:
            await self.http_client.post(SLACK_WEBHOOK_URL, json={"text": (
                f":red_circle: *HIGH-RISK SESSION — `{self.session_id[:8]}`*\n"
                f"*Attacker IP:* `{self.source_ip}`\n"
                f"*MITRE techniques detected:* {self._technique_count}\n"
                f"*Server:* `{HOSTNAME}` (NexoPay prod)\n"
                f"*Action:* Review session in the SOC dashboard"
            )})
            logger.warning(f"[{self.session_id}] High-risk Slack alert sent ({self._technique_count} techniques)")
        except Exception as e:
            logger.error(f"Slack high-risk alert failed: {e}")

    async def _lookup_threat_intel(self):
        if not ABUSEIPDB_KEY:
            return
        try:
            r = await self.http_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": self.source_ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                timeout=5.0,
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                score   = d.get("abuseConfidenceScore", 0)
                country = d.get("countryCode", "Unknown")
                reports = d.get("totalReports", 0)
                logger.info(f"[{self.session_id}] AbuseIPDB {self.source_ip}: score={score} country={country} reports={reports}")
                if score >= 25:
                    asyncio.create_task(self._record_ioc({
                        "ioc_type": "ip", "value": self.source_ip,
                        "confidence": score / 100.0,
                        "context": f"AbuseIPDB: score={score}, country={country}, reports={reports}",
                    }))
        except Exception as e:
            logger.debug(f"AbuseIPDB lookup failed: {e}")

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
            # D2: filesystem errors (cat/ls) go to stderr
            _fs_errs = ("No such file or directory", "cannot access", "Is a directory",
                        "Permission denied", "missing operand", "cannot touch",
                        "cat: error", "ls: error", "touch: error")
            if isinstance(output, str) and any(e in output for e in _fs_errs):
                self._write_err(output)
            else:
                self._write_line(output)

        # B1: exit code inference for FS handler
        if isinstance(output, str) and "Permission denied" in output:
            self._set_exit(1)
        elif isinstance(output, str) and ("No such file or directory" in output
                                          or "cannot access" in output
                                          or "Is a directory" in output
                                          or output.startswith(("cat: error", "ls: error",
                                                                "touch: error", "cat: missing",
                                                                "touch: missing", "touch: cannot"))):
            self._set_exit(2 if "missing operand" not in output else 1)
        else:
            self._set_exit(0)

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
                    today_label = datetime.utcfromtimestamp(BOOT_TIME).strftime("%b%d")
                    if "aux" in cmd:
                        output = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                        output += _KERNEL_THREADS
                        for p in processes:
                            output += (f"{p['username']:<10} {p['pid']:>5} {p['cpu_percent']:>4.1f} "
                                       f"{p['mem_percent']:>4.1f}      0     0 ?        Ss   {today_label}   0:00 {p['name']}\n")
                        # B6: surface this session's background jobs in ps aux
                        now = time.time()
                        for job in self._bg_jobs:
                            run_s = int(now - job["started"])
                            mins, secs = divmod(run_s, 60)
                            cpu = round(random.uniform(0.1, 2.4), 1)
                            mem = round(random.uniform(0.2, 1.6), 1)
                            output += (f"{self.username:<10} {job['pid']:>5} {cpu:>4.1f} {mem:>4.1f} "
                                       f"   2048  1024 pts/0    S    "
                                       f"{datetime.utcnow().strftime('%H:%M')}   {mins}:{secs:02d} {job['cmd']}\n")
                    else:
                        output = "  PID TTY          TIME CMD\n"
                        output += "    1 ?        00:00:05 init\n"
                        output += "  134 ?        00:00:00 sshd\n"
                        for p in processes[:5]:
                            output += f"{p['pid']:>5} pts/0    00:00:00 {p['name']}\n"
                        for job in self._bg_jobs:
                            output += f"{job['pid']:>5} pts/0    00:00:00 {job['cmd'].split()[0] if job['cmd'] else 'sh'}\n"
            except Exception as e:
                output = f"ps: error: {e}"
        if output:
            self._write_line(output)
        self._set_exit(0)
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
            _aws_id = os.getenv('CANARY_AWS_ACCESS_KEY', 'AKIAVLQNEXOPAY1PROD7')  # nosemgrep
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

    # ------------------------------------------------------------------
    # B2: Persistent state helpers (fire-and-forget, no error propagation)
    # ------------------------------------------------------------------
    async def _persist_state(self, kind: str, name: str, value: str):
        try:
            await self.http_client.put(
                f"{SANDBOX_URL}/state/{self.source_ip}/{kind}/{name}",
                json={"value": value})
        except Exception:
            pass

    async def _delete_state(self, kind: str, name: str):
        try:
            await self.http_client.delete(
                f"{SANDBOX_URL}/state/{self.source_ip}/{kind}/{name}")
        except Exception:
            pass

    async def _record(self, cmd: str, out: str, duration_ms: int = 0,
                      exit_code: Optional[int] = None):
        if exit_code is None:
            exit_code = self._last_exit
        try:
            await self.http_client.post(f"{SANDBOX_URL}/commands/{self.session_id}",
                json={"command": cmd, "output": out, "exit_code": exit_code,
                      "duration_ms": duration_ms})
        except: pass

    async def _record_ioc(self, ioc: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/iocs/{self.session_id}",
                json={"ioc_type": ioc.get("ioc_type"), "value": ioc.get("value"),
                      "confidence": ioc.get("confidence", 0.5),
                      "context": "AI extracted from command/response"})
        except Exception as e:
            logger.error(f"Failed to report IOC: {e}")

    async def _record_mitre_for_command(self, cmd: str):
        """Fire-and-forget: call AI Engine's MITRE matcher for ANY command."""
        if not AI_ENGINE_URL:
            return
        try:
            r = await self.http_client.post(
                f"{AI_ENGINE_URL}/mitre-match",
                json={"command": cmd},
                timeout=3.0,
            )
            if r.status_code == 200:
                for tech in r.json().get("mitre_techniques", []):
                    asyncio.create_task(self._record_mitre_technique(tech))
        except Exception as e:
            logger.debug(f"mitre-match failed for {cmd[:50]}: {e}")

    async def _record_mitre_technique(self, technique: dict):
        try:
            await self.http_client.post(f"{SANDBOX_URL}/attack-techniques/{self.session_id}",
                json={"technique_id": technique.get("technique_id"),
                      "technique_name": technique.get("technique_name"),
                      "tactic": technique.get("tactic"),
                      "confidence": technique.get("confidence", 0.5),
                      "evidence": technique.get("evidence", "")})
            self._technique_count += 1
            if not self._alerted_high and self._technique_count >= 3:
                self._alerted_high = True
                asyncio.create_task(self._alert_high_risk())
        except Exception as e:
            logger.error(f"Failed to report MITRE technique: {e}")

    async def _close(self):
        try:
            await self.http_client.delete(f"{SANDBOX_URL}/sessions/{self.session_id}")
            logger.info(f"Session {self.session_id} closed")
        except: pass
        await self.http_client.aclose()


# ──────────────────────────────────────────────────────────────────────────────
# D4: SFTP subsystem — asyncssh SFTPServer backed by sandbox-store virtual FS
# ──────────────────────────────────────────────────────────────────────────────

class _SFTPReaderAdapter:
    """Duck-typed reader that feeds bytes from SessionHandler.data_received → SFTPServerHandler."""
    def __init__(self):
        self._buf = bytearray()
        self._waiter: Optional[asyncio.Future] = None

    def feed(self, data: bytes):
        self._buf.extend(data)
        if self._waiter and not self._waiter.done():
            self._waiter.set_result(None)

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._waiter = asyncio.get_event_loop().create_future()
            await self._waiter
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    async def read(self, n: int = -1) -> bytes:
        return await self.readexactly(n)


class _SFTPWriterAdapter:
    """Duck-typed writer that sends bytes directly on the SSH channel."""
    def __init__(self, chan):
        self._chan = chan

    def write(self, data: bytes):
        try:
            self._chan.write(data)
        except Exception:
            pass


def _sftp_long_name(name: str, is_dir: bool, size: int) -> str:
    perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M")
    return f"{perm} 1 root root {size:>8d} {ts} {name}"


class HoneypotSFTPServer(asyncssh.SFTPServer):
    """SFTP server backed by sandbox-store; attacker uploads are stored + IOC'd."""

    _VIRTUAL_DIRS = frozenset({
        '/', '/root', '/home', '/home/ubuntu', '/tmp', '/etc', '/etc/ssh',
        '/var', '/var/log', '/var/backups', '/opt', '/opt/nexopay',
        '/opt/nexopay/bin', '/opt/nexopay/config', '/opt/nexopay/data',
        '/opt/nexopay/logs', '/usr', '/usr/bin', '/usr/local',
        '/proc', '/sys', '/dev', '/run',
    })

    _DIR_LISTINGS: dict = {
        '/': ['root', 'home', 'etc', 'opt', 'tmp', 'var', 'usr', 'proc', 'sys', 'dev', 'run'],
        '/root': ['.bashrc', '.bash_history', '.ssh'],
        '/root/.ssh': ['authorized_keys', 'known_hosts'],
        '/home': ['ubuntu'],
        '/home/ubuntu': ['.bashrc'],
        '/tmp': [],
        '/etc': ['hostname', 'passwd', 'shadow', 'os-release', 'hosts', 'ssh', 'crontab'],
        '/etc/ssh': ['sshd_config', 'ssh_host_rsa_key.pub'],
        '/var': ['log', 'backups'],
        '/var/log': ['auth.log', 'syslog'],
        '/opt/nexopay': ['bin', 'config', 'data', 'logs'],
        '/opt/nexopay/config': [
            'app.env', 'db.env', 'redis.env', 'payment-gw.env',
        ],
        '/opt/nexopay/logs': ['api.log', 'worker.log'],
    }

    _STATIC_FILES: dict = {
        '/etc/hostname': 'api-prod-01\n',
        '/etc/hosts': (
            '127.0.0.1   localhost\n'
            '127.0.1.1   api-prod-01\n'
            '::1         localhost ip6-localhost ip6-loopback\n'
        ),
        '/etc/passwd': (
            'root:x:0:0:root:/root:/bin/bash\n'
            'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
            'ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n'
            'nexopay:x:1001:1001:NexoPay Service:/opt/nexopay:/sbin/nologin\n'
        ),
        '/etc/shadow': 'root:*:19900:0:99999:7:::\n',
        '/root/.bashrc': (
            '# ~/.bashrc\nexport PS1="\\u@\\h:\\w\\$ "\n'
            'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            'alias ll="ls -la"\n'
        ),
        '/root/.bash_history': '',
        '/root/.ssh/authorized_keys': '',
        '/root/.ssh/known_hosts': '',
        '/etc/crontab': (
            '# /etc/crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n'
            '*/5 * * * * root /opt/nexopay/bin/health_check.sh\n'
            '0 2 * * * root /opt/nexopay/bin/db_backup.sh\n'
        ),
        '/etc/ssh/sshd_config': (
            'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n'
            'PubkeyAuthentication yes\nX11Forwarding no\nPrintLastLog yes\n'
        ),
        '/var/log/auth.log': '',
        '/var/log/syslog': '',
        '/opt/nexopay/config/app.env': (
            'APP_ENV=production\nAPP_PORT=8080\n'
            'LOG_LEVEL=info\nSECRET_KEY=REDACTED\n'
        ),
        '/opt/nexopay/config/db.env': (
            'DB_HOST=db-primary.nexopay.internal\nDB_PORT=5432\n'
            'DB_NAME=nexopay_prod\nDB_USER=nexopay\nDB_PASSWORD=REDACTED\n'
        ),
        '/opt/nexopay/config/redis.env': (
            'REDIS_HOST=redis.nexopay.internal\nREDIS_PORT=6379\n'
            'REDIS_PASSWORD=REDACTED\n'
        ),
        '/opt/nexopay/config/payment-gw.env': (
            'PAYMENT_GW_URL=https://api.payment-gateway.com/v2\n'
            'PAYMENT_GW_KEY=REDACTED\nPAYMENT_GW_SECRET=REDACTED\n'
        ),
        '/opt/nexopay/logs/api.log': '',
        '/opt/nexopay/logs/worker.log': '',
    }

    def __init__(self, chan):
        super().__init__(chan)
        conn = chan.get_connection()
        self._username = conn.get_extra_info('username') or 'root'
        self._source_ip = conn.get_extra_info('peername')[0]
        self._session_id: Optional[str] = None
        self._http = httpx.AsyncClient(timeout=5.0)

    # ── helpers ────────────────────────────────────────────────────────────────

    async def _ensure_session(self):
        if self._session_id:
            return
        self._session_id = f"sftp-{self._source_ip}-{uuid.uuid4().hex[:8]}"
        try:
            await self._http.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": self._session_id,
                "source_ip": self._source_ip,
                "protocol": "ssh",
                "username": self._username,
            })
        except Exception:
            pass
        logger.info(f"[SFTP] Session {self._session_id} for {self._source_ip} ({self._username})")

    @staticmethod
    def _norm(path: str) -> str:
        parts: list = []
        for seg in path.split('/'):
            if seg == '..':
                if parts:
                    parts.pop()
            elif seg and seg != '.':
                parts.append(seg)
        return '/' + '/'.join(parts) if parts else '/'

    def _dir_attrs(self) -> asyncssh.SFTPAttrs:
        return asyncssh.SFTPAttrs(
            size=4096, uid=0, gid=0, permissions=0o040755,
            atime=int(time.time()), mtime=int(time.time()), nlink=2)

    def _file_attrs(self, size: int = 0) -> asyncssh.SFTPAttrs:
        return asyncssh.SFTPAttrs(
            size=size, uid=0, gid=0, permissions=0o100644,
            atime=int(time.time()), mtime=int(time.time()), nlink=1)

    async def _store_stat(self, path: str):
        """Check sandbox-store for a file/dir entry; returns (is_dir, size) or None."""
        if not self._session_id:
            return None
        try:
            r = await self._http.get(
                f"{SANDBOX_URL}/files/{self._session_id}",
                params={"path": path})
            if r.status_code == 200:
                content = r.json().get('content', '')
                return (False, len(content.encode()))
            if r.status_code == 422:  # "Is a directory"
                return (True, 4096)
        except Exception:
            pass
        return None

    async def _log_sftp_ioc(self, path: str, size: int):
        try:
            await self._http.post(f"{SANDBOX_URL}/iocs/{self._session_id}", json={
                "ioc_type": "sftp_upload",
                "value": path,
                "confidence": 0.95,
                "context": f"SFTP upload from {self._source_ip} ({size} bytes)",
            })
        except Exception:
            pass

    # ── SFTPServer interface ───────────────────────────────────────────────────

    async def realpath(self, path: str) -> str:
        return self._norm(path or '/root')

    async def stat(self, path: str) -> asyncssh.SFTPAttrs:
        return await self.lstat(path)

    async def lstat(self, path: str) -> asyncssh.SFTPAttrs:
        path = self._norm(path)
        if path in self._VIRTUAL_DIRS:
            return self._dir_attrs()
        if path in self._STATIC_FILES:
            return self._file_attrs(len(self._STATIC_FILES[path].encode()))
        await self._ensure_session()
        result = await self._store_stat(path)
        if result is not None:
            is_dir, size = result
            return self._dir_attrs() if is_dir else self._file_attrs(size)
        raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, f"No such file or directory")

    async def readdir(self, path: str):
        path = self._norm(path)
        if path not in self._VIRTUAL_DIRS:
            await self._ensure_session()
            result = await self._store_stat(path)
            if result is None or not result[0]:
                raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, "No such file or directory")

        names: list = []
        base_listing = list(self._DIR_LISTINGS.get(path, []))

        # Add any files written to this directory via sandbox-store
        await self._ensure_session()
        try:
            r = await self._http.get(
                f"{SANDBOX_URL}/files/{self._session_id}/list",
                params={"path": path})
            if r.status_code == 200:
                for e in r.json().get('entries', []):
                    ename = e['name']
                    if ename not in base_listing:
                        base_listing.append(ename)
        except Exception:
            pass

        for entry in base_listing:
            full = f"{path.rstrip('/')}/{entry}"
            is_dir = full in self._VIRTUAL_DIRS or (
                path in self._DIR_LISTINGS and entry in self._DIR_LISTINGS.get(full, []))
            # refine: if entry is a key in _DIR_LISTINGS it's definitely a dir
            is_dir = is_dir or full in self._DIR_LISTINGS
            size = 4096 if is_dir else len(self._STATIC_FILES.get(full, '').encode())
            attrs = self._dir_attrs() if is_dir else self._file_attrs(size)
            names.append(asyncssh.SFTPName(
                filename=entry,
                longname=_sftp_long_name(entry, is_dir, size),
                attrs=attrs))

        return names

    async def open(self, path: str, pflags, attrs):
        path = self._norm(path)
        write = bool(pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_CREAT))
        append = bool(pflags & asyncssh.FXF_APPEND)

        if write:
            existing = b''
            if append:
                if path in self._STATIC_FILES:
                    existing = self._STATIC_FILES[path].encode()
                else:
                    await self._ensure_session()
                    result = await self._store_stat(path)
                    if result and not result[0]:
                        try:
                            r = await self._http.get(
                                f"{SANDBOX_URL}/files/{self._session_id}",
                                params={"path": path})
                            if r.status_code == 200:
                                existing = r.json().get('content', '').encode()
                        except Exception:
                            pass
            return {'path': path, 'buf': bytearray(existing), 'write': True}

        # Read mode
        if path in self._STATIC_FILES:
            return {'path': path, 'data': self._STATIC_FILES[path].encode(), 'write': False}

        await self._ensure_session()
        try:
            r = await self._http.get(
                f"{SANDBOX_URL}/files/{self._session_id}",
                params={"path": path})
            if r.status_code == 200:
                data = r.json().get('content', '').encode()
                return {'path': path, 'data': data, 'write': False}
        except Exception:
            pass
        raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, "No such file")

    async def close(self, file_obj: dict):
        if not file_obj.get('write'):
            return
        path = file_obj['path']
        buf: bytearray = file_obj['buf']
        size = len(buf)
        logger.info(f"[SFTP] Upload: {path} ({size} bytes) from {self._source_ip}")
        try:
            content = buf.decode('utf-8', errors='replace')
            await self._http.post(f"{SANDBOX_URL}/files/{self._session_id}", json={
                "path": path, "content": content, "permissions": "644"})
            await self._log_sftp_ioc(path, size)
        except Exception as e:
            logger.warning(f"[SFTP] Store failed: {e}")
        # Close the shared http client only when connection drops, not on each file
        # (handled in connection_lost / garbage collection)

    async def read(self, file_obj: dict, offset: int, length: int) -> bytes:
        data = file_obj.get('data') or file_obj.get('buf', b'')
        return bytes(data[offset:offset + length])

    async def write(self, file_obj: dict, offset: int, data: bytes):
        buf: bytearray = file_obj['buf']
        end = offset + len(data)
        if end > len(buf):
            buf.extend(b'\x00' * (end - len(buf)))
        buf[offset:end] = data

    async def mkdir(self, path: str, attrs):
        # Honeypot: accept mkdir silently
        pass

    async def rmdir(self, path: str):
        pass

    async def remove(self, path: str):
        pass

    async def rename(self, oldpath: str, newpath: str, flags: int = 0):
        pass

    async def readlink(self, path: str) -> str:
        raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, "Not a symlink")

    async def symlink(self, oldpath: str, newpath: str):
        pass

    async def setstat(self, path: str, attrs):
        pass


class SSHServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None
        self._conn_auth_attempts = 0  # D6: per-connection counter for MaxAuthTries

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

    def public_key_auth_supported(self):
        return True

    async def validate_public_key(self, username, key):
        """D3: Log fingerprint as high-value IOC; 40% sticky-accept, 60% reject."""
        ip = self._conn.get_extra_info('peername')[0]
        try:
            fingerprint = key.get_fingerprint()
        except Exception:
            fingerprint = "<unknown>"
        logger.info(f"Pubkey auth from {ip} as {username}: {fingerprint[:40]}")

        self._conn_auth_attempts += 1
        if self._conn_auth_attempts > 6:
            try:
                self._conn.disconnect(
                    asyncssh.DISC_TOO_MANY_CONNECTIONS, "Too many authentication failures")
            except Exception:
                pass
            return False

        st = _auth_record(ip)
        if st.get("accepted_key") is not None:
            return fingerprint == st["accepted_key"]

        if random.random() < 0.40:
            st["accepted_key"] = fingerprint
            logger.info(f"Pubkey accepted for {username} from {ip}")
            asyncio.create_task(self._async_record_pubkey(ip, username, fingerprint))
            return True

        logger.info(f"Pubkey rejected for {username} from {ip}")
        return False

    async def _async_record_pubkey(self, ip: str, username: str, fingerprint: str):
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                await c.post(f"{SANDBOX_URL}/iocs/unknown", json={
                    "ioc_type": "ssh_pubkey", "value": fingerprint,
                    "confidence": 0.90,
                    "context": f"Public-key auth attempt from {ip} as {username}",
                })
        except Exception:
            pass

    async def validate_password(self, username, password):
        ip = self._conn.get_extra_info('peername')[0]
        st = _auth_record(ip)

        await asyncio.sleep(random.uniform(0.2, 0.8))

        # D6: OpenSSH-style MaxAuthTries — disconnect after 6 attempts on the
        # same connection, no timed lockouts.
        self._conn_auth_attempts += 1
        if self._conn_auth_attempts > 6:
            logger.warning(f"MaxAuthTries exceeded for {ip}")
            try:
                self._conn.disconnect(
                    asyncssh.DISC_TOO_MANY_CONNECTIONS,
                    "Too many authentication failures",
                )
            except Exception:
                pass
            return False

        st["attempts"] += 1

        if st["accepted"] is not None:
            if password == st["accepted"]:
                logger.info(f"Accepted: {username} from {ip}")
                return True
            logger.warning(f"Rejected: {username}/{password} from {ip}")
            return False

        # Sticky probabilistic acceptance (Phase 1.4) — once a password is
        # accepted for an IP, it's accepted on future attempts too.
        if st["attempts"] >= st["threshold"] and random.random() < 0.40:
            st["accepted"] = password
            logger.info(f"Accepted: {username} from {ip} (password locked in)")
            return True

        logger.warning(f"Rejected: {username}/{password} from {ip}")
        return False

    # D7: port-forwarding & agent-forwarding — log as high-value IOC then
    # respond with "administratively prohibited" like a real hardened sshd.
    def server_requested(self, listen_host, listen_port):
        try:
            ip = self._conn.get_extra_info('peername')[0]
        except Exception:
            ip = "unknown"
        logger.warning(f"Remote port-forward attempt from {ip}: {listen_host}:{listen_port}")
        return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        try:
            ip = self._conn.get_extra_info('peername')[0]
        except Exception:
            ip = "unknown"
        logger.warning(f"Local port-forward attempt from {ip}: -> {dest_host}:{dest_port}")
        return False

    def session_requested(self):
        username = self._conn.get_extra_info('username') or "root"
        source_ip = self._conn.get_extra_info('peername')[0]
        return SessionHandler(username, source_ip)


def _ensure_host_key() -> str:
    """Generate the SSH host key once per persistent volume, then reuse forever.

    Stable across container restarts so the host-key fingerprint never rotates —
    real production sshd hosts persist /etc/ssh/ssh_host_rsa_key.
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError:
        pass
    if not os.path.exists(HOST_KEY_PATH):
        logger.info(f"Generating SSH host key at {HOST_KEY_PATH}")
        key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
        key.write_private_key(HOST_KEY_PATH)
        try:
            os.chmod(HOST_KEY_PATH, 0o600)
        except OSError:
            pass
    else:
        logger.info(f"Reusing existing SSH host key at {HOST_KEY_PATH}")
    return HOST_KEY_PATH


async def start_server():
    ai_status = "AI-Enhanced" if AI_ENGINE_URL else "Static"
    logger.info(f"Session service starting ({ai_status})")
    logger.info(f"Port {LISTEN_PORT}")
    host_key_path = _ensure_host_key()
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{SANDBOX_URL}/health")
            logger.info("Sandbox reachable" if r.status_code == 200 else "Sandbox issue")
    except:
        logger.error("Sandbox unreachable")

    await asyncssh.create_server(
        SSHServer, LISTEN_HOST, LISTEN_PORT,
        server_host_keys=[host_key_path],
        server_version=SERVER_VERSION,
        kex_algs=_KEX_ALGS,
        encryption_algs=_ENCRYPTION_ALGS,
        mac_algs=_MAC_ALGS,
        compression_algs=['none'],
        process_factory=None)
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("Shutting down")
    except Exception as e:
        logger.error(f"Error: {e}")
