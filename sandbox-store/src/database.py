import sqlite3
import json
import os
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class SandboxDatabase:
    """
    Manages all database operations for the sandbox state store.
    Implements ACID transactions and state consistency.
    """
    
    def __init__(self, db_path: str = "/data/honeypot.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        # check_same_thread=False is needed for async applications like FastAPI
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        # Enable Write-Ahead Logging for better concurrency
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA synchronous=NORMAL;')
        conn.row_factory = sqlite3.Row  # Access columns by name
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        # Get schema path from environment or use default
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema_path = os.path.join(base_dir, 'schemas', 'init_db.sql')
        
        if not os.path.exists(schema_path):
            logger.warning(f"Schema file not found at {schema_path}")
            return
        
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        with self.get_connection() as conn:
            conn.executescript(schema)
            # Safe migration: add country column if it doesn't exist yet
            try:
                conn.execute("ALTER TABLE sessions ADD COLUMN country TEXT DEFAULT NULL")
                conn.commit()
                logger.info("Migrated sessions table: added 'country' column")
            except Exception:
                pass  # Column already exists, that's fine
        
        logger.info(f"Database initialized from {schema_path}")
    
    # ==================== SESSION MANAGEMENT ====================
    
    def create_session(self, session_id: str, source_ip: str, 
                       protocol: str, username: Optional[str] = None, 
                       password: Optional[str] = None) -> bool:
        """Create a new honeypot session."""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO sessions 
                    (session_id, source_ip, protocol, username, password, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                """, (session_id, source_ip, protocol, username, password))
                conn.commit()
                
                # Initialize default filesystem for this session
                self._init_default_filesystem(conn, session_id)
                
                # Initialize default processes
                self._init_default_processes(conn, session_id)
                
                # Initialize default environment
                self._init_default_environment(conn, session_id)
                
                conn.commit()
                logger.info(f"Created session {session_id} from {source_ip}")
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"Session {session_id} already exists")
            return False
    
    def _init_default_filesystem(self, conn, session_id: str):
        """Create realistic NexoPay fintech server filesystem."""
        # Read canary token env vars; fall back to realistic-looking static values
        # Use `or` so empty-string env vars also trigger the fallback
        canary_aws_key    = os.getenv('CANARY_AWS_ACCESS_KEY')    or 'AKIAVLQNEXOPAY1PROD7'
        canary_aws_secret = os.getenv('CANARY_AWS_SECRET_KEY')    or 'hP7wNk3vQx2mLrTjY8dZfGbCeAiUoS9pXnWvKm1'
        canary_stripe_key = os.getenv('CANARY_STRIPE_KEY')        or ('sk_live_' + '51HxY8zKjHnxpay4QmK9p2LrTjY8bZfGbCeAiUoS9pX')
        canary_dns_host   = os.getenv('CANARY_DNS_HOSTNAME')      or ''

        hosts_extra = f'10.0.1.99 {canary_dns_host}\n' if canary_dns_host else ''
        hosts_content = (
            '127.0.0.1 localhost\n'
            '127.0.1.1 api-prod-01\n'
            '10.0.1.45 api-prod-01.nexopay.internal api-prod-01\n'
            '10.0.1.46 api-prod-02.nexopay.internal\n'
            '10.0.1.10 db-primary.nexopay.internal db-primary\n'
            '10.0.1.11 db-replica.nexopay.internal\n'
            '10.0.1.20 cache-01.nexopay.internal cache-01\n'
            '10.0.1.5  bastion.nexopay.internal bastion\n'
            '10.0.1.30 monitoring.nexopay.internal\n'
            '10.0.1.50 ci.nexopay.internal\n'
            + hosts_extra
        )

        sql_dump = (
            '-- PostgreSQL database dump\n'
            '-- Dumped from database version 14.10 (Ubuntu 14.10-0ubuntu0.22.04.1)\n'
            '-- Dumped by pg_dump version 14.10\n\n'
            'SET statement_timeout = 0;\nSET client_encoding = \'UTF8\';\n\n'
            'CREATE TABLE public.users (\n'
            '    id varchar(26) NOT NULL,\n'
            '    email varchar(255) NOT NULL,\n'
            '    password_hash varchar(255) NOT NULL,\n'
            '    stripe_customer_id varchar(50),\n'
            '    kyc_status varchar(20) DEFAULT \'pending\',\n'
            '    created_at timestamptz DEFAULT now()\n'
            ');\n\n'
            'CREATE TABLE public.api_tokens (\n'
            '    id varchar(26) NOT NULL,\n'
            '    user_id varchar(26) NOT NULL,\n'
            '    token varchar(64) NOT NULL,\n'
            '    token_hash varchar(128) NOT NULL,\n'
            '    scope varchar(255) DEFAULT \'payments:read payments:write\',\n'
            '    last_used_at timestamptz,\n'
            '    expires_at timestamptz\n'
            ');\n\n'
            'CREATE TABLE public.transactions (\n'
            '    id varchar(26) NOT NULL,\n'
            '    user_id varchar(26) NOT NULL,\n'
            '    amount_cents integer NOT NULL,\n'
            '    currency char(3) DEFAULT \'USD\',\n'
            '    stripe_payment_intent_id varchar(66),\n'
            '    status varchar(20) DEFAULT \'pending\',\n'
            '    created_at timestamptz DEFAULT now()\n'
            ');\n\n'
            'CREATE TABLE public.webhook_secrets (\n'
            '    merchant_id varchar(26) NOT NULL,\n'
            '    secret varchar(64) NOT NULL,\n'
            '    created_at timestamptz DEFAULT now()\n'
            ');\n\n'
            'COPY public.users (id, email, password_hash, stripe_customer_id, kyc_status, created_at) FROM stdin;\n'
            'u_01HX4KP2QRSTUV	james.hartley@gmail.com	$2b$12$LJ3kQrPz8mVyNxWoT5aFUeK7sGbYcHdIjElMnOpR4tSu6vXwZaA	cus_NxP3x4yA1b2c3d4e5	verified	2025-11-12 09:14:22+00\n'
            'u_01HX4KP2WXYZAB	sarah.chen@techcorp.io	$2b$12$Kp9mNqRs3tUvWxYz0AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq	cus_NxP5x6yB2c3d4e5f6	verified	2025-11-15 14:30:01+00\n'
            'u_01HX4KP3CDEFGH	michael.torres@enterprise.com	$2b$12$Mn0oP1qR2sT3uV4wX5yZ6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o	cus_NxP7x8yC3d4e5f6g7	verified	2025-11-18 11:05:44+00\n'
            'u_01HX4KP3IJKLMN	emily.watson@startup.ai	$2b$12$No1pQ2rS3tU4vW5xY6zA7b8C9d0E1f2G3h4I5j6K7l8M9n0O1p	cus_NxP9x0yD4e5f6g7h8	pending	2025-12-01 08:22:33+00\n'
            'u_01HX4KP3OPQRST	david.kim@fintech.co	$2b$12$Op2qR3sT4uV5wX6yZ7aB8cD9eF0gH1iJ2kL3mN4oP5qR6sT7uV	cus_NxPax1yE5f6g7h8i9	verified	2025-12-10 16:45:12+00\n'
            '\\.\n\n'
            'COPY public.api_tokens (id, user_id, token, token_hash, scope, last_used_at, expires_at) FROM stdin;\n'
            'tk_01HXA1B2C3D4E5	u_01HX4KP2QRSTUV	nxp_live_3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c	8f14e45fceea167a5a36dedd4bea2543	payments:read payments:write refunds:write	2026-04-28 23:58:01+00	2027-04-28 00:00:00+00\n'
            'tk_01HXA1B2C3D4F6	u_01HX4KP2WXYZAB	nxp_live_7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f	a87ff679a2f3e71d9181a67b7542122c	payments:read	2026-04-27 10:15:33+00	2027-04-27 00:00:00+00\n'
            'tk_01HXA1B2C3D4G7	u_01HX4KP3CDEFGH	nxp_live_1z2y3x4w5v6u7t8s9r0q1p2o3n4m5l6k7j8i9h0g1f2e3d4c5b6a	eccbc87e4b5ce2fe28308fd9f2a7baf3	payments:read payments:write	2026-04-25 14:22:11+00	2027-04-25 00:00:00+00\n'
            '\\.\n\n'
            'COPY public.transactions (id, user_id, amount_cents, currency, stripe_payment_intent_id, status, created_at) FROM stdin;\n'
            'txn_01HXB1C2D3E4F5	u_01HX4KP2QRSTUV	9999	USD	pi_3OxNpYLkdIwHu7ix1vQaXbZc	succeeded	2026-04-28 23:59:01+00\n'
            'txn_01HXB1C2D3E4G6	u_01HX4KP2WXYZAB	4999	USD	pi_3OxNpYMkdIwHu7ix2wRbYcZd	succeeded	2026-04-28 22:10:44+00\n'
            'txn_01HXB1C2D3E4H7	u_01HX4KP3CDEFGH	149900	USD	pi_3OxNpYNkdIwHu7ix3xScZdAe	processing	2026-04-29 00:02:15+00\n'
            '\\.\n\n'
            'COPY public.webhook_secrets (merchant_id, secret, created_at) FROM stdin;\n'
            'm_3xNp4y1234ABCD	whsec_3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b	2025-10-01 00:00:00+00\n'
            'm_3xNp4y5678EFGH	whsec_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1	2025-11-15 00:00:00+00\n'
            '\\.\n\n'
            '-- Completed on 2026-04-28 03:00:01 UTC\n'
        )

        sql_dump_old = sql_dump.replace('2026-04-28', '2026-04-21').replace('2026-04-29', '2026-04-22')

        default_dirs = [
            ('/home',                    'directory', '755',  'root',     'root'),
            ('/home/ubuntu',             'directory', '755',  'ubuntu',   'ubuntu'),
            ('/home/ubuntu/.ssh',        'directory', '700',  'ubuntu',   'ubuntu'),
            ('/home/deploy',             'directory', '755',  'deploy',   'deploy'),
            ('/home/deploy/.ssh',        'directory', '700',  'deploy',   'deploy'),
            ('/root',                    'directory', '700',  'root',     'root'),
            ('/root/.ssh',               'directory', '700',  'root',     'root'),
            ('/root/.aws',               'directory', '700',  'root',     'root'),
            ('/root/.kube',              'directory', '700',  'root',     'root'),
            ('/root/.docker',            'directory', '700',  'root',     'root'),
            ('/etc',                     'directory', '755',  'root',     'root'),
            ('/etc/ssh',                 'directory', '755',  'root',     'root'),
            ('/etc/nginx',               'directory', '755',  'root',     'root'),
            ('/etc/nginx/sites-available','directory','755',  'root',     'root'),
            ('/etc/netplan',             'directory', '755',  'root',     'root'),
            ('/etc/fail2ban',            'directory', '755',  'root',     'root'),
            ('/etc/cron.d',              'directory', '755',  'root',     'root'),
            ('/etc/sudoers.d',           'directory', '750',  'root',     'root'),
            ('/etc/apt',                 'directory', '755',  'root',     'root'),
            ('/var',                     'directory', '755',  'root',     'root'),
            ('/var/log',                 'directory', '755',  'root',     'root'),
            ('/var/log/nginx',           'directory', '755',  'root',     'root'),
            ('/var/log/nexopay',         'directory', '755',  'nexopay',  'nexopay'),
            ('/var/log/postgresql',      'directory', '755',  'postgres', 'postgres'),
            ('/var/backups',             'directory', '755',  'root',     'root'),
            ('/var/www',                 'directory', '755',  'www-data', 'www-data'),
            ('/var/www/html',            'directory', '755',  'www-data', 'www-data'),
            ('/tmp',                     'directory', '1777', 'root',     'root'),
            ('/usr',                     'directory', '755',  'root',     'root'),
            ('/usr/bin',                 'directory', '755',  'root',     'root'),
            ('/usr/local',               'directory', '755',  'root',     'root'),
            ('/opt',                     'directory', '755',  'root',     'root'),
            ('/opt/nexopay',             'directory', '755',  'root',     'nexopay'),
            ('/opt/nexopay/config',      'directory', '700',  'root',     'nexopay'),
            ('/opt/nexopay/data',        'directory', '750',  'nexopay',  'nexopay'),
            ('/opt/nexopay/logs',        'directory', '755',  'nexopay',  'nexopay'),
            ('/opt/nexopay/scripts',     'directory', '755',  'root',     'nexopay'),
            ('/proc',                    'directory', '555',  'root',     'root'),
        ]

        default_files = [
            # ── System identity ──────────────────────────────────────────────────
            ('/etc/hostname', 'file',
             'api-prod-01\n',
             '644', 'root', 'root'),
            ('/etc/hosts', 'file', hosts_content, '644', 'root', 'root'),
            ('/etc/os-release', 'file',
             'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\n'
             'ID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\nVERSION_ID="22.04"\n'
             'HOME_URL="https://www.ubuntu.com/"\nUBUNTU_CODENAME=jammy\n',
             '644', 'root', 'root'),
            ('/etc/lsb-release', 'file',
             'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n'
             'DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"\n',
             '644', 'root', 'root'),
            ('/etc/debian_version', 'file', 'bookworm/sid\n', '644', 'root', 'root'),
            ('/etc/issue', 'file', 'Ubuntu 22.04.3 LTS \\n \\l\n', '644', 'root', 'root'),
            ('/etc/fstab', 'file',
             '# /etc/fstab\nUUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 /    ext4 errors=remount-ro 0 1\n'
             'UUID=b2c3d4e5-f6a7-8901-bcde-f01234567891 /opt ext4 defaults 0 2\n'
             'tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0\n',
             '644', 'root', 'root'),
            ('/etc/resolv.conf', 'file',
             '# Generated by NetworkManager\nnameserver 10.0.0.2\nnameserver 8.8.8.8\n'
             'search nexopay.internal\noptions timeout:2 attempts:3\n',
             '644', 'root', 'root'),
            ('/etc/netplan/01-netcfg.yaml', 'file',
             'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n'
             '      dhcp4: no\n      addresses:\n        - 10.0.1.45/24\n'
             '      gateway4: 10.0.1.1\n      nameservers:\n        addresses: [10.0.0.2, 8.8.8.8]\n',
             '600', 'root', 'root'),
            ('/etc/passwd', 'file',
             'root:x:0:0:root:/root:/bin/bash\n'
             'ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n'
             'deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n'
             'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
             'nexopay:x:1002:1002:NexoPay:/opt/nexopay:/bin/bash\n'
             'postgres:x:109:117:PostgreSQL:/var/lib/postgresql:/bin/bash\n',
             '644', 'root', 'root'),
            ('/etc/shadow', 'file',
             'root:$6$rounds=65536$rST7pKN4aFbFxs2/$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ:19855:0:99999:7:::\n'
             'ubuntu:$6$rounds=65536$qRS8oKM3aEbExr1/$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij:19855:0:99999:7:::\n'
             'nexopay:$6$rounds=65536$pQR9nLK2bDcDwt0/$zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUTSR:19855:0:99999:7:::\n',
             '000', 'root', 'shadow'),
            ('/etc/ssh/sshd_config', 'file',
             'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\n'
             'AuthorizedKeysFile .ssh/authorized_keys\nChallengeResponseAuthentication no\n'
             'UsePAM yes\nX11Forwarding no\nPrintMotd no\nAcceptEnv LANG LC_*\n'
             'Subsystem sftp /usr/lib/openssh/sftp-server\nMaxAuthTries 6\n'
             'ClientAliveInterval 300\nClientAliveCountMax 2\n',
             '644', 'root', 'root'),
            ('/etc/sudoers', 'file',
             'Defaults\tenv_reset\nDefaults\tmail_badpass\n'
             'Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"\n'
             'root\tALL=(ALL:ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n',
             '440', 'root', 'root'),
            ('/etc/sudoers.d/nexopay', 'file',
             '# NexoPay service accounts\n'
             'nexopay ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nexopay-api, /usr/bin/systemctl status nexopay-api\n'
             'deploy  ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/local/bin/kubectl\n',
             '440', 'root', 'root'),
            ('/etc/apt/sources.list', 'file',
             'deb http://archive.ubuntu.com/ubuntu jammy main restricted\n'
             'deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted\n'
             'deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n'
             'deb http://archive.ubuntu.com/ubuntu jammy universe\n',
             '644', 'root', 'root'),
            ('/etc/nginx/nginx.conf', 'file',
             'user www-data;\nworker_processes auto;\nerror_log /var/log/nginx/error.log;\n'
             'pid /run/nginx.pid;\nevents { worker_connections 1024; }\n'
             'http {\n    include /etc/nginx/mime.types;\n    default_type application/octet-stream;\n'
             '    access_log /var/log/nginx/access.log;\n    sendfile on;\n    keepalive_timeout 65;\n'
             '    include /etc/nginx/sites-enabled/*;\n}\n',
             '644', 'root', 'root'),
            ('/etc/fail2ban/jail.local', 'file',
             '[DEFAULT]\nbantime  = 3600\nfindtime = 600\nmaxretry = 5\n\n'
             '[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\n\n'
             '[nginx-http-auth]\nenabled = true\nport = http,https\nfilter = nginx-http-auth\nlogpath = /var/log/nginx/error.log\n',
             '644', 'root', 'root'),
            # ── Proc (fake but expected) ──────────────────────────────────────────
            ('/proc/version', 'file',
             'Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) '
             '(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld 2.38) '
             '#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n',
             '444', 'root', 'root'),
            ('/proc/cpuinfo', 'file',
             'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 79\n'
             'model name\t: Intel(R) Xeon(R) E5-2676 v3 @ 2.40GHz\nstepping\t: 2\n'
             'cpu MHz\t\t: 2400.060\ncache size\t: 30720 KB\nphysical id\t: 0\n'
             'siblings\t: 4\ncore id\t\t: 0\ncpu cores\t: 4\nbogomips\t: 4800.12\n\n'
             'processor\t: 1\nvendor_id\t: GenuineIntel\n'
             'model name\t: Intel(R) Xeon(R) E5-2676 v3 @ 2.40GHz\ncpu MHz\t\t: 2400.060\n\n'
             'processor\t: 2\nvendor_id\t: GenuineIntel\n'
             'model name\t: Intel(R) Xeon(R) E5-2676 v3 @ 2.40GHz\ncpu MHz\t\t: 2400.060\n\n'
             'processor\t: 3\nvendor_id\t: GenuineIntel\n'
             'model name\t: Intel(R) Xeon(R) E5-2676 v3 @ 2.40GHz\ncpu MHz\t\t: 2400.060\n',
             '444', 'root', 'root'),
            ('/proc/meminfo', 'file',
             'MemTotal:       16384000 kB\nMemFree:         3214568 kB\nMemAvailable:    9876543 kB\n'
             'Buffers:          234512 kB\nCached:          6345128 kB\nSwapCached:            0 kB\n'
             'Active:          8234512 kB\nInactive:        3456789 kB\n'
             'SwapTotal:       2097148 kB\nSwapFree:        2097148 kB\nDirty:               128 kB\n',
             '444', 'root', 'root'),
            # ── Honeytoken: AWS credentials ───────────────────────────────────────
            ('/root/.aws/credentials', 'file',
             f'[default]\naws_access_key_id = {canary_aws_key}\naws_secret_access_key = {canary_aws_secret}\n\n'
             f'[nexopay-prod]\naws_access_key_id = {canary_aws_key}\naws_secret_access_key = {canary_aws_secret}\nregion = us-east-1\n',
             '600', 'root', 'root'),
            ('/root/.aws/config', 'file',
             '[default]\nregion = us-east-1\noutput = json\n\n'
             '[profile nexopay-prod]\nregion = us-east-1\noutput = json\n'
             'role_arn = arn:aws:iam::123456789012:role/nexopay-prod-role\n',
             '600', 'root', 'root'),
            # ── Honeytoken: SSH private key ───────────────────────────────────────
            ('/root/.ssh/id_rsa', 'file',
             '-----BEGIN RSA PRIVATE KEY-----\n'
             'MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtesHMSWBaJRqZBdHGBfTosXe\n'
             'Lm7gTM+cGiYL9ROEMEApT/S6MtFf6OWWtM3lCc0cSCdVxSiMO2l6htj3z1vJQFV\n'
             'lsb5dZGqAQiCkFQCBMzVx4IUygT9aqdlyFjKJLhHCaxPHJY3C5mANkzp3xCfuvA/\n'
             'YDVCmLdP8V/TSmvr2WLQiX4HWiWE/DLtGJFhJbHuX9JhfYEPVBcIZV3IiZxhsMp\n'
             'zOjVIR9WO4kLtl4RHXuNpBNjJoXGYV6DMDp1s3QJX3XJQN9kNI7K0zvG6oKJ4EW\n'
             'zs5p1IqPXvIZqJjVXrlyNWGADZVJpPxK/f7uWwIDAQABAoIBAC5RgZ+hBx7xHNaM\n'
             'pPgwGMnCd2vwhJOri38HGmMSFJJJFDMK2xdJwPANdqGmUcnSzVdBtxVGSTHRMh32\n'
             'QITz2AGXQM1ctbFBsFf9CPhQ4l9g3Jn0YDVzYp4dpVTLiHiEzINVUBuBGUhIXV/m\n'
             'LKV7TrNb5QfRKj4Y5rTwBpK1wOPr2dHJa9X3Qs5Y7ZeHSmKbCXPqWZVGxJzN/a5E\n'
             '3TtF8PdK9mRYvbX2LqJcN7HsWfAuU6mZpYDQkS5rIo3TbXVnREMxL4cK8pJGwTqB\n'
             '8YnCzN2VtOeXPk7hD3FmBa1qWZ4CjKpNlY2VrEsMhTn6pLFoRQAECgYEA7xNpqBXY\n'
             '5KmTZpW9sXGVb2HrTRcAE1JKfCZv7kQ2MnWOX9IkDpHJqY3eRsBFtLUNvdX5PmZj\n'
             'VZ2CkX9YwrN8H7mK6VtLxPqBzYxWsTE4JpCqNZXm1RwGbHnKV3M9L8dAcOEqYsFz\n'
             'IJpWTrXm7VNbU9Kl3sYcR2aEDTBx0CgYEA5dJf3Z8P7mLqV9YnXGsWrTBaK4pCA\n'
             'IMEdxGfV1k3MhZWNsb4JXlKoP9kYvVcBr7wGnqEKpYXjHMtU6aD2sLT0VFZJW2R\n'
             '9cNO4YpXZ1mCqsTVrGlsK4wNEBm7PnW6bYhJfD5MzqC1V3RAoGBAI6LpHZ8N2fMq\n'
             'Y5KrXtJpBWvGsDcAE3HKjVTlPxQ8nZCuEW7sN4IYqXm2VZ9fKrC1bHL5T7GmZ0Mp\n'
             'XNsZJ8wGqrYXI4ClTm2sK5DHpBVkFyNt3aREIMu7Q8PwLb4RGWfJ2xZsK5v4nNXo\n'
             'C1VkZ7P9sGqHJ2VRtEYFoAoGBALmD6mkV/KT9QBLR6INX+xSM1cCqCMqE5W9VbEk\n'
             'l3Q3nXeJxhVcC7GhX2E5cxRCxoL5sYOJvpzQb7XF1NHKbEiO4mSfJH7K0Q7A1sH5\n'
             'HPm5K7f+xnW1W7ZQFZ7X4kqGYkRRIUJwPQWfwSzHbEOZqpQWq8yiB+rnZ4LBnq5v\n'
             'X7Ge5AoGBAJiExabcDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop\n'
             'qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrst\n'
             'uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890123456789ABCDE\n'
             '-----END RSA PRIVATE KEY-----\n',
             '600', 'root', 'root'),
            ('/root/.ssh/id_rsa.pub', 'file',
             'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRndVLkklx2zfEef/KBZ6ng8C16wcxJYFo'
             'lGpkF0cYF9Oixd4ubuBMz5waJgv1E4QwQClP9Loy0V/o5Za0zeUJzRxIJ1XFKIw7aXqG2Pf'
             'PW8lAVWWxvl1kaoBCIKQVAIEzNXHghTKBP1qp2XIWO4kuEcJrE8cljcLmYA2TOnfEJ+68D9g'
             'NUKYt0/xX9NKa+vZYtCJfgdaJYT8Mu0YkWElse5f0mF9gQ9UFwhlXciJnGGwynM6NUhH1Y7i'
             'Qu2XhEde42kE2MmhcZhXoMwOnWzdAlfdclA32Q0jsrTO8bqgongRbOzmnUio9e8hmomNVeuXI1'
             'YYANlUmk/Er9/u5bA== root@api-prod-01\n',
             '644', 'root', 'root'),
            ('/root/.ssh/authorized_keys', 'file',
             'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+deployed0001... deploy@ci-runner-01\n'
             'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+devops0002... devops@nexopay-laptop\n',
             '600', 'root', 'root'),
            ('/root/.ssh/known_hosts', 'file',
             'db-primary.nexopay.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1db...\n'
             'cache-01.nexopay.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD2ca...\n'
             'bastion.nexopay.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQE3ba...\n'
             '10.0.1.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQF4db...\n',
             '644', 'root', 'root'),
            # ── Honeytoken: Docker / Git / NPM / Kube ────────────────────────────
            ('/root/.docker/config.json', 'file',
             '{\n  "auths": {\n'
             '    "registry.nexopay.internal:5000": {\n      "auth": "bmV4b3BheV9jaTo1M2NyM3RQQHNzdzByZA=="\n    },\n'
             '    "ghcr.io": {\n      "auth": "Z2hwX05leG9QYXlDSTIwMjU6Z2hwX0FBQUJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBdGVzdA=="\n    }\n'
             '  },\n  "credsStore": "desktop"\n}\n',
             '600', 'root', 'root'),
            ('/root/.gitconfig', 'file',
             '[user]\n\tname = DevOps Bot\n\temail = devops@nexopay.io\n'
             '[core]\n\teditor = vim\n[credential]\n\thelper = store\n[push]\n\tdefault = current\n',
             '644', 'root', 'root'),
            ('/root/.git-credentials', 'file',
             'https://ghp_3xNp4yAcC3sSt0k3nH3r3XXXXXXXXXXXXXXXX:x-oauth-basic@github.com\n'
             'https://nexopay-ci:5m4rtP@ssw0rd2025@gitlab.nexopay.internal\n',
             '600', 'root', 'root'),
            ('/root/.npmrc', 'file',
             '//registry.npmjs.org/:_authToken=npm_3xNp4yN0d3J5T0k3n12345678901234XXXXXXXX\n'
             '//registry.nexopay.internal/npm/:_authToken=nexo_npm_priv_XXXXXXXX\n'
             'registry=https://registry.npmjs.org/\n',
             '600', 'root', 'root'),
            ('/root/.kube/config', 'file',
             'apiVersion: v1\nclusters:\n- cluster:\n'
             '    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t\n'
             '    server: https://eks-nexopay-prod-01.us-east-1.eks.amazonaws.com\n'
             '  name: nexopay-prod\ncontexts:\n- context:\n    cluster: nexopay-prod\n'
             '    user: nexopay-admin\n  name: nexopay-prod\ncurrent-context: nexopay-prod\n'
             'kind: Config\npreferences: {}\nusers:\n- name: nexopay-admin\n  user:\n'
             '    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjNXcGVvbFJUa2tyOUd4dW5lZ2V0N1FScmZXbnBY'
             'VW9PN3VuaXpsYlBzY1kifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5'
             'pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJuZXhvcGF5Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2Nv'
             'dW50Om5leG9wYXk6bmV4b3BheS1hZG1pbiJ9.SIGNATURE_PLACEHOLDER\n',
             '600', 'root', 'root'),
            # ── Honeytoken: App config with secrets ──────────────────────────────
            ('/opt/nexopay/config/stripe.env', 'file',
             f'STRIPE_SECRET_KEY={canary_stripe_key}\n'
             'STRIPE_PUBLISHABLE_KEY=pk_live_51HxY8zKjHnxpay4QmK9p2LrTj\n'
             'STRIPE_WEBHOOK_SECRET=whsec_3xNp4yW3bh00kS3cr3tXXXXXXXXXXXXX\n'
             'STRIPE_API_VERSION=2023-10-16\n',
             '640', 'root', 'nexopay'),
            ('/opt/nexopay/config/auth.env', 'file',
             'JWT_SECRET=nxp-jwt-pr0d-s3cr3t-2025-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n'
             'JWT_REFRESH_SECRET=nxp-refresh-pr0d-s3cr3t-2025-ZYXWVUTSRQPONMLKJIHGFE\n'
             'JWT_EXPIRY=3600\nJWT_REFRESH_EXPIRY=2592000\n'
             'ADMIN_BOOTSTRAP_TOKEN=nxp_admin_b00tstr4p_XXXXXXXXXXXXXXXXXXXXXXXX\n'
             'SESSION_SECRET=nxp-sess-s3cr3t-XXXXXXXXXXXXXXXXXXXX\n',
             '640', 'root', 'nexopay'),
            ('/opt/nexopay/config/database.env', 'file',
             'DB_HOST=db-primary.nexopay.internal\nDB_PORT=5432\nDB_NAME=nexopay_prod\n'
             'DB_USER=nexopay_app\nDB_PASSWORD=Nx!Pr0d_Pg_P@ss_2025_Secure\n'
             'DB_POOL_MIN=2\nDB_POOL_MAX=20\n'
             'REDIS_URL=redis://:r3d1s_nxp_2025_pr0d@cache-01.nexopay.internal:6379/0\n'
             'REDIS_TTL=3600\n',
             '640', 'root', 'nexopay'),
            ('/opt/nexopay/config/aws.env', 'file',
             f'AWS_ACCESS_KEY_ID={canary_aws_key}\n'
             f'AWS_SECRET_ACCESS_KEY={canary_aws_secret}\n'
             'AWS_DEFAULT_REGION=us-east-1\nAWS_ACCOUNT_ID=123456789012\n'
             'S3_BUCKET_RECEIPTS=nexopay-receipts-prod-us-east-1\n'
             'S3_BUCKET_REPORTS=nexopay-reports-prod-us-east-1\n'
             'S3_BUCKET_BACKUPS=nexopay-backups-prod-us-east-1\n'
             'KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd-56ef-78gh-90ij-1234567890kl\n',
             '640', 'root', 'nexopay'),
            # ── Bash histories ───────────────────────────────────────────────────
            ('/root/.bash_history', 'file',
             'systemctl status nexopay-api\n'
             'kubectl get pods -n nexopay\n'
             'kubectl logs -f deploy/nexopay-api -n nexopay\n'
             'cat /opt/nexopay/config/stripe.env\n'
             f'aws s3 ls s3://nexopay-backups-prod-us-east-1 --profile nexopay-prod\n'
             'aws s3 sync /var/backups s3://nexopay-backups-prod-us-east-1/2026-04/\n'
             'pg_dump -h db-primary.nexopay.internal -U nexopay_app nexopay_prod > /var/backups/nexopay_db_2026-04-28.sql\n'
             'ssh deploy@bastion.nexopay.internal\n'
             'tail -f /opt/nexopay/logs/error.log\n'
             'tail -100 /var/log/auth.log\n'
             'cat /opt/nexopay/config/database.env\n'
             'psql -h db-primary.nexopay.internal -U nexopay_app -d nexopay_prod -c "SELECT COUNT(*) FROM transactions;"\n'
             'redis-cli -h cache-01.nexopay.internal -a r3d1s_nxp_2025_pr0d ping\n'
             'systemctl restart nexopay-api\n'
             'kubectl rollout history deploy/nexopay-api -n nexopay\n'
             'docker pull registry.nexopay.internal:5000/nexopay-api:v2.14.3\n'
             'openssl x509 -in /etc/nginx/ssl/nexopay.crt -noout -dates\n'
             'cat /root/.aws/credentials\n'
             'aws sts get-caller-identity\n'
             'ls -la /opt/nexopay/config/\n'
             'less /opt/nexopay/logs/app.log\n',
             '600', 'root', 'root'),
            ('/home/ubuntu/.bashrc', 'file',
             '# .bashrc\nexport PS1="\\u@\\h:\\w\\$ "\nalias ll="ls -la"\nalias la="ls -A"\nalias l="ls -CF"\n',
             '644', 'ubuntu', 'ubuntu'),
            ('/home/ubuntu/.bash_history', 'file',
             'git clone git@github.com:nexopay/nexopay-api.git\n'
             'cd nexopay-api\nnpm install\ncp .env.example .env\nvim .env\n'
             'npm run migrate\nnpm run test\n'
             'git checkout -b feature/payment-retry-logic\n'
             'git add -A && git commit -m "feat: add payment retry logic"\n'
             'git push origin feature/payment-retry-logic\n'
             'ssh ubuntu@bastion.nexopay.internal\n'
             'kubectl get pods --all-namespaces\n'
             'cat /opt/nexopay/config/database.env\n'
             'psql -h localhost -U nexopay_app -d nexopay_dev\n'
             'npm run build\n',
             '600', 'ubuntu', 'ubuntu'),
            ('/home/deploy/.bash_history', 'file',
             'docker build -t registry.nexopay.internal:5000/nexopay-api:v2.14.3 .\n'
             'docker push registry.nexopay.internal:5000/nexopay-api:v2.14.3\n'
             'kubectl apply -f k8s/deployment.yaml -n nexopay\n'
             'kubectl rollout status deploy/nexopay-api -n nexopay\n'
             'helm upgrade nexopay-api ./charts/nexopay-api --set image.tag=v2.14.3\n'
             'kubectl get events -n nexopay --sort-by=.metadata.creationTimestamp\n'
             'curl -s http://api-prod-01:3000/health\n'
             'kubectl scale deploy/nexopay-api --replicas=4 -n nexopay\n',
             '600', 'deploy', 'deploy'),
            # ── Application scripts and version ──────────────────────────────────
            ('/opt/nexopay/scripts/deploy.sh', 'file',
             '#!/bin/bash\nset -e\nVERSION=${1:-latest}\n'
             'echo "[deploy] Deploying nexopay-api:$VERSION"\n'
             'kubectl set image deployment/nexopay-api nexopay-api=registry.nexopay.internal:5000/nexopay-api:$VERSION -n nexopay\n'
             'kubectl rollout status deployment/nexopay-api -n nexopay --timeout=120s\n'
             'echo "[deploy] Health check..."\n'
             'curl -sf http://api-prod-01:3000/health || (echo "[deploy] FAILED" && exit 1)\n'
             'echo "[deploy] Done: $VERSION"\n',
             '755', 'root', 'nexopay'),
            ('/opt/nexopay/scripts/db-migrate.sh', 'file',
             '#!/bin/bash\nset -e\nsource /opt/nexopay/config/database.env\n'
             'echo "[migrate] Running migrations on $DB_HOST/$DB_NAME"\n'
             'psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f /opt/nexopay/migrations/latest.sql\n'
             'echo "[migrate] Done"\n',
             '755', 'root', 'nexopay'),
            ('/opt/nexopay/scripts/rotate-keys.sh', 'file',
             '#!/bin/bash\n# Rotate AWS keys via KMS - run quarterly\n# See: https://wiki.nexopay.internal/security/key-rotation\n'
             'set -e\nsource /opt/nexopay/config/aws.env\n'
             'echo "[rotate] Initiating key rotation via KMS..."\n'
             'aws kms rotate-key-on-demand --key-id $KMS_KEY_ARN --region $AWS_DEFAULT_REGION\n'
             'echo "[rotate] Keys rotated. Update /opt/nexopay/config/aws.env with new credentials."\n'
             '# TODO: automate credential update (ticket #NPY-4421)\n',
             '750', 'root', 'nexopay'),
            ('/opt/nexopay/current-version', 'file', 'v2.14.3\n', '644', 'nexopay', 'nexopay'),
            # ── Application and system logs ──────────────────────────────────────
            ('/opt/nexopay/logs/app.log', 'file',
             '2026-04-28T23:59:55.123Z [INFO] nexopay-api v2.14.3 starting on port 3000\n'
             '2026-04-28T23:59:55.234Z [INFO] Connected to PostgreSQL at db-primary.nexopay.internal:5432\n'
             '2026-04-28T23:59:55.312Z [INFO] Connected to Redis at cache-01.nexopay.internal:6379\n'
             '2026-04-28T23:59:55.400Z [INFO] Stripe webhook listener active on /webhooks/stripe\n'
             '2026-04-29T00:00:01.001Z [INFO] POST /v1/payments 201 142ms merchant_id=m_3xNp4y1234\n'
             '2026-04-29T00:00:03.234Z [INFO] POST /v1/payments 201 98ms merchant_id=m_abc456\n'
             '2026-04-29T00:01:12.456Z [INFO] GET /v1/customers/cus_3xNp4y7890 200 23ms\n'
             '2026-04-29T00:02:45.789Z [WARN] Rate limit approached for merchant m_3xNp4y1234 (480/500 req/min)\n'
             '2026-04-29T00:05:00.000Z [INFO] Stripe webhook received: payment_intent.succeeded pi_3OXXXXXXXXXXXXXXXX\n'
             '2026-04-29T00:10:22.111Z [INFO] POST /v1/refunds 200 201ms payment_id=pi_3OYYYYYYYYYYYYYY\n',
             '644', 'nexopay', 'nexopay'),
            ('/opt/nexopay/logs/error.log', 'file',
             '2026-04-27T14:32:10.456Z [ERROR] DB connection timeout after 30000ms - retrying (attempt 2/3)\n'
             '2026-04-27T14:32:40.789Z [ERROR] DB connection timeout after 30000ms - retrying (attempt 3/3)\n'
             '2026-04-27T14:33:10.123Z [INFO] DB reconnected successfully\n'
             '2026-04-28T09:15:22.456Z [ERROR] Stripe webhook signature verification failed for /webhooks/stripe\n'
             '2026-04-28T09:15:22.457Z [WARN] Possible webhook replay attack from 185.220.101.45\n',
             '644', 'nexopay', 'nexopay'),
            ('/var/log/nexopay/access.log', 'file',
             '10.0.1.1 - - [29/Apr/2026:00:00:01 +0000] "POST /v1/payments HTTP/1.1" 201 342 "https://app.nexopay.io" "NexoPay-Client/2.3"\n'
             '10.0.1.1 - - [29/Apr/2026:00:01:12 +0000] "GET /v1/customers/cus_3xNp4y7890 HTTP/1.1" 200 1024 "-" "NexoPay-SDK/1.4.2"\n'
             '185.220.101.45 - - [29/Apr/2026:00:15:33 +0000] "GET /v1/admin HTTP/1.1" 403 89 "-" "python-requests/2.31.0"\n'
             '185.220.101.45 - - [29/Apr/2026:00:15:34 +0000] "GET /.env HTTP/1.1" 404 162 "-" "python-requests/2.31.0"\n',
             '640', 'nexopay', 'nexopay'),
            ('/var/log/postgresql/postgresql.log', 'file',
             '2026-04-29 00:00:01.234 UTC [2345] nexopay_app@nexopay_prod LOG:  execute: INSERT INTO transactions VALUES($1,$2,$3,$4,$5,$6)\n'
             '2026-04-29 00:00:01.235 UTC [2345] nexopay_app@nexopay_prod DETAIL:  parameters: $1 = \'txn_01HXXXXX\', $5 = \'pi_3OXXXXXXXXXXXXXXXX\', $6 = \'succeeded\'\n'
             '2026-04-29 00:00:03.456 UTC [2346] nexopay_app@nexopay_prod LOG:  execute: SELECT * FROM api_tokens WHERE token_hash=$1 AND expires_at > NOW()\n',
             '640', 'postgres', 'postgres'),
            ('/var/log/syslog', 'file',
             'Apr 29 00:00:01 api-prod-01 systemd[1]: Starting Daily apt download activities...\n'
             'Apr 29 00:00:02 api-prod-01 sshd[134]: Server listening on 0.0.0.0 port 22.\n'
             'Apr 29 00:00:05 api-prod-01 systemd[1]: nexopay-api.service: Started.\n'
             'Apr 29 00:10:22 api-prod-01 cron[567]: (root) CMD (pg_dump -h db-primary.nexopay.internal -U nexopay_app nexopay_prod > /var/backups/nexopay_db_2026-04-29.sql)\n',
             '644', 'root', 'root'),
            ('/var/log/auth.log', 'file',
             'Apr 28 23:45:12 api-prod-01 sshd[4521]: Invalid user admin from 45.142.212.100 port 54321\n'
             'Apr 28 23:45:12 api-prod-01 sshd[4521]: Failed password for invalid user admin from 45.142.212.100 port 54321 ssh2\n'
             'Apr 28 23:45:14 api-prod-01 sshd[4522]: Failed password for root from 45.142.212.100 port 54322 ssh2\n'
             'Apr 28 23:45:16 api-prod-01 sshd[4523]: Failed password for root from 45.142.212.100 port 54323 ssh2\n'
             'Apr 28 23:45:16 api-prod-01 sshd[4523]: PAM service(sshd) ignoring max retries; 4 > 3\n'
             'Apr 28 23:58:02 api-prod-01 sshd[5001]: Accepted publickey for root from 10.0.1.5 port 41234 ssh2: RSA SHA256:3xNp4yF1ng3rpr1ntXXXXXXXXXXXXXXXXXXXXXX\n'
             'Apr 29 00:15:33 api-prod-01 sshd[5234]: Failed password for root from 185.220.101.45 port 55321 ssh2\n'
             'Apr 29 00:15:34 api-prod-01 sshd[5235]: Failed password for ubuntu from 185.220.101.45 port 55322 ssh2\n'
             'Apr 29 00:15:35 api-prod-01 sshd[5236]: Failed password for nexopay from 185.220.101.45 port 55323 ssh2\n'
             'Apr 29 00:22:10 api-prod-01 sshd[5401]: Accepted password for root from 10.0.1.5 port 43210 ssh2\n',
             '640', 'root', 'root'),
            ('/var/log/nginx/access.log', 'file',
             '10.0.1.1 - - [29/Apr/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"\n'
             '185.220.101.45 - - [29/Apr/2026:00:15:30 +0000] "GET /admin HTTP/1.1" 403 153 "-" "Nikto/2.1.6"\n',
             '644', 'root', 'root'),
            ('/var/log/fail2ban.log', 'file',
             '2026-04-28 00:01:12,345 fail2ban.filter [421]: INFO    [sshd] Found 185.220.101.45\n'
             '2026-04-28 00:01:18,567 fail2ban.filter [421]: INFO    [sshd] Found 185.220.101.45\n'
             '2026-04-28 00:01:24,789 fail2ban.filter [421]: INFO    [sshd] Found 185.220.101.45\n'
             '2026-04-28 00:01:24,901 fail2ban.actions [421]: NOTICE  [sshd] Ban 185.220.101.45\n'
             '2026-04-28 01:01:24,123 fail2ban.actions [421]: NOTICE  [sshd] Unban 185.220.101.45\n'
             '2026-04-28 02:15:33,456 fail2ban.filter [421]: INFO    [sshd] Found 45.142.212.100\n'
             '2026-04-28 02:15:39,678 fail2ban.filter [421]: INFO    [sshd] Found 45.142.212.100\n'
             '2026-04-28 02:15:45,890 fail2ban.filter [421]: INFO    [sshd] Found 45.142.212.100\n'
             '2026-04-28 02:15:45,012 fail2ban.actions [421]: NOTICE  [sshd] Ban 45.142.212.100\n'
             '2026-04-28 03:22:23,678 fail2ban.filter [421]: INFO    [sshd] Found 194.165.16.72\n'
             '2026-04-28 03:22:23,890 fail2ban.actions [421]: NOTICE  [sshd] Ban 194.165.16.72\n',
             '640', 'root', 'root'),
            # ── Honeytoken database: SQL dump (plaintext) ────────────────────────
            ('/var/backups/nexopay_db_2026-04-28.sql', 'file', sql_dump,     '640', 'root', 'root'),
            ('/var/backups/nexopay_db_2026-04-21.sql', 'file', sql_dump_old, '640', 'root', 'root'),
            ('/var/backups/ssl_certs_backup.tar.gz',   'file', '[binary archive]', '600', 'root', 'root'),
            # ── Honeytoken database: file path (SQLite binary placeholder) ───────
            ('/opt/nexopay/data/payments.db', 'file', '[SQLite3 binary database]', '640', 'nexopay', 'nexopay'),
            # ── Nginx and misc ───────────────────────────────────────────────────
            ('/var/www/html/index.html', 'file',
             '<html><body><h1>NexoPay API Gateway</h1></body></html>\n',
             '644', 'www-data', 'www-data'),
            ('/tmp/notes.txt', 'file',
             'TODO: rotate KMS keys this quarter (ticket #NPY-4421)\nCheck redis memory usage on cache-01\n',
             '644', 'root', 'root'),
        ]

        for path, file_type, perms, owner, group in default_dirs:
            conn.execute("""
                INSERT OR IGNORE INTO filesystem
                (session_id, path, file_type, permissions, owner, group_name, size)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (session_id, path, file_type, perms, owner, group))

        for path, file_type, content, perms, owner, group in default_files:
            conn.execute("""
                INSERT OR IGNORE INTO filesystem
                (session_id, path, file_type, content, permissions, owner, group_name, size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, path, file_type, content, perms, owner, group, len(content)))

    def _init_default_processes(self, conn, session_id: str):
        """Create realistic NexoPay server process list."""
        default_processes = [
            (1,    0,    'systemd',      '/sbin/init',                                          'root',     'running', 0.1, 0.5),
            (2,    0,    'kthreadd',     '',                                                    'root',     'sleeping', 0.0, 0.0),
            (134,  1,    'sshd',         '/usr/sbin/sshd -D',                                   'root',     'running', 0.0, 0.2),
            (567,  1,    'cron',         '/usr/sbin/cron -f',                                   'root',     'running', 0.0, 0.1),
            (892,  1,    'nginx',        'nginx: master process /usr/sbin/nginx -g daemon on;', 'root',     'running', 0.1, 0.3),
            (893,  892,  'nginx',        'nginx: worker process',                               'www-data', 'running', 0.0, 0.6),
            (1562, 134,  'sshd',         'sshd: root@pts/0',                                    'root',     'running', 0.1, 0.4),
            (2048, 1,    'redis-server', '/usr/bin/redis-server 127.0.0.1:6379',                'redis',    'running', 0.2, 2.5),
            (2150, 1,    'postgres',     '/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main', 'postgres', 'running', 0.1, 4.2),
            (2151, 2150, 'postgres',     'postgres: checkpointer',                              'postgres', 'running', 0.0, 0.3),
            (2152, 2150, 'postgres',     'postgres: background writer',                         'postgres', 'running', 0.0, 0.3),
            (3100, 1,    'node',         '/usr/bin/node /opt/nexopay/current/server.js',        'nexopay',  'running', 2.1, 8.4),
            (3101, 3100, 'node',         '/usr/bin/node /opt/nexopay/current/worker.js',        'nexopay',  'running', 1.8, 7.9),
            (3102, 3100, 'node',         '/usr/bin/node /opt/nexopay/current/worker.js',        'nexopay',  'running', 1.6, 7.8),
            (3103, 3100, 'node',         '/usr/bin/node /opt/nexopay/current/worker.js',        'nexopay',  'running', 1.9, 8.1),
        ]

        for pid, ppid, name, cmdline, user, status, cpu, mem in default_processes:
            conn.execute("""
                INSERT OR IGNORE INTO processes
                (session_id, pid, ppid, name, cmdline, username, status, cpu_percent, mem_percent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, pid, ppid, name, cmdline, user, status, cpu, mem))

    def _init_default_environment(self, conn, session_id: str):
        """Create NexoPay server environment variables."""
        canary_aws_key    = os.getenv('CANARY_AWS_ACCESS_KEY',    'AKIAVLQNEXOPAY1PROD7')
        canary_aws_secret = os.getenv('CANARY_AWS_SECRET_KEY',    'hP7wNk3vQx2mLrTjY8dZfGbCeAiUoS9pXnWvKm1')
        canary_stripe_key = os.getenv('CANARY_STRIPE_KEY')        or ('sk_live_' + '51HxY8zKjHnxpay4QmK9p2LrTjY8bZfGbCeAiUoS9pX')

        default_env = {
            'PATH':                '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME':                '/root',
            'USER':                'root',
            'SHELL':               '/bin/bash',
            'TERM':                'xterm-256color',
            'LANG':                'en_US.UTF-8',
            'NODE_ENV':            'production',
            'NODE_VERSION':        '20.11.0',
            'AWS_DEFAULT_REGION':  'us-east-1',
            'AWS_ACCESS_KEY_ID':   canary_aws_key,
            'AWS_SECRET_ACCESS_KEY': canary_aws_secret,
            'STRIPE_SECRET_KEY':   canary_stripe_key,
            'DB_HOST':             'db-primary.nexopay.internal',
            'DB_NAME':             'nexopay_prod',
            'NEXOPAY_VERSION':     'v2.14.3',
        }

        for key, value in default_env.items():
            conn.execute("""
                INSERT OR IGNORE INTO environment_vars
                (session_id, key, value, scope)
                VALUES (?, ?, ?, 'session')
            """, (session_id, key, value))
    
    def close_session(self, session_id: str):
        """Mark session as closed."""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE sessions 
                SET status = 'closed', end_time = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
            conn.commit()
        logger.info(f"Closed session {session_id}")
    
    # ==================== FILESYSTEM OPERATIONS ====================
    
    def read_file(self, session_id: str, path: str) -> Optional[str]:
        """Read file content from sandbox filesystem."""
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT content FROM filesystem 
                WHERE session_id = ? AND path = ? AND file_type = 'file'
            """, (session_id, path)).fetchone()
            
            if result:
                return result['content']
            return None
    
    def write_file(self, session_id: str, path: str, content: str, 
                    permissions: str = '644') -> bool:
        """Write or update file in sandbox filesystem."""
        try:
            with self.get_connection() as conn:
                # Check if file exists
                existing = conn.execute("""
                    SELECT id FROM filesystem 
                    WHERE session_id = ? AND path = ?
                """, (session_id, path)).fetchone()
                
                now = datetime.now().isoformat()
                
                if existing:
                    # Update existing file
                    conn.execute("""
                        UPDATE filesystem 
                        SET content = ?, size = ?, modified_time = ?, accessed_time = ?
                        WHERE session_id = ? AND path = ?
                    """, (content, len(content), now, now, session_id, path))
                else:
                    # Create new file
                    conn.execute("""
                        INSERT INTO filesystem 
                        (session_id, path, file_type, content, size, permissions, 
                         owner, group_name, created_time, modified_time, accessed_time)
                        VALUES (?, ?, 'file', ?, ?, ?, 'root', 'root', ?, ?, ?)
                    """, (session_id, path, content, len(content), permissions, 
                          now, now, now))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            return False
    
    def list_directory(self, session_id: str, path: str) -> List[Dict]:
        """List directory contents."""
        if not path.endswith('/'):
            path += '/'
        
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT path, file_type, size, permissions, owner, group_name, 
                       modified_time
                FROM filesystem 
                WHERE session_id = ? AND path LIKE ? AND path != ?
            """, (session_id, f"{path}%", path)).fetchall()
            
            entries = []
            for row in results:
                # Only include direct children, not nested subdirectories
                rel_path = row['path'][len(path):]
                if '/' not in rel_path or rel_path.endswith('/'):
                    entries.append({
                        'name': rel_path.rstrip('/'),
                        'type': row['file_type'],
                        'size': row['size'],
                        'permissions': row['permissions'],
                        'owner': row['owner'],
                        'group': row['group_name'],
                        'modified': row['modified_time']
                    })
            
            return entries
    
    def file_exists(self, session_id: str, path: str) -> bool:
        """Check if file or directory exists."""
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT 1 FROM filesystem 
                WHERE session_id = ? AND path = ?
            """, (session_id, path)).fetchone()
            return result is not None
    
    # ==================== PROCESS MANAGEMENT ====================
    
    def add_process(self, session_id: str, pid: int, name: str, 
                    cmdline: str = '', ppid: int = 1) -> bool:
        """Add a fake process to the process table."""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO processes 
                    (session_id, pid, ppid, name, cmdline, username, status)
                    VALUES (?, ?, ?, ?, ?, 'root', 'running')
                """, (session_id, pid, ppid, name, cmdline))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"Process PID {pid} already exists in session {session_id}")
            return False
    
    def list_processes(self, session_id: str) -> List[Dict]:
        """Get list of all processes for a session."""
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT pid, ppid, name, cmdline, username, status, 
                       cpu_percent, mem_percent, start_time
                FROM processes 
                WHERE session_id = ?
                ORDER BY pid
            """, (session_id,)).fetchall()
            
            return [dict(row) for row in results]
    
    def kill_process(self, session_id: str, pid: int) -> bool:
        """Remove a process (simulate kill command)."""
        with self.get_connection() as conn:
            conn.execute("""
                DELETE FROM processes 
                WHERE session_id = ? AND pid = ?
            """, (session_id, pid))
            conn.commit()
            return True
    
    # ==================== COMMAND HISTORY ====================
    
    def add_command(self, session_id: str, command: str, output: str = '', 
                    exit_code: int = 0, duration_ms: int = 0):
        """Record a command in history."""
        with self.get_connection() as conn:
            # Get next sequence number
            seq_result = conn.execute("""
                SELECT COALESCE(MAX(sequence_number), 0) + 1 as next_seq
                FROM command_history 
                WHERE session_id = ?
            """, (session_id,)).fetchone()
            
            next_seq = seq_result['next_seq']
            
            conn.execute("""
                INSERT INTO command_history 
                (session_id, sequence_number, command, output, exit_code, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, next_seq, command, output, exit_code, duration_ms))
            
            # Update session command count
            conn.execute("""
                UPDATE sessions 
                SET command_count = command_count + 1
                WHERE session_id = ?
            """, (session_id,))
            
            conn.commit()
    
    def get_command_history(self, session_id: str, limit: int = 100) -> List[Dict]:
        """Retrieve command history for a session."""
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT sequence_number, timestamp, command, output, exit_code, duration_ms
                FROM command_history 
                WHERE session_id = ?
                ORDER BY sequence_number DESC
                LIMIT ?
            """, (session_id, limit)).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== LOGS ====================
    
    def add_log(self, session_id: str, log_source: str, log_level: str, 
                message: str):
        """Add a system log entry."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO system_logs 
                (session_id, log_source, log_level, message)
                VALUES (?, ?, ?, ?)
            """, (session_id, log_source, log_level, message))
            conn.commit()
    
    def get_logs(self, session_id: str, source: Optional[str] = None, 
                 limit: int = 100) -> List[Dict]:
        """Retrieve system logs."""
        with self.get_connection() as conn:
            if source:
                results = conn.execute("""
                    SELECT timestamp, log_source, log_level, message
                    FROM system_logs 
                    WHERE session_id = ? AND log_source = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (session_id, source, limit)).fetchall()
            else:
                results = conn.execute("""
                    SELECT timestamp, log_source, log_level, message
                    FROM system_logs 
                    WHERE session_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (session_id, limit)).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== IOCs ====================
    
    def add_ioc(self, session_id: str, ioc_type: str, value: str, 
                confidence: float = 0.5, context: str = ''):
        """Record an Indicator of Compromise."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO iocs 
                (session_id, ioc_type, value, confidence, context)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, ioc_type, value, confidence, context))
            conn.commit()
    
    def get_iocs(self, session_id: Optional[str] = None, ioc_type: Optional[str] = None) -> List[Dict]:
        """Retrieve IOCs with optional filtering."""
        with self.get_connection() as conn:
            query = "SELECT * FROM iocs WHERE 1=1"
            params = []
            
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            
            if ioc_type:
                query += " AND ioc_type = ?"
                params.append(ioc_type)
            
            query += " ORDER BY extracted_at DESC"
            
            results = conn.execute(query, params).fetchall()
            return [dict(row) for row in results]
    
    # ==================== ATTACK TECHNIQUES ====================
    
    def add_attack_technique(self, session_id: str, technique_id: str, 
                            technique_name: str, tactic: str, 
                            confidence: float, evidence: str):
        """Record a detected MITRE ATT&CK technique."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO attack_techniques 
                (session_id, technique_id, technique_name, tactic, confidence, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, technique_id, technique_name, tactic, confidence, evidence))
            conn.commit()
    
    def get_attack_techniques(self, session_id: Optional[str] = None) -> List[Dict]:
        """Retrieve detected attack techniques."""
        with self.get_connection() as conn:
            if session_id:
                results = conn.execute("""
                    SELECT * FROM attack_techniques 
                    WHERE session_id = ?
                    ORDER BY detected_at DESC
                """, (session_id,)).fetchall()
            else:
                results = conn.execute("""
                    SELECT * FROM attack_techniques 
                    ORDER BY detected_at DESC
                """).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== STATE SNAPSHOTS ====================
    
    def create_snapshot(self, session_id: str) -> str:
        """Create a complete state snapshot for rollback capability."""
        with self.get_connection() as conn:
            # Gather all state data
            snapshot_data = {
                'filesystem': [dict(row) for row in conn.execute(
                    "SELECT * FROM filesystem WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'processes': [dict(row) for row in conn.execute(
                    "SELECT * FROM processes WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'environment': [dict(row) for row in conn.execute(
                    "SELECT * FROM environment_vars WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'logs': [dict(row) for row in conn.execute(
                    "SELECT * FROM system_logs WHERE session_id = ?", 
                    (session_id,)).fetchall()],
            }
            
            snapshot_json = json.dumps(snapshot_data, default=str)
            checksum = hashlib.sha256(snapshot_json.encode()).hexdigest()
            
            conn.execute("""
                INSERT INTO state_snapshots 
                (session_id, snapshot_data, checksum)
                VALUES (?, ?, ?)
            """, (session_id, snapshot_json, checksum))
            conn.commit()
            
            return checksum
    
    def get_session_state(self, session_id: str) -> Dict:
        """Get complete current state for a session (for AI context)."""
        with self.get_connection() as conn:
            state = {
                'session_info': dict(conn.execute(
                    "SELECT * FROM sessions WHERE session_id = ?", 
                    (session_id,)).fetchone() or {}),
                'filesystem_count': conn.execute(
                    "SELECT COUNT(*) as count FROM filesystem WHERE session_id = ?", 
                    (session_id,)).fetchone()['count'],
                'process_count': conn.execute(
                    "SELECT COUNT(*) as count FROM processes WHERE session_id = ?", 
                    (session_id,)).fetchone()['count'],
                'recent_commands': self.get_command_history(session_id, limit=10),
                'environment': {row['key']: row['value'] for row in conn.execute(
                    "SELECT key, value FROM environment_vars WHERE session_id = ?", 
                    (session_id,)).fetchall()},
            }
            
            return state
