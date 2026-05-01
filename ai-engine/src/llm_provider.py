import os
import json
import google.generativeai as genai

class LLMProvider:
    def __init__(self, provider: str = "gemini"):
        self.provider = provider.lower()
        
        if self.provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                print("WARNING: GEMINI_API_KEY not set. Using fallback responses.")
                self.model = None
                return
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-2.5-flash-lite')

    def generate_shell_response(self, command: str, context: dict, conversation_history: list = None) -> str:
        system_prompt = f"""You are simulating a compromised Ubuntu 22.04 production server for NexoPay Inc., a payment processing startup.

CRITICAL RULES:
1. Respond ONLY with exact terminal output - no explanations, no markdown, no code blocks
2. Be consistent - same command should give similar output
3. Simulate realistic errors when appropriate
4. Keep responses under 300 characters unless it's naturally long output
5. Never break character or mention you are an AI
6. For wget/curl: simulate the download attempt with realistic output
7. For echo: just print what was asked to echo

Server identity:
- Hostname: api-prod-01
- OS: Ubuntu 22.04.3 LTS
- Role: Production payment API backend (PCI-DSS environment)
- Internal domain: nexopay.internal
- IP: 10.0.1.45

Running services:
- Node.js payment API on port 3000 (4 worker processes, PID 3100-3103)
- PostgreSQL 14 on port 5432 (db-primary.nexopay.internal)
- Redis 7 on port 6379 (cache-01.nexopay.internal)
- nginx on ports 80/443 (reverse proxy to Node.js)
- sshd on port 22

Key paths:
- /opt/nexopay/           — application root
- /opt/nexopay/config/    — secret config files (stripe.env, auth.env, database.env, aws.env)
- /opt/nexopay/data/payments.db — SQLite database
- /var/backups/nexopay_db_2026-04-28.sql — latest DB dump

payments.db schema: users, api_tokens, sessions, transactions, webhook_secrets
AWS region: us-east-1
Kubernetes cluster: eks-nexopay-prod-01.us-east-1.eks.amazonaws.com

Current user: {context.get('username', 'root')}
Current directory: {context.get('current_directory', '/root')}

Recent commands:
{json.dumps(conversation_history[-5:] if conversation_history else [], indent=2)}

Command: {command}

Respond with ONLY the terminal output:"""

        if not getattr(self, "model", None):
            import datetime
            base = command.split()[0] if command.split() else command
            args = command.split()[1:]

            if base == "wget":
                target = args[0] if args else 'http://unknown'
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                fname = target.split('/')[-1] or 'index.html'
                return (f"--{now}--  {target}\nResolving host...\nConnecting... connected.\n"
                        f"HTTP request sent, awaiting response... 200 OK\nLength: 45312 [application/octet-stream]\n"
                        f"Saving to: '{fname}'\n\n{fname}  100%[===================>]  44.25K  --.-KB/s    in 0.1s\n\n"
                        f"{now} (412 KB/s) - '{fname}' saved [45312/45312]")
            elif base == "curl":
                if any(f in command for f in ['/health', '/status']):
                    return '{"status":"ok","version":"v2.14.3","uptime":1234567}'
                return ("<html>\n<head><title>403 Forbidden</title></head>\n"
                        "<body>\n<center><h1>403 Forbidden</h1></center>\n"
                        "<hr><center>nginx/1.18.0 (Ubuntu)</center>\n</body>\n</html>")
            elif base == "nmap":
                return ("Starting Nmap 7.80 at 2026-04-29\nNmap scan report for target\n"
                        "Host is up (0.00013s latency).\n"
                        "PORT     STATE SERVICE\n"
                        "22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n"
                        "3000/tcp open  ppp\n5432/tcp open  postgresql\n6379/tcp open  redis\n"
                        "Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds")
            elif base == "netstat":
                return ("Active Internet connections (servers and established)\n"
                        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
                        "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n"
                        "tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN\n"
                        "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n"
                        "tcp6       0      0 :::22                   :::*                    LISTEN")
            elif base == "iptables":
                if "-L" in command:
                    return ("Chain INPUT (policy DROP)\n"
                            "target  prot opt source        destination\n"
                            "ACCEPT  all  --  anywhere      anywhere    state RELATED,ESTABLISHED\n"
                            "ACCEPT  tcp  --  anywhere      anywhere    tcp dpt:ssh\n"
                            "ACCEPT  tcp  --  anywhere      anywhere    tcp dpt:http\n"
                            "ACCEPT  tcp  --  anywhere      anywhere    tcp dpt:https\n"
                            "Chain FORWARD (policy DROP)\nChain OUTPUT (policy ACCEPT)")
                return ""
            elif base == "lscpu":
                return ("Architecture:            x86_64\nCPU op-mode(s):          32-bit, 64-bit\n"
                        "Byte Order:              Little Endian\nCPU(s):                  4\n"
                        "On-line CPU(s) list:     0-3\nVendor ID:               GenuineIntel\n"
                        "Model name:              Intel(R) Xeon(R) E5-2676 v3 @ 2.40GHz\n"
                        "CPU MHz:                 2400.060\nCache:                   30720 KB")
            elif base == "ping":
                target = args[0] if args else "google.com"
                return (f"PING {target} (142.251.46.238) 56(84) bytes of data.\n"
                        f"64 bytes from 142.251.46.238: icmp_seq=1 ttl=117 time=12.4 ms\n"
                        f"64 bytes from 142.251.46.238: icmp_seq=2 ttl=117 time=11.2 ms\n^C\n"
                        f"--- {target} ping statistics ---\n"
                        f"2 packets transmitted, 2 received, 0% packet loss, time 1001ms")
            elif base == "nslookup":
                target = args[0] if args else "google.com"
                return (f"Server:         10.0.0.2\nAddress:        10.0.0.2#53\n\n"
                        f"Non-authoritative answer:\nName:   {target}\nAddress: 142.251.46.238")
            elif base == "last":
                today = datetime.datetime.now().strftime('%b %d')
                return (f"root     pts/0        10.0.1.5         {today} 22:10   still logged in\n"
                        f"deploy   pts/1        10.0.1.50        {today} 18:32 - 18:45  (00:12)\n"
                        f"root     pts/0        185.220.101.45   {today} 00:22 - 00:35  (00:13)\n"
                        f"reboot   system boot  5.15.0-91-generi {today} 00:00   still running\n\n"
                        f"wtmp begins {today} 00:00:01 2026")
            elif base == "df":
                return ("Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                        "/dev/sda1      41251136  9234512  29875240  24% /\n"
                        "/dev/sdb1     103080896  4234512  93534256   5% /opt\n"
                        "tmpfs           8192000        0   8192000   0% /dev/shm")
            elif base == "free":
                return ("               total        used        free      shared  buff/cache   available\n"
                        "Mem:        16384000     5234512     3123412      102344     8026076    10876543\n"
                        "Swap:        2097148           0     2097148")
            elif base == "uptime":
                return " 00:22:14 up 18 days,  6:45,  1 user,  load average: 2.14, 1.98, 1.87"
            elif base == "ps":
                if "aux" in command:
                    return ("USER       PID %CPU %MEM    VSZ    RSS TTY  STAT START   TIME COMMAND\n"
                            "root         1  0.1  0.5  22532   9820 ?   Ss   Apr10   0:12 /sbin/init\n"
                            "root       134  0.0  0.2  72312   4512 ?   Ss   Apr10   0:00 /usr/sbin/sshd -D\n"
                            "root       892  0.1  0.3 144896   6144 ?   Ss   Apr10   0:05 nginx: master process\n"
                            "www-data   893  0.0  0.6 145231  12341 ?   S    Apr10   0:12 nginx: worker process\n"
                            "nexopay   3100  2.1  8.4 921344 172032 ?  Sl   Apr10  18:34 node /opt/nexopay/current/server.js\n"
                            "nexopay   3101  1.8  7.9 876288 163840 ?  Sl   Apr10  15:12 node /opt/nexopay/current/worker.js\n"
                            "nexopay   3102  1.6  7.8 876288 163840 ?  Sl   Apr10  14:55 node /opt/nexopay/current/worker.js\n"
                            "nexopay   3103  1.9  8.1 876288 163840 ?  Sl   Apr10  16:01 node /opt/nexopay/current/worker.js\n"
                            "postgres  2150  0.1  4.2 341248  86016 ?  S    Apr10   1:23 postgres: nexopay_app nexopay_prod\n"
                            "redis     2048  0.2  2.5 126976  51200 ?  Ssl  Apr10   0:45 /usr/bin/redis-server 127.0.0.1:6379")
                return "  PID TTY          TIME CMD\n 1562 pts/0    00:00:00 bash\n 3521 pts/0    00:00:00 ps"
            elif base == "who" or base == "w":
                today = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
                return f"root     pts/0        10.0.1.5         ({today})"
            elif base == "apt":
                if "list" in command:
                    return ("Listing... Done\n"
                            "nginx/jammy-updates,now 1.18.0-6ubuntu14.4 amd64 [installed]\n"
                            "nodejs/jammy-updates,now 20.11.0-1nodesource1 amd64 [installed]\n"
                            "postgresql-14/jammy-updates,now 14.10-0ubuntu0.22.04.1 amd64 [installed]\n"
                            "redis/jammy-updates,now 7.0.15-1 amd64 [installed]\n"
                            "openssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.6 amd64 [installed]")
                return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
            elif base == "cat":
                filename = args[0] if args else ""
                if "/etc/passwd" in filename:
                    return ("root:x:0:0:root:/root:/bin/bash\n"
                            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                            "deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n"
                            "nexopay:x:1002:1002:NexoPay:/opt/nexopay:/bin/bash\n"
                            "postgres:x:109:117:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
                            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
                if "/etc/shadow" in filename:
                    return ("root:$6$rounds=65536$rST7pKN4aFbFxs2/$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ:19855:0:99999:7:::\n"
                            "ubuntu:$6$rounds=65536$qRS8oKM3aEbExr1/$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij:19855:0:99999:7:::")
                if "/etc/hosts" in filename:
                    return ("127.0.0.1 localhost\n127.0.1.1 api-prod-01\n"
                            "10.0.1.10 db-primary.nexopay.internal\n"
                            "10.0.1.20 cache-01.nexopay.internal\n"
                            "10.0.1.5  bastion.nexopay.internal")
                return f"cat: {filename}: No such file or directory"
            elif base == "python3":
                if "-c" in command:
                    return ""
                return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux"
            elif base == "find":
                if "*.env" in command or ".env" in command:
                    return ("/opt/nexopay/config/stripe.env\n/opt/nexopay/config/auth.env\n"
                            "/opt/nexopay/config/database.env\n/opt/nexopay/config/aws.env\n"
                            "/home/deploy/.env")
                if "*.db" in command or ".db" in command:
                    return "/opt/nexopay/data/payments.db"
                filename = args[-1] if args else "."
                return f"{filename}\n{filename}/config.json\n{filename}/server.js"
            elif base == "scp":
                return ("sending incremental file list\npayments.db\n\n"
                        "   2,048,576 100%    4.21MB/s    0:00:00 (xfr#1, to-chk=0/1)\n\n"
                        "sent 2,048,648 bytes  received 35 bytes  4,097,366.00 bytes/sec\n"
                        "total size is 2,048,576  speedup is 1.00")
            elif base == "crontab":
                if "-l" in command:
                    return ("# m h  dom mon dow   command\n"
                            "0 3 * * * /etc/cron.daily/nexopay-backup >> /var/log/nexopay-backup.log 2>&1\n"
                            "0 4 * * 0 /usr/sbin/certbot renew --quiet\n"
                            "*/5 * * * * /usr/bin/node /opt/nexopay/scripts/health-check.js")
                return ""
            elif base == "echo":
                return " ".join(args).strip('"').strip("'")
            elif base in ["whoami", "id", "uname"]:
                if base == "uname" and "-a" in command:
                    return "Linux api-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
                return "root"
            else:
                return f"bash: {base}: command not found"

        try:
            response = self.model.generate_content(
                system_prompt,
                generation_config={"max_output_tokens": 200, "temperature": 0.2}
            )
            return response.text.strip()
        except Exception as e:
            print(f"Gemini error: {e}")
            base = command.split()[0] if command.split() else command
            return f"bash: {base}: command not found"
