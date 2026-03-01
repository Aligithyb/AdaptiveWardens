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
        system_prompt = f"""You are simulating a compromised Ubuntu 22.04 corporate server shell.

CRITICAL RULES:
1. Respond ONLY with exact terminal output - no explanations, no markdown, no code blocks
2. Be consistent - same command should give similar output
3. Simulate realistic errors when appropriate
4. Keep responses under 300 characters unless it's naturally long output
5. Never break character or mention you are an AI
6. For wget/curl: simulate the download attempt with realistic output
7. For echo: just print what was asked to echo

Current context:
- Username: {context.get('username', 'root')}
- Current directory: {context.get('current_directory', '/root')}
- Hostname: ubuntu-server
- OS: Ubuntu 22.04.3 LTS

Recent commands:
{json.dumps(conversation_history[-5:] if conversation_history else [], indent=2)}

Command: {command}

Respond with ONLY the terminal output:"""

        if not getattr(self, "model", None):
            base = command.split()[0] if command.split() else command
            args = command.split()[1:]
            
            if base == "wget":
                target = args[0] if args else 'http://unknown'
                import datetime
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return f"--{now}--  {target}\nResolving host...\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 45 [text/plain]\nSaving to: 'payload.sh'\n\npayload.sh            100%[===================>]      45  --.-KB/s    in 0s      \n\n{now} (4.50 MB/s) - 'payload.sh' saved [45/45]"
            elif base == "curl":
                return "<html>\n<head><title>403 Forbidden</title></head>\n<body>\n<center><h1>403 Forbidden</h1></center>\n<hr><center>nginx</center>\n</body>\n</html>"
            elif base == "nmap":
                return "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-01\nNmap scan report for target\nHost is up (0.00013s latency).\nNot shown: 998 closed ports\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n\nNmap done: 1 IP address (1 host up) scanned in 0.06 seconds"
            elif base == "netstat":
                return "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State      \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \ntcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     "
            elif base == "iptables":
                if "-L" in command:
                    return "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n\nChain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination         \n\nChain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination         "
                return ""
            elif base == "lscpu":
                return "Architecture:            x86_64\nCPU op-mode(s):        32-bit, 64-bit\nAddress sizes:         39 bits physical, 48 bits virtual\nByte Order:            Little Endian\nCPU(s):                  4\nOn-line CPU(s) list:   0-3\nVendor ID:               GenuineIntel\nModel name:              Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz"
            elif base == "ping":
                target = args[0] if args else "google.com"
                return f"PING {target} (142.251.46.238) 56(84) bytes of data.\n64 bytes from 142.251.46.238: icmp_seq=1 ttl=117 time=12.4 ms\n64 bytes from 142.251.46.238: icmp_seq=2 ttl=117 time=11.2 ms\n^C\n--- {target} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 11.234/11.832/12.431/0.598 ms"
            elif base == "nslookup":
                target = args[0] if args else "google.com"
                return f"Server:         8.8.8.8\nAddress:        8.8.8.8#53\n\nNon-authoritative answer:\nName:   {target}\nAddress: 142.251.46.238"
            elif base == "last":
                import datetime
                today = datetime.datetime.now().strftime('%b %d')
                return f"root     pts/0        192.168.1.50     {today} 10:10   still logged in\nreboot   system boot  5.15.0-91-generi {today} 09:45   still running\n\nwtmp begins {today} 09:45:22 2026"
            elif base == "df":
                return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1      40595636 8234512  30274712  22% /\ntmpfs             65536       0     65536   0% /dev/shm"
            elif base == "free":
                return "              total        used        free      shared  buff/cache   available\nMem:        8163240     1234512     5023412      102344     1905316     6543212\nSwap:       2097148           0     2097148"
            elif base == "uptime":
                return " 11:22:33 up 2 days, 14:22,  1 user,  load average: 0.05, 0.08, 0.12"
            elif base == "ps":
                if "aux" in command:
                    return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.1  0.5  22532  9820 ?        Ss   09:45   0:01 /sbin/init\nroot       134  0.0  0.2  72312  4512 ?        Ss   09:45   0:00 /usr/sbin/sshd -D\nwww-data   893  0.0  0.6 145231 12341 ?        S    10:30   0:02 nginx: worker process"
                return "  PID TTY          TIME CMD\n 1562 pts/0    00:00:00 bash\n 3521 pts/0    00:00:00 ps"
            elif base == "who" or base == "w":
                import datetime
                today = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
                return f"root     pts/0        192.168.1.50     ({today})"
            elif base == "apt":
                if "list" in command:
                    return "Listing... Done\nnginx/jammy-updates,now 1.18.0-6ubuntu14.4 amd64 [installed]\nopenssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.6 amd64 [installed]\npython3/jammy,now 3.10.6-1 amd64 [installed]"
                return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
            elif base == "cat":
                filename = args[0] if args else ""
                if "/etc/passwd" in filename:
                    return "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nadmin:x:1001:1001:Admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
                if "/etc/shadow" in filename:
                    return "root:$6$rounds=65536$fake_salt$fake_hash:19000:0:99999:7:::\nubuntu:$6$fake_salt$fake_hash:19000:0:99999:7:::"
                if "/etc/hosts" in filename:
                     return "127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n10.0.5.21 vpn.corp.local\n10.0.5.22 db.corp.local"
                return f"cat: {filename}: No such file or directory"
            elif base == "python3":
                if "-c" in command:
                    return "ls" if 'os.system("ls")' in command else ""
                return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux"
            elif base == "find":
                filename = args[-1] if args else "."
                return f"{filename}\n{filename}/config.json\n{filename}/main.py"
            elif base == "scp":
                return "sending incremental file list\nshadow\n\n          1,532 100%    1.46MB/s    0:00:00 (xfr#1, to-chk=0/1)\n\nsent 1,612 bytes  received 35 bytes  3,294.00 bytes/sec\ntotal size is 1,532  speedup is 0.93"
            elif base == "crontab":
                if "-l" in command:
                    return "# m h  dom mon dow   command\n0 5 * * * /usr/bin/backup.sh > /dev/null 2>&1"
                return ""
            elif base == "echo":
                return " ".join(args).strip('"').strip("'")
            elif base in ["whoami", "id", "uname"]:
                if base == "uname" and "-a" in command:
                    return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
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
