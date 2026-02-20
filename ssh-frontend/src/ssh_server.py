#!/usr/bin/env python3
"""
SSH Honeypot Frontend - Static Response Version
Works with Sandbox Store database, no AI needed yet
"""
import asyncio
import asyncssh
import uuid
import sys
import os
import httpx
from typing import Optional
from datetime import datetime

# Configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://localhost:8001")

# SSH Banner
SSH_BANNER = """
Ubuntu 22.04.3 LTS
"""

# ========================================
# STATIC COMMAND RESPONSES
# These work WITHOUT any AI - instant responses
# ========================================
STATIC_RESPONSES = {
    "whoami":           lambda ctx: ctx.get("username", "root"),
    "id":               lambda ctx: "uid=0(root) gid=0(root) groups=0(root)",
    "pwd":              lambda ctx: ctx.get("current_directory", "/root"),
    "hostname":         lambda ctx: "ubuntu-server",
    "uname -a":         lambda ctx: "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname":            lambda ctx: "Linux",
    "echo $USER":       lambda ctx: ctx.get("username", "root"),
    "echo $HOME":       lambda ctx: ctx.get("environment", {}).get("HOME", "/root"),
    "echo $SHELL":      lambda ctx: "/bin/bash",
    "echo $PATH":       lambda ctx: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "date":             lambda ctx: datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"),
    "uptime":           lambda ctx: f" {datetime.now().strftime('%H:%M:%S')} up 47 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01",
    "w":                lambda ctx: f"{ctx.get('username', 'root')} pts/0 {ctx.get('source_ip', '0.0.0.0')} {datetime.now().strftime('%H:%M')} 0.00s 0.00s -bash",
    "who":              lambda ctx: f"{ctx.get('username', 'root')} pts/0 {datetime.now().strftime('%Y-%m-%d %H:%M')} ({ctx.get('source_ip', '0.0.0.0')})",
    
    "ls":               lambda ctx: "Desktop  Documents  Downloads  anaconda3  .bash_history  .bashrc  .ssh",
    "ls -l":            lambda ctx: "total 48\ndrwxr-xr-x 2 root root 4096 Feb 17 14:32 Desktop\ndrwxr-xr-x 2 root root 4096 Feb 17 14:32 Documents\ndrwxr-xr-x 2 root root 4096 Feb 17 14:32 Downloads\ndrwxr-xr-x 5 root root 4096 Feb 10 09:15 anaconda3\n-rw------- 1 root root 1247 Feb 17 14:20 .bash_history\n-rw-r--r-- 1 root root 3106 Oct 15 2021 .bashrc\ndrwx------ 2 root root 4096 Feb 10 09:15 .ssh",
    "ls -la":           lambda ctx: "total 48\ndrwx------ 6 root root 4096 Feb 17 14:32 .\ndrwxr-xr-x 20 root root 4096 Feb 17 10:12 ..\n-rw------- 1 root root 1247 Feb 17 14:20 .bash_history\n-rw-r--r-- 1 root root 3106 Oct 15 2021 .bashrc\ndrwx------ 2 root root 4096 Feb 10 09:15 .ssh\ndrwxr-xr-x 2 root root 4096 Feb 17 14:32 Desktop\ndrwxr-xr-x 2 root root 4096 Feb 17 14:32 Documents",
    "ls /":             lambda ctx: "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "ls -la /":         lambda ctx: "total 84\ndrwxr-xr-x  20 root root  4096 Feb 17 10:12 .\ndrwxr-xr-x  20 root root  4096 Feb 17 10:12 ..\ndrwxr-xr-x   2 root root  4096 Feb 10 14:23 bin\ndrwxr-xr-x   3 root root  4096 Feb 10 14:28 boot\ndrwxr-xr-x  18 root root  3840 Feb 17 10:12 dev\ndrwxr-xr-x 130 root root 12288 Feb 17 10:12 etc\ndrwxr-xr-x   3 root root  4096 Feb 10 14:23 home",
    
    "cat /etc/hostname": lambda ctx: "ubuntu-server",
    "cat /etc/os-release": lambda ctx: 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\nVERSION_ID="22.04"',
    "cat /etc/passwd":  lambda ctx: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    
    "ps":               lambda ctx: "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps",
    "ps aux":           lambda ctx: "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  22540  9876 ?        Ss   Feb10   0:02 /sbin/init\nroot       134  0.0  0.2  15234  8765 ?        Ss   Feb10   0:01 /usr/sbin/sshd -D\nroot       567  0.0  0.1  12345  6789 ?        Ss   Feb10   0:00 /usr/sbin/cron -f\nroot      1234  0.0  0.1  23456  7654 pts/0    Ss   14:32   0:00 -bash\nroot      5678  0.0  0.0  12345  3456 pts/0    R+   14:35   0:00 ps aux",
    
    "netstat -an":      lambda ctx: "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0     64 10.0.2.15:22            10.0.2.2:54321          ESTABLISHED",
    "ss -tlnp":         lambda ctx: "State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port\nLISTEN  0       128     0.0.0.0:22          0.0.0.0:*\nLISTEN  0       128     0.0.0.0:80          0.0.0.0:*",
    
    "ifconfig":         lambda ctx: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        inet6 fe80::a00:27ff:fe3f:4a8b  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:3f:4a:8b  txqueuelen 1000  (Ethernet)",
    "ip a":             lambda ctx: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0",
    
    "env":              lambda ctx: f"HOME={ctx.get('environment', {}).get('HOME', '/root')}\nUSER={ctx.get('username', 'root')}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nSHELL=/bin/bash\nPWD={ctx.get('current_directory', '/root')}\nTERM=xterm-256color\nLANG=en_US.UTF-8",
    
    "history":          lambda ctx: "    1  ls\n    2  cd /tmp\n    3  wget http://update.server.com/patch.sh\n    4  chmod +x patch.sh\n    5  ./patch.sh\n    6  history",
    
    "crontab -l":       lambda ctx: "# m h dom mon dow command\n*/5 * * * * /usr/local/bin/backup.sh\n0 2 * * * /usr/local/bin/cleanup.sh",
    
    "sudo -l":          lambda ctx: "Matching Defaults entries for root on ubuntu-server:\n    env_reset, mail_badpass\n\nUser root may run the following commands on ubuntu-server:\n    (ALL : ALL) ALL",
    
    "cat /etc/shadow":  lambda ctx: "cat: /etc/shadow: Permission denied",  # Trick them
    
    "clear":            lambda ctx: "",
    "exit":             lambda ctx: "",  # Handled separately
    "logout":           lambda ctx: "",  # Handled separately
}

# Fallback for unknown commands
def get_fallback_response(command: str, ctx: dict) -> str:
    """Generate a fallback response for unknown commands."""
    cmd_base = command.split()[0] if command.split() else command
    
    # Common fallbacks
    fallbacks = {
        "wget":    "Connecting to host... failed: Connection refused.",
        "curl":    "curl: (7) Failed to connect to host: Connection refused",
        "nmap":    "Starting Nmap 7.80 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn",
        "nc":      "nc: connect to host port 80 (tcp) failed: Connection refused",
        "python":  "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux",
        "python3": "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux",
        "pip":     "pip 22.0.2 from /usr/lib/python3/dist-packages/pip (python 3.10)",
        "ssh":     "ssh: connect to host: Connection timed out",
        "cat":     f"cat: {command.split()[1] if len(command.split()) > 1 else 'file'}: No such file or directory",
        "cd":      "",  # Handled separately
        "mkdir":   "",
        "touch":   "",
        "rm":      "",
        "cp":      "",
        "mv":      "",
        "nano":    "",
        "vim":     "",
        "vi":      "",
    }
    
    return fallbacks.get(cmd_base, f"bash: {cmd_base}: command not found")


# ========================================
# SSH SERVER SESSION HANDLER
# ========================================
class HoneypotSSHSession(asyncssh.SSHServerSession):
    """Handles individual SSH session interactions."""
    
    def __init__(self):
        self.session_id = None
        self.username = None
        self.source_ip = None
        self.current_directory = "/root"
        self.context = {}
        self.http_client = httpx.AsyncClient(timeout=5.0)
    
    def connection_made(self, chan):
        """Called when the SSH channel is opened."""
        self.chan = chan
    
    def shell_requested(self):
        """Called when user requests a shell."""
        return True
    
    async def session_started(self):
        """Called when the session starts (after authentication)."""
        # Send banner
        self.chan.write(SSH_BANNER)
        
        # Initialize session in database
        await self.init_session()
        
        # Show prompt
        await self.show_prompt()
    
    async def init_session(self):
        """Create session in sandbox database."""
        self.session_id = str(uuid.uuid4())
        
        try:
            response = await self.http_client.post(
                f"{SANDBOX_URL}/sessions/",
                json={
                    "session_id": self.session_id,
                    "source_ip": self.source_ip,
                    "protocol": "ssh",
                    "username": self.username,
                    "password": "*** (logged in database)"
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Session created: {self.session_id} from {self.source_ip}")
                
                # Get session state (includes environment, filesystem, etc.)
                state_response = await self.http_client.get(
                    f"{SANDBOX_URL}/sessions/{self.session_id}/state"
                )
                
                if state_response.status_code == 200:
                    state = state_response.json()
                    self.context = {
                        "session_id": self.session_id,
                        "username": self.username,
                        "source_ip": self.source_ip,
                        "current_directory": self.current_directory,
                        "environment": state.get("environment", {}),
                        "recent_commands": state.get("recent_commands", [])
                    }
                    print(f"📦 Session state loaded for {self.session_id}")
            else:
                print(f"⚠️  Failed to create session: {response.text}")
        
        except Exception as e:
            print(f"❌ Error creating session: {e}")
    
    async def show_prompt(self):
        """Display command prompt."""
        prompt = f"{self.username}@ubuntu-server:{self.current_directory}$ "
        self.chan.write(prompt)
    
    async def data_received(self, data, datatype):
        """Called when the user types something."""
        command = data.strip()
        
        if not command:
            await self.show_prompt()
            return
        
        # Handle built-in commands
        if command in ["exit", "logout"]:
            self.chan.write("\nlogout\n")
            await self.close_session()
            self.chan.close()
            return
        
        if command.startswith("cd "):
            await self.handle_cd(command)
            await self.show_prompt()
            return
        
        # Process command
        output = await self.process_command(command)
        
        # Display output
        if output:
            self.chan.write(output + "\n")
        
        # Record in database
        await self.record_command(command, output)
        
        # Show next prompt
        await self.show_prompt()
    
    async def handle_cd(self, command: str):
        """Handle directory change."""
        parts = command.split()
        if len(parts) == 1:
            self.current_directory = self.context.get("environment", {}).get("HOME", "/root")
        else:
            new_dir = parts[1]
            if new_dir.startswith("/"):
                self.current_directory = new_dir
            elif new_dir == "..":
                if self.current_directory != "/":
                    self.current_directory = "/".join(self.current_directory.rstrip("/").split("/")[:-1]) or "/"
            else:
                self.current_directory = f"{self.current_directory.rstrip('/')}/{new_dir}"
        
        self.context["current_directory"] = self.current_directory
    
    async def process_command(self, command: str) -> str:
        """Process a command and return output."""
        command_lower = command.strip().lower()
        
        # Check static responses first
        for pattern, handler in STATIC_RESPONSES.items():
            if command_lower == pattern or command_lower.startswith(pattern + " "):
                return handler(self.context)
        
        # Fallback for unknown commands
        return get_fallback_response(command, self.context)
    
    async def record_command(self, command: str, output: str):
        """Record command in database."""
        try:
            await self.http_client.post(
                f"{SANDBOX_URL}/commands/{self.session_id}",
                json={
                    "command": command,
                    "output": output,
                    "exit_code": 0,
                    "duration_ms": 10
                }
            )
        except Exception as e:
            print(f"⚠️  Failed to record command: {e}")
    
    async def close_session(self):
        """Close session in database."""
        try:
            await self.http_client.delete(
                f"{SANDBOX_URL}/sessions/{self.session_id}"
            )
            print(f"🔒 Session closed: {self.session_id}")
        except Exception as e:
            print(f"⚠️  Failed to close session: {e}")
        
        await self.http_client.aclose()


# ========================================
# SSH SERVER
# ========================================
class HoneypotSSHServer(asyncssh.SSHServer):
    """SSH server that accepts all authentication attempts."""
    
    def __init__(self):
        self.sessions = {}
    
    def connection_made(self, conn):
        """Called when a new connection is made."""
        peername = conn.get_extra_info('peername')
        source_ip = peername[0] if peername else "unknown"
        print(f"🔌 New connection from {source_ip}")
    
    def connection_lost(self, exc):
        """Called when connection is lost."""
        print(f"🔌 Connection closed")
    
    def begin_auth(self, username):
        """Begin authentication - log the username."""
        print(f"🔐 Auth attempt: username={username}")
        return True
    
    def password_auth_supported(self):
        """Enable password authentication."""
        return True
    
    def validate_password(self, username, password):
        """Accept ALL passwords and log them."""
        print(f"🔑 Login: username={username}, password={password}")
        return True  # Accept everything!
    
    def session_requested(self):
        """Create a new session handler."""
        session = HoneypotSSHSession()
        
        # Get connection info
        conn = asyncssh.get_current_connection()
        peername = conn.get_extra_info('peername')
        
        session.username = conn.get_extra_info('username') or "root"
        session.source_ip = peername[0] if peername else "unknown"
        
        return session


async def start_server():
    """Start the SSH honeypot server."""
    print("=" * 60)
    print("🍯 AdaptiveWardens SSH Honeypot")
    print("=" * 60)
    print(f"📍 Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"🗄️  Sandbox Store: {SANDBOX_URL}")
    print("=" * 60)
    print("⚠️  ACCEPTING ALL PASSWORDS - This is a honeypot!")
    print("=" * 60)
    
    # Check if sandbox is reachable
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{SANDBOX_URL}/health")
            if response.status_code == 200:
                print("✅ Sandbox Store is reachable")
            else:
                print("⚠️  Sandbox Store responded but health check failed")
    except Exception as e:
        print(f"❌ Cannot reach Sandbox Store: {e}")
        print("⚠️  Starting anyway, but database operations will fail")
    
    print("\n🚀 Server starting...\n")
    
    # Generate host key
    await asyncssh.create_server(
        HoneypotSSHServer,
        LISTEN_HOST,
        LISTEN_PORT,
        server_host_keys=['ssh_host_key'],
        process_factory=None
    )
    
    # Run forever
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)
