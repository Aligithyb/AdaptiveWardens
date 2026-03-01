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
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", None)  # NEW: Optional AI
SSH_BANNER = """Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar  1 11:22:33 UTC 2026

  System load:  0.05               Processes:             156
  Usage of /:   22.4% of 38.60GB   Users logged in:       0
  Memory usage: 15%                IPv4 address for eth0: 10.0.2.15
  Swap usage:   0%

0 updates can be applied immediately.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Mar 1 10:10:01 2026 from 192.168.1.50
"""

# Keep some static responses for speed (non-filesystem commands)
STATIC_RESPONSES = {
    "whoami": lambda ctx: ctx.get("username", "root"),
    "id": lambda ctx: "uid=0(root) gid=0(root) groups=0(root)",
    "hostname": lambda ctx: "ubuntu-server",
    "uname -a": lambda ctx: "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "uname": lambda ctx: "Linux",
    "ifconfig": lambda ctx: "eth0: inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        inet6 fe80::a00:27ff:fe8f:1234  prefixlen 64  scopeid 0x20<link>\n        RX packets 12345  bytes 1234567 (1.2 MB)\n        TX packets 5432   bytes 987654  (987.6 KB)",
    "df -h": lambda ctx: "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G  8.4G   30G  22% /\ntmpfs           3.9G     0  3.9G   0% /dev/shm\n/dev/sdb1       100G   12G   83G  13% /opt/corp",
    "df": lambda ctx: "Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/sda1       41251136  8794112  30340240  23% /\ntmpfs            4031640        0   4031640   0% /dev/shm\n/dev/sdb1      103080896 12582912  85241856  13% /opt/corp",
    "free -m": lambda ctx: "               total        used        free      shared  buff/cache   available\nMem:            7942         842        5120          12        1980        6850\nSwap:           2047           0        2047",
    "free": lambda ctx: "               total        used        free      shared  buff/cache   available\nMem:         8132800      862208     5242880       12288     2027712     7014400\nSwap:        2097148           0     2097148",
    "uptime": lambda ctx: " 10:20:05 up 12 days,  3:14,  1 user,  load average: 0.05, 0.08, 0.12",
    "lsblk": lambda ctx: "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nsda      8:0    0   40G  0 disk \n└─sda1   8:1    0   40G  0 part /\nsdb      8:16   0  100G  0 disk \n└─sdb1   8:17   0  100G  0 part /opt/corp",
    "mount": lambda ctx: "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n/dev/sdb1 on /opt/corp type ext4 (rw,relatime)",
}

def get_fallback(cmd: str, ctx: dict) -> str:
    base = cmd.split()[0] if cmd.split() else cmd
    fallbacks = {"wget": "Connection refused.", "curl": "curl: (7) Failed to connect", "nmap": "Host seems down"}
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
        self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
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
                self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
                continue
            
            # Handle comments
            cmd = raw_line.split('#')[0].strip()
            if not cmd:
                # Just a comment - show prompt
                self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
                continue
            
            if cmd in ["exit", "logout"]:
                self.chan.write("\nlogout\n")
                await self._close()
                self.chan.close()
                return

            # Normal command processing
            if cmd.startswith("cd "):
                self._handle_cd(cmd)
                self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
            elif cmd.startswith("ls") or cmd.startswith("cat ") or cmd.startswith("touch ") or cmd.startswith("mkdir "):
                await self._handle_fs_command(cmd)
            elif cmd.startswith("ps"):
                await self._handle_ps_command(cmd)
            elif cmd == "env":
                await self._handle_env_command()
            else:
                await self._handle_generic_command(cmd)

    def data_received(self, data, datatype):
        asyncio.create_task(self._process_command_string(data))
    
    async def _handle_generic_command(self, cmd: str):
        """Handle commands: static -> AI -> fallback"""
        # Check static responses first
        cmd_lower = cmd.lower()
        output = None
        for pattern, handler in STATIC_RESPONSES.items():
            if cmd_lower == pattern or cmd_lower.startswith(pattern + " "):
                output = handler(self.context)
                break
        
        # NEW: If not static and AI is available, try AI
        if output is None and AI_ENGINE_URL:
            output = await self._get_ai_response(cmd)
        
        # Fallback
        if output is None:
            output = get_fallback(cmd, self.context)
        
        if output:
            self.chan.write(output + "\n")
        
        # Track command history for AI context
        self.command_history.append({"command": cmd, "output": output})
        
        asyncio.create_task(self._record(cmd, output))
        self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
    
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
        self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
    
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
        self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
    
    async def _handle_env_command(self):
        """Handle env command using database"""
        output = ""
        
        if self.context.get("environment"):
            for key, value in self.context["environment"].items():
                output += f"{key}={value}\n"
        else:
            output = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nUSER=root\nSHELL=/bin/bash"
        
        self.chan.write(output + "\n")
        self.command_history.append({"command": "env", "output": output})
        asyncio.create_task(self._record("env", output))
        self.chan.write(f"{self.username}@ubuntu-server:{self.current_directory}$ ")
    
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
        print(f"🔑 Login: {username}/{password}")
        return True
    
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
