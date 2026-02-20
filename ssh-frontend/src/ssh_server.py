import asyncssh
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict
import aiohttp
import json

logger = logging.getLogger(__name__)

class HoneypotSSHServer(asyncssh.SSHServer):
    """
    SSH server that accepts all connections and logs credentials.
    """
    
    def __init__(self, ai_engine_url: str):
        self.ai_engine_url = ai_engine_url
        self.sessions = {}
    
    def connection_made(self, conn):
        """Called when connection is established."""
        logger.info(f"SSH connection from {conn.get_extra_info('peername')[0]}")
    
    def connection_lost(self, exc):
        """Called when connection is closed."""
        if exc:
            logger.error(f"SSH connection error: {exc}")
    
    def begin_auth(self, username):
        """Start authentication process - accept any username."""
        logger.info(f"Authentication attempt for user: {username}")
        return True
    
    def password_auth_supported(self):
        """Indicate that password authentication is supported."""
        return True
    
    def validate_password(self, username, password):
        """Accept any password but log credentials."""
        logger.info(f"Login attempt - User: {username}, Password: {password}")
        # Always accept to maintain deception
        return True


class HoneypotSSHSession(asyncssh.SSHServerSession):
    """
    Handles an individual SSH session with AI-driven responses.
    """
    
    def __init__(self, ai_engine_url: str, sandbox_url: str):
        self.ai_engine_url = ai_engine_url
        self.sandbox_url = sandbox_url
        self.session_id = str(uuid.uuid4())
        self.username = None
        self.source_ip = None
        self.command_count = 0
        self.current_directory = '/root'
        self.environment = {
            'HOME': '/root',
            'USER': 'root',
            'SHELL': '/bin/bash',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        }
        
        # Terminal state
        self.term_type = 'xterm-256color'
        self.term_size = (80, 24)
        
        logger.info(f"Created session {self.session_id}")
    
    def connection_made(self, chan):
        """Called when session channel is opened."""
        self._chan = chan
    
    async def _send(self, data: str):
        """Send data to client."""
        if data:
            self._chan.write(data)
    
    async def _create_session_in_sandbox(self):
        """Initialize session in sandbox database."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.sandbox_url}/sessions/",
                    json={
                        'session_id': self.session_id,
                        'source_ip': self.source_ip,
                        'protocol': 'ssh',
                        'username': self.username,
                        'password': ''  # Already logged
                    }
                ) as resp:
                    if resp.status == 200:
                        logger.info(f"Session {self.session_id} created in sandbox")
                    else:
                        logger.error(f"Failed to create sandbox session: {await resp.text()}")
        except Exception as e:
            logger.error(f"Error creating sandbox session: {e}")
    
    async def session_started(self):
        """Called when session starts - show fake shell prompt."""
        # Get connection info
        conn = self._chan.get_connection()
        self.source_ip = conn.get_extra_info('peername')[0]
        self.username = conn.get_extra_info('username', 'root')
        
        # Create session in sandbox
        await self._create_session_in_sandbox()
        
        # Send welcome banner
        await self._send("Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)\n\n")
        await self._send(" * Documentation:  https://help.ubuntu.com\n")
        await self._send(" * Management:     https://landscape.canonical.com\n")
        await self._send(" * Support:        https://ubuntu.com/advantage\n\n")
        await self._send("Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y") + f" from {self.source_ip}\n")
        
        # Show prompt
        await self._send_prompt()
    
    async def _send_prompt(self):
        """Send shell prompt."""
        prompt = f"{self.username}@ubuntu-server:{self.current_directory}$ "
        await self._send(prompt)
    
    def data_received(self, data, datatype):
        """Handle incoming data (commands)."""
        try:
            # Decode command
            command = data.decode('utf-8', errors='ignore').strip()
            
            # Handle special keys
            if command == '\x03':  # Ctrl+C
                asyncio.create_task(self._send("\n"))
                asyncio.create_task(self._send_prompt())
                return
            
            if command == '\x04':  # Ctrl+D (EOF)
                self._chan.exit(0)
                return
            
            if not command:
                asyncio.create_task(self._send_prompt())
                return
            
            # Process command
            asyncio.create_task(self._process_command(command))
            
        except Exception as e:
            logger.error(f"Error processing data: {e}")
    
    async def _process_command(self, command: str):
        """Process a command using AI engine."""
        try:
            self.command_count += 1
            logger.info(f"Session {self.session_id} - Command #{self.command_count}: {command}")
            
            # Send newline (echo command)
            await self._send("\n")
            
            # Handle built-in commands first
            if command.startswith('cd '):
                await self._handle_cd(command)
                await self._send_prompt()
                return
            
            if command == 'exit' or command == 'logout':
                await self._send("logout\n")
                self._chan.exit(0)
                return
            
            # Get current state from sandbox
            state_context = await self._get_sandbox_state()
            
            # Build context for AI
            context = {
                'session_id': self.session_id,
                'command': command,
                'current_directory': self.current_directory,
                'username': self.username,
                'hostname': 'ubuntu-server',
                'environment': self.environment,
                'recent_commands': state_context.get('recent_commands', [])
            }
            
            # Call AI engine to generate response
            start_time = datetime.now()
            response_data = await self._call_ai_engine(context)
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            output = response_data.get('output', '')
            exit_code = response_data.get('exit_code', 0)
            state_mutations = response_data.get('state_mutations', {})
            
            # Apply state mutations to sandbox
            await self._apply_state_mutations(state_mutations)
            
            # Record command in history
            await self._record_command(command, output, exit_code, duration_ms)
            
            # Send output to client
            if output:
                await self._send(output)
                if not output.endswith('\n'):
                    await self._send('\n')
            
            # Send prompt
            await self._send_prompt()
            
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            await self._send("bash: command processing error\n")
            await self._send_prompt()
    
    async def _call_ai_engine(self, context: Dict) -> Dict:
        """Call AI engine to generate command response."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ai_engine_url}/process",
                    json=context,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.error(f"AI engine error: {await resp.text()}")
                        return {'output': 'Command not found', 'exit_code': 127}
        except asyncio.TimeoutError:
            logger.error("AI engine timeout")
            return {'output': 'Command timed out', 'exit_code': 124}
        except Exception as e:
            logger.error(f"Error calling AI engine: {e}")
            return {'output': 'bash: command error', 'exit_code': 1}
    
    async def _get_sandbox_state(self) -> Dict:
        """Get current session state from sandbox."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.sandbox_url}/sessions/{self.session_id}/state"
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {}
        except Exception as e:
            logger.error(f"Error getting sandbox state: {e}")
            return {}
    
    async def _apply_state_mutations(self, mutations: Dict):
        """Apply state changes to sandbox."""
        try:
            async with aiohttp.ClientSession() as session:
                # Filesystem mutations
                for fs_mut in mutations.get('filesystem', []):
                    action = fs_mut['action']
                    path = fs_mut['path']
                    
                    if action in ['create', 'write']:
                        await session.post(
                            f"{self.sandbox_url}/files/{self.session_id}",
                            json={
                                'path': path,
                                'content': fs_mut.get('content', ''),
                                'permissions': fs_mut.get('permissions', '644')
                            }
                        )
                
                # Process mutations
                for proc_mut in mutations.get('processes', []):
                    if proc_mut['action'] == 'start':
                        await session.post(
                            f"{self.sandbox_url}/processes/{self.session_id}",
                            json={
                                'pid': proc_mut['pid'],
                                'name': proc_mut['name'],
                                'cmdline': proc_mut.get('cmdline', '')
                            }
                        )
                
                # Environment mutations
                for env_mut in mutations.get('environment', []):
                    self.environment[env_mut['key']] = env_mut['value']
                
                # Log mutations
                for log_mut in mutations.get('logs', []):
                    await session.post(
                        f"{self.sandbox_url}/logs/{self.session_id}",
                        json=log_mut
                    )
                    
        except Exception as e:
            logger.error(f"Error applying state mutations: {e}")
    
    async def _record_command(self, command: str, output: str, exit_code: int, duration_ms: int):
        """Record command in sandbox history."""
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.sandbox_url}/commands/{self.session_id}",
                    json={
                        'command': command,
                        'output': output,
                        'exit_code': exit_code,
                        'duration_ms': duration_ms
                    }
                )
        except Exception as e:
            logger.error(f"Error recording command: {e}")
    
    async def _handle_cd(self, command: str):
        """Handle cd command locally."""
        parts = command.split(maxsplit=1)
        if len(parts) == 1:
            # cd without args -> go to home
            self.current_directory = self.environment.get('HOME', '/root')
        else:
            target = parts[1]
            if target == '~':
                self.current_directory = self.environment.get('HOME', '/root')
            elif target == '-':
                # cd - would need history
                pass
            elif target.startswith('/'):
                self.current_directory = target
            else:
                # Relative path
                if self.current_directory.endswith('/'):
                    self.current_directory += target
                else:
                    self.current_directory += '/' + target
            
            # Normalize path
            self.current_directory = self.current_directory.replace('//', '/')
    
    def eof_received(self):
        """Handle EOF (Ctrl+D)."""
        self._chan.exit(0)
        return False
    
    def break_received(self, msec):
        """Handle break signal."""
        return False


async def start_ssh_server(host='0.0.0.0', port=2222, 
                          ai_engine_url='http://ai-engine:8002',
                          sandbox_url='http://sandbox-store:8001'):
    """
    Start the SSH honeypot server.
    """
    
    # Generate or load host key
    import os
    host_key_path = '/configs/ssh_host_key'
    
    if not os.path.exists(host_key_path):
        logger.info("Generating new SSH host key...")
        key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
        key.write_private_key(host_key_path)
    
    # Create server factory
    def session_factory():
        return HoneypotSSHSession(ai_engine_url, sandbox_url)
    
    def server_factory():
        return HoneypotSSHServer(ai_engine_url)
    
    # Start server
    await asyncssh.create_server(
        server_factory,
        host,
        port,
        server_host_keys=[host_key_path],
        session_factory=session_factory,
        encoding=None  # Handle encoding ourselves
    )
    
    logger.info(f"SSH honeypot listening on {host}:{port}")


async def main():
    """Main entry point."""
    import os
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Get configuration from environment
    host = os.getenv('SSH_HOST', '0.0.0.0')
    port = int(os.getenv('SSH_PORT', 2222))
    ai_engine_url = os.getenv('AI_ENGINE_URL', 'http://ai-engine:8002')
    sandbox_url = os.getenv('SANDBOX_URL', 'http://sandbox-store:8001')
    
    # Start server
    await start_ssh_server(host, port, ai_engine_url, sandbox_url)
    
    # Keep running
    await asyncio.Event().wait()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down SSH honeypot...")
