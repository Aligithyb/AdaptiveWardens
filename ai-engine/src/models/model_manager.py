import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    AutoModelForSeq2SeqLM,
    pipeline
)
import logging
from typing import Dict, List, Optional
import json
import re
from functools import lru_cache

logger = logging.getLogger(__name__)

class AIModelManager:
    """
    Manages AI models for command response generation.
    Uses transformer models with custom prompting for cybersecurity context.
    """
    
    def __init__(self, model_name: str = "distilgpt2", device: str = "cpu"):
        self.model_name = model_name
        self.device = device
        self.tokenizer = None
        self.model = None
        self.response_cache = {}
        
        self._load_model()
    
    def _load_model(self):
        """Load the transformer model and tokenizer."""
        logger.info(f"Loading model: {self.model_name}")
        
        try:
            # For smaller, faster models suitable for CPU
            if "gpt" in self.model_name.lower():
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float32,  # Use float32 for CPU
                ).to(self.device)
                
                # Set pad token if not set
                if self.tokenizer.pad_token is None:
                    self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # For seq2seq models like T5
            elif "t5" in self.model_name.lower() or "flan" in self.model_name.lower():
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModelForSeq2SeqLM.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float32,
                ).to(self.device)
            
            else:
                # Generic fallback
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float32,
                ).to(self.device)
            
            self.model.eval()  # Set to evaluation mode
            logger.info("Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    @lru_cache(maxsize=1000)
    def _get_cached_response(self, cache_key: str) -> Optional[str]:
        """Check if we have a cached response for common commands."""
        return self.response_cache.get(cache_key)
    
    def _build_prompt(self, command: str, context: Dict) -> str:
        """
        Build a context-aware prompt for the AI model.
        
        Args:
            command: The attacker's command
            context: Dictionary containing:
                - current_directory: Current working directory
                - username: Current user
                - hostname: System hostname
                - recent_commands: List of recent commands
                - filesystem_state: Relevant filesystem info
                - process_state: Relevant process info
        """
        
        # Extract context
        cwd = context.get('current_directory', '/root')
        user = context.get('username', 'root')
        hostname = context.get('hostname', 'ubuntu-server')
        recent = context.get('recent_commands', [])
        
        # Build context string
        context_str = f"""You are simulating a Linux terminal session.
Current user: {user}
Current directory: {cwd}
Hostname: {hostname}
"""
        
        if recent:
            context_str += "\nRecent commands:\n"
            for cmd in recent[-5:]:  # Last 5 commands
                context_str += f"$ {cmd['command']}\n{cmd['output'][:100]}\n"
        
        # Build the prompt
        prompt = f"""{context_str}

Command: {command}
Output:"""
        
        return prompt
    
    def generate_response(self, command: str, context: Dict, 
                         max_length: int = 512, temperature: float = 0.7) -> str:
        """
        Generate a realistic command output.
        
        Args:
            command: The command to process
            context: Context dictionary with system state
            max_length: Maximum tokens to generate
            temperature: Sampling temperature (higher = more creative)
        
        Returns:
            Generated command output
        """
        
        # Check cache first for common commands
        cache_key = f"{command}:{context.get('current_directory', '/')}"
        cached = self._get_cached_response(cache_key)
        if cached:
            logger.debug(f"Using cached response for: {command}")
            return cached
        
        # Check for static responses (fallback)
        static_response = self._get_static_response(command, context)
        if static_response:
            self.response_cache[cache_key] = static_response
            return static_response
        
        # Generate with AI model
        try:
            prompt = self._build_prompt(command, context)
            
            # Tokenize
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=512
            ).to(self.device)
            
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_length,
                    temperature=temperature,
                    do_sample=True,
                    top_p=0.95,
                    top_k=50,
                    num_return_sequences=1,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )
            
            # Decode
            generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract only the output part (after "Output:")
            if "Output:" in generated_text:
                response = generated_text.split("Output:")[-1].strip()
            else:
                response = generated_text.strip()
            
            # Clean up response
            response = self._clean_response(response, command)
            
            # Cache for future use
            self.response_cache[cache_key] = response
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            # Fallback to static response
            return self._get_static_response(command, context) or "Command not found"
    
    def _clean_response(self, response: str, command: str) -> str:
        """Clean and validate generated response."""
        # Remove any prompt remnants
        response = response.split("Command:")[0]
        response = response.split("$")[0]
        
        # Limit length
        lines = response.split('\n')
        if len(lines) > 50:
            lines = lines[:50]
            lines.append("... (output truncated)")
        
        response = '\n'.join(lines).strip()
        
        # Ensure it looks realistic
        if len(response) < 5 and command not in ['pwd', 'whoami', 'id']:
            response = self._get_static_response(command, {})
        
        return response
    
    def _get_static_response(self, command: str, context: Dict) -> Optional[str]:
        """
        Fallback static responses for common commands.
        This ensures the honeypot always has reasonable responses.
        """
        
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return ""
        
        base_cmd = cmd_parts[0]
        cwd = context.get('current_directory', '/root')
        user = context.get('username', 'root')
        hostname = context.get('hostname', 'ubuntu-server')
        
        static_responses = {
            'pwd': cwd,
            'whoami': user,
            'hostname': hostname,
            'id': f"uid=0({user}) gid=0(root) groups=0(root)",
            'uname': "Linux",
            'date': "Thu Feb 13 10:30:45 UTC 2026",
            'uptime': " 10:30:45 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.09",
            'w': f" 10:30:45 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.09\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n{user}     pts/0    192.168.1.100    10:15    0.00s  0.04s  0.00s w",
            'echo': ' '.join(cmd_parts[1:]) if len(cmd_parts) > 1 else '',
        }
        
        # Handle commands with arguments
        if base_cmd == 'cat' and len(cmd_parts) > 1:
            # This would need to query the sandbox filesystem
            return None  # Let the calling code handle this
        
        if base_cmd == 'ls':
            # This would need to query the sandbox filesystem
            return None
        
        if base_cmd == 'ps':
            # This would need to query the sandbox processes
            return None
        
        if base_cmd in ['wget', 'curl']:
            # Simulate download
            if len(cmd_parts) > 1:
                url = cmd_parts[-1]
                return f"--2026-02-13 10:30:45--  {url}\nResolving... failed: Name or service not known."
            return "wget: missing URL"
        
        if base_cmd in ['apt', 'apt-get', 'yum']:
            return "E: Could not open lock file /var/lib/dpkg/lock - open (13: Permission denied)\nE: Unable to lock the administration directory (/var/lib/dpkg/), are you root?"
        
        # Return static response if available
        return static_responses.get(base_cmd)
    
    def extract_state_mutations(self, command: str, output: str, context: Dict) -> Dict:
        """
        Analyze command and output to determine state changes.
        
        Returns a dictionary of state mutations:
        {
            'filesystem': [{'action': 'create', 'path': '/tmp/test.txt', 'content': '...'}],
            'processes': [{'action': 'start', 'pid': 1234, 'name': 'nginx'}],
            'environment': [{'key': 'TEST', 'value': 'value'}],
            'logs': [{'source': 'auth.log', 'message': '...'}]
        }
        """
        
        mutations = {
            'filesystem': [],
            'processes': [],
            'environment': [],
            'logs': []
        }
        
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return mutations
        
        base_cmd = cmd_parts[0]
        
        # File creation/modification commands
        if base_cmd in ['touch', 'echo', '>>', '>']:
            if '>' in command:
                # Redirection
                match = re.search(r'>\s*([^\s]+)', command)
                if match:
                    path = match.group(1)
                    content = output if output else ''
                    mutations['filesystem'].append({
                        'action': 'write',
                        'path': path,
                        'content': content
                    })
            elif base_cmd == 'touch' and len(cmd_parts) > 1:
                for path in cmd_parts[1:]:
                    mutations['filesystem'].append({
                        'action': 'create',
                        'path': path,
                        'content': ''
                    })
        
        # Directory commands
        elif base_cmd in ['mkdir']:
            for path in cmd_parts[1:]:
                mutations['filesystem'].append({
                    'action': 'mkdir',
                    'path': path
                })
        
        elif base_cmd in ['rm', 'rmdir']:
            for path in cmd_parts[1:]:
                if path not in ['-rf', '-r', '-f']:
                    mutations['filesystem'].append({
                        'action': 'delete',
                        'path': path
                    })
        
        # Process commands
        elif base_cmd in ['./start.sh', 'python', 'node', 'java']:
            # Simulated process start
            import random
            mutations['processes'].append({
                'action': 'start',
                'pid': random.randint(1000, 9999),
                'name': cmd_parts[0],
                'cmdline': command
            })
        
        # Environment variables
        elif base_cmd == 'export':
            if '=' in command:
                match = re.search(r'export\s+(\w+)=(.+)', command)
                if match:
                    mutations['environment'].append({
                        'key': match.group(1),
                        'value': match.group(2).strip('"\'')
                    })
        
        # Log relevant commands
        if base_cmd in ['wget', 'curl', 'nc', 'ncat', 'ssh', 'scp']:
            mutations['logs'].append({
                'source': 'auth.log',
                'level': 'WARNING',
                'message': f"Suspicious command executed: {command}"
            })
        
        return mutations
