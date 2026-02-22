import os
import json
import google.generativeai as genai

class LLMProvider:
    def __init__(self, provider: str = "gemini"):
        self.provider = provider.lower()
        
        if self.provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise ValueError("GEMINI_API_KEY not set")
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
