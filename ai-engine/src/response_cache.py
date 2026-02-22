from datetime import datetime, timedelta
from typing import Optional
import hashlib
import json

class ResponseCache:
    def __init__(self):
        self.cache = {}

    def get_cache_key(self, command: str, context: dict) -> str:
        relevant_context = {
            'cwd': context.get('current_directory', '/root'),
            'user': context.get('username', 'root'),
        }
        key_data = f"{command}:{json.dumps(relevant_context, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, command: str, context: dict) -> Optional[str]:
        key = self.get_cache_key(command, context)
        if key in self.cache:
            cached = self.cache[key]
            if datetime.now() - cached['timestamp'] < timedelta(minutes=5):
                cached['count'] += 1
                return cached['response']
        return None

    def set(self, command: str, context: dict, response: str):
        key = self.get_cache_key(command, context)
        self.cache[key] = {
            'response': response,
            'timestamp': datetime.now(),
            'count': 1
        }
