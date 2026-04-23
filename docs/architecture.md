# AdaptiveWardens Architecture & Design

AdaptiveWardens is designed as a lightweight, microservices-based AI honeypot. By strictly separating concerns between the SSH frontend, the AI processing layer, and the persistence engine, the system remains scalable, secure, and robust against attacker noise.

## Core Microservices

1. **SSH Frontend (`ssh-frontend`)**
   - **Role**: Primary attack surface binding to port 2222.
   - **Tech Stack**: Python, `asyncssh`.
   - **Statelessness**: The SSH server holds minimal state per connection. It delegates all heavy lifting (filesystem navigation, command result parsing, and AI query) to other internal APIs.
   - **Safeguards**: Employs async networking to handle multiple connections efficiently without thread exhaustion.

2. **AI Engine (`ai-engine`)**
   - **Role**: Interprets commands using Google's Gemini API and formats realistic bash responses.
   - **Tech Stack**: Python, `FastAPI`, `google-generativeai`.
   - **Statelessness**: Almost entirely stateless cache (in-memory or SQLite integration). Reusable and horizontally scalable if load increases.
   - **Safeguards**: Has structured caching (preventing API exhaustion when attackers spam identical commands). Includes internal error fallback responses ("bash: command not found").

3. **Sandbox Store (`sandbox-store`)**
   - **Role**: Centralized persistence API ensuring isolated environments for each attacker session, handling virtual filesystems, and persisting logs.
   - **Tech Stack**: Python, `FastAPI`, `sqlite3`.
   - **ACID Integrity**: Uses SQLite configured with `WAL` (Write-Ahead Logging) and `check_same_thread=False` to safely handle concurrent HTTP requests mimicking concurrent SSH attacker events.
   - **Safeguards**: Data is isolated by `session_id`. Database timeouts and rollback mechanisms ensure no corrupted internal state.

4. **Dashboard Backend & Frontend**
   - **Role**: Read-only visualization tools for the Security Operations Center (SOC).
   - **Safeguards**: Separated fully from the honeypot internal network interfaces. Hardcoded public IPs are removed in favor of environment variable configurations for true flexibility.

## Networking and Isolation

The Docker Compose setup defines two distinct networks:
- **`honeypot-internal`**: `ssh-frontend` -> `ai-engine` -> `sandbox-store`. No internet access bypass allowed.
- **`honeypot-external`**: Exposes the `dashboard-frontend` and binds the `ssh-frontend` listener.

## Architecture Justifications & Trade-offs

- **Why Microservices via Docker Compose?**
  - Segmenting the SSH handler from the Database handler means that an attacker discovering a 0-day within `asyncssh` cannot automatically compromise the persistence or log storage layers, achieving true network isolation. However, this introduces slight serialization latency versus monolithic designs.
- **Why SQLite instead of PostgreSQL?**
  - To fulfill the strict "run-with-one-command" objective without bloating the docker-compose deployment. Using SQLite and WAL mode is enough to handle ~250 concurrent attackers before locking occurs, sufficient for most honeypots.
- **Why AI Fallback Heuristics?**
  - Gemini API relies on cloud networking and rate limits, meaning 99.9% uptime is impossible natively. Providing static "command not found" fallbacks ensures the attacker doesn't realize the backend failed, maintaining illusion and session stability natively.
- **Docker Policies**: `restart: unless-stopped` guarantees high uptime upon system reboot or unexpected process crashes.
- **Health Checks**: Implemented across all APIs using CURL or TCP connection checks, allowing Docker to correctly mark service states and handle dependency orchestration safely.
- **Load Scaling**: A load testing script (`scripts/load_test_ssh.py`) is provided using `asyncssh`. Under heavy concurrency, the bottleneck will typically offload to the synchronous SQLite writes or the external Gemini API limits. Standard production limits (max 50 connections) prevent host OOM issues.
