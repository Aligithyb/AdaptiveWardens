# AdaptiveWardens: AI-Driven Adaptive Honeypot

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Docker](https://img.shields.io/badge/docker-required-blue)

## 🎯 Quick Start

```bash
# Clone and setup
git clone https://github.com/Aligithyb/-AdaptiveWardens.git
cd AdaptiveWardens

# Start the honeypot
./start.sh

# Access dashboard
open http://localhost:3000
```

## 📋 Project Overview

AdaptiveWardens is an AI-driven honeypot using transformer models to create realistic SSH and HTTP environments for threat intelligence gathering.

### Features
- 🤖 AI-powered command responses
- 🔍 Automated IOC extraction
- 🎯 MITRE ATT&CK mapping
- 📊 Real-time dashboard
- 🔒 Zero-risk sandboxed execution

## 🏗️ Architecture

```
Attackers → SSH/HTTP → AI Engine → Sandbox Store → Dashboard
```

## 👥 Team

**Team #1 - Fall 2025**
- Ali Ahmed Reda (202201006) - AI Engine & IOC Extraction
- Ali Nazeer (202100732) - SSH/HTTP Frontends & Dashboard  
- Ahmed Yasser (202201883) - Sandbox State Store
- Abdulkhaliq Sarwat (202202084) - HTTP Frontend & Integration

**Supervisor:** Dr. Ashraf Hafez Badawi

## 📚 Documentation

See `/docs` folder for detailed implementation guides.

## 🤝 Contributing

Each team member works on their branch:
```bash
git checkout -b feature/your-name-component
# Make changes
git push origin feature/your-name-component
```

## 📄 License

Academic project - Fall 2025
