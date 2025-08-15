# Honeypot Network Simulation & Analysis

## 📌 Overview
A Python-based honeypot that emulates multiple network services (FTP, SSH, HTTP, HTTPS) to detect, log, and analyze suspicious activity.  
Includes:
- **Honeypot Server** — Listens on multiple ports and logs all interactions.
- **Attack Simulator** — Simulates port scans, brute-force attempts, and payload injections.
- **Log Analyzer** — Extracts insights from logs: top attackers, targeted ports, hourly trends, and common payloads.

## 🚀 Features
- Multiple service emulation with realistic banners
- Threaded connection handling
- Built-in attack simulator for testing
- Analysis report with behavioral insights

## 📂 Project Structure
honeypot.py # Honeypot server
honeypot_simulator.py # Attack simulator
log_analyzer.py # Log analyzer
honeypot_logs/ # Log storage (ignored in Git)

## ⚙️ Requirements
- Python 3.x  
- **No external libraries needed** — uses only Python's standard library.


## ⚙️ Installation
```bash
# Clone the repository
git clone https://github.com/sam-kolige/honeypot-network-simulation.git
cd honeypot-network-simulation
```


## 🖥 Usage

### Start the Honeypot
```bash
python honeypot.py
```
By default, it listens on ports 21, 22, 80, and 443.

### Run the Attack Simulator
```bash
python honeypot_simulator.py --target 127.0.0.1 --intensity medium --duration 60
```

### Analyze Logs
```bash 
python log_analyzer.py honeypot_logs/honeypot_<date>.json
```

## 🛡 Safety Notes

Run only in a controlled environment (local network or VM).

Do not expose to the public internet without precautions.


## 📜 License

MIT License
