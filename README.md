# WebAudit - Intelligent Web Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![AI](https://img.shields.io/badge/AI-Llama3%20Powered-purple)

An automated web application penetration testing framework that crawls targets, detects vulnerabilities, applies CVSS scoring, generates AI-written narratives, and produces professional PDF reports.

---

## Features

- Web Crawler - Recursively maps all endpoints and forms
- SQL Injection Scanner - Detects error-based SQLi in GET and POST parameters
- XSS Scanner - Detects reflected Cross-Site Scripting vulnerabilities
- CVSS 3.1 Scoring - Industry standard severity ratings for every finding
- AI Analysis - Local LLM generates professional pentest narrative automatically
- PDF Report - Professional client-ready report with cover page, findings, and remediation

---

## How It Works
Target URL
|
v
[Phase 1] Crawler -----------> Maps all endpoints and forms
|
v
[Phase 2] SQLi Scanner -------> Tests for SQL Injection
|
v
[Phase 3] XSS Scanner --------> Tests for Cross-Site Scripting
|
v
[Phase 4] CVSS Scoring -------> Assigns severity scores
|
v
[Phase 5] AI Analysis --------> Writes executive summary
|
v
[Phase 6] PDF Report ---------> Generates professional report

---

## Requirements

- Kali Linux (recommended) or any Linux distro
- Python 3.x
- Docker (for running DVWA lab)
- Ollama (for AI analysis)

---

## Installation

### Step 1 - Clone the repository
```bash
git clone https://github.com/ratan27612761-rgb/webaudit.git
cd webaudit
```

### Step 2 - Install Python dependencies
```bash
pip3 install requests beautifulsoup4 fpdf2 ollama --break-system-packages
```

### Step 3 - Install and start Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
```

Open a new terminal and pull the AI model:
```bash
ollama pull llama3
```

### Step 4 - Set up the target lab (DVWA)
```bash
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```

Open your browser and go to `http://localhost`
- Click Setup / Reset Database
- Login with `admin` / `test`

---

## Usage

### Edit the target in main.py
```python
TARGET = "http://your-target-here.com"
```

### Run the scanner
```bash
python3 main.py
```

### Get your report
```bash
ls reports/

---

## Demo

### Scan DVWA Lab (practice)
```bash
python3 main.py
```

### Scan Any Website
```bash
python3 scan.py http://target-website.com
```

---

## Screenshots

### Terminal Output
[!!!] SQLi FOUND at http://localhost/vulnerabilities/sqli/
Parameter: id
Payload  : '
Evidence : you have an error in your sql syntax
CVSS     : 9.8 (CRITICAL)
[!!!] XSS FOUND at http://localhost/vulnerabilities/csp/
Payload  : <script>alert('XSS')</script>
CVSS     : 7.4 (HIGH)

---

## Important Note

This tool is built for:
- Practicing on intentionally vulnerable apps like DVWA
- Authorized penetration testing engagements only
- Educational and learning purposes

Never use this tool against systems without explicit written permission.

---

## Roadmap

- [ ] Command Injection detection
- [ ] CSRF detection
- [ ] Blind SQL Injection detection
- [ ] HTML report option
- [ ] Multi-threading for faster scans
- [ ] Login support for authenticated scans on any target

---

## Updating WebAudit

To get the latest version with new features and bug fixes:

```bash
cd webaudit
git pull origin main
```

## Version History

| Version | Changes |
|---|---|
| v1.0.0 | Initial release - Crawler, SQLi, XSS, CVSS, AI, PDF |

