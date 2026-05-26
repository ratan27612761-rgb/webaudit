# WebAudit - Intelligent Web Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![AI](https://img.shields.io/badge/AI-Llama3%20Powered-purple)
![Version](https://img.shields.io/badge/Version-1.0.0-orange)

An automated web application penetration testing framework that crawls targets, detects vulnerabilities, applies CVSS 3.1 scoring, generates AI-written narratives, and produces professional PDF reports.

---

## Features

- Web Crawler — Recursively maps all endpoints and forms
- SQL Injection Scanner — Detects error-based SQLi in GET and POST parameters
- XSS Scanner — Detects reflected Cross-Site Scripting vulnerabilities
- CVSS 3.1 Scoring — Industry standard severity ratings for every finding
- AI Analysis — Local LLM generates professional pentest narrative automatically
- PDF Report — Professional client-ready report with cover page, findings, and remediation

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
- Docker (for DVWA lab practice)
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

### Step 3 - Install and start Ollama (AI engine)
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Open Terminal 1 and run:
```bash
ollama serve
```

Open Terminal 2 and pull the model:
```bash
ollama pull llama3
```

---

## Usage

WebAudit has two modes:

### Mode 1 - Practice on DVWA Lab (Beginners)

DVWA is an intentionally vulnerable web app for safe practice.

#### Setup DVWA
```bash
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```

Open browser at `http://localhost`:
- Click **Setup / Reset Database**
- Login with `admin` / `test`

#### Run scanner on DVWA
```bash
python3 main.py
```

---

### Mode 2 - Scan Any Real Target (Advanced)

Use `scan.py` to scan any website you have permission to test.

#### Basic scan
```bash
python3 scan.py -u http://target-website.com
```

#### Deeper crawl (finds more pages)
```bash
python3 scan.py -u http://target-website.com -d 3
```

#### Fast scan without AI
```bash
python3 scan.py -u http://target-website.com --no-ai
```

#### Scan without PDF report
```bash
python3 scan.py -u http://target-website.com --no-pdf
```

#### See all options
```bash
python3 scan.py -h
```

#### Check version
```bash
python3 scan.py --version
```

---

## Command Reference

| Command | Description |
|---|---|
| `python3 main.py` | Scan DVWA lab |
| `python3 scan.py -u URL` | Scan any target |
| `python3 scan.py -u URL -d 3` | Scan with depth 3 |
| `python3 scan.py -u URL --no-ai` | Skip AI analysis |
| `python3 scan.py -u URL --no-pdf` | Skip PDF report |
| `python3 scan.py -h` | Show help |
| `python3 scan.py --version` | Show version |

---

## Real Target Testing - Step by Step

### Step 1 - Get permission first
Only scan websites you own or have written permission to test.
Good practice targets (legal to scan):
- `http://testfire.net` - IBM demo bank app
- `http://demo.testfire.net` - IBM demo app
- `http://juice-shop.herokuapp.com` - OWASP Juice Shop
- `http://localhost` - Your own DVWA lab

### Step 2 - Start Ollama (for AI analysis)
Open Terminal 1:
```bash
ollama serve
```

### Step 3 - Run the scan
Open Terminal 2:
```bash
cd webaudit
python3 scan.py -u http://testfire.net
```

### Step 4 - Get your PDF report
```bash
ls reports/
```

Open the PDF — it contains:
- Cover page with target and date
- Risk summary table
- AI-written executive summary
- Detailed findings with CVSS scores
- Remediation recommendations

---

## Sample Output
██╗    ██╗███████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
██║    ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║  ██║██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║  ██║██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║
╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
WebAudit v1.0.0 - Intelligent Web Pentest Framework
GitHub: https://github.com/ratan27612761-rgb/webaudit
[Phase 1] Crawling target...
[+] Found: http://testfire.net/index.jsp (200)
[+] Found: http://testfire.net/login.jsp (200)
--> Endpoints found : 15
--> Forms found     : 4
[Phase 2] Testing for SQL Injection...
[!!!] SQLi FOUND at http://testfire.net/login.jsp
Payload  : '
Evidence : you have an error in your sql syntax
CVSS     : 9.8 (CRITICAL)
[Phase 3] Testing for XSS...
[!!!] XSS FOUND at http://testfire.net/search.jsp
Payload  : <script>alert('XSS')</script>
CVSS     : 7.4 (HIGH)
[Phase 5] AI Executive Summary...
During the assessment of testfire.net, two critical
vulnerabilities were identified...
[Phase 6] PDF Report saved to: reports/webaudit_report_20260526.pdf
==================================================
SCAN COMPLETE
SQLi found        : 1
XSS found         : 1
Total vulns       : 2
CRITICAL          : 1
HIGH              : 1

---

## Project Structure
webaudit/
├── main.py                 # DVWA lab scanner
├── scan.py                 # Universal scanner (any target)
├── modules/
│   ├── crawler.py          # Web crawler
│   ├── sqli.py             # SQL injection scanner
│   ├── xss.py              # XSS scanner
│   ├── cvss.py             # CVSS scoring engine
│   ├── ai_analysis.py      # AI narrative generator
│   └── pdf_report.py       # PDF report generator
├── reports/                # Generated PDF reports
└── README.md

---

## Vulnerability Coverage

| Vulnerability | Detection Method | CVSS Score |
|---|---|---|
| SQL Injection | Error-based signature matching | 9.8 CRITICAL |
| Reflected XSS | Payload reflection detection | 7.4 HIGH |
| Blind SQLi | Coming soon | - |
| CSRF | Coming soon | - |
| Command Injection | Coming soon | - |

---

## Updating WebAudit

To get the latest version:
```bash
cd webaudit
git pull origin main
```

---

## Version History

| Version | Changes |
|---|---|
| v1.0.0 | Initial release - Crawler, SQLi, XSS, CVSS, AI, PDF |

---

## Comparison With Other Tools

| Feature | WebAudit | Nikto | OWASP ZAP | Burp Suite |
|---|---|---|---|---|
| SQLi Detection | Yes | Yes | Yes | Yes |
| XSS Detection | Yes | Yes | Yes | Yes |
| CVSS Scoring | Yes | No | No | No |
| AI Narrative | Yes | No | No | No |
| PDF Report | Yes | No | Yes | Yes (paid) |
| Free | Yes | Yes | Yes | No |
| CLI Arguments | Yes | Yes | Yes | Yes |

---

## Legal Disclaimer

This tool is for educational purposes and authorized penetration testing only.
Only use WebAudit against systems you own or have explicit written permission to test.
Unauthorized scanning is illegal and unethical.
The author is not responsible for any misuse or damage caused by this tool.

---

## Tech Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core language |
| requests | HTTP client |
| BeautifulSoup4 | HTML parsing |
| fpdf2 | PDF generation |
| Ollama + Llama3 | Local AI analysis |
| Docker + DVWA | Target lab environment |

---

## Author

Built by [Ratan](https://github.com/ratan27612761-rgb) as a portfolio project for web application penetration testing.

---

## License

MIT License - feel free to use, modify, and distribute.
