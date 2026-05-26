import requests
from bs4 import BeautifulSoup
from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.cvss import CVSSScorer
from modules.ai_analysis import AIAnalyzer
from modules.pdf_report import generate_report
from datetime import datetime
import os

TARGET = "http://localhost"  # DVWA target

print("=" * 50)
print("  WebAudit - Intelligent Pentest Framework")
print("=" * 50)
print(f"\n[*] Target: {TARGET}")

# Login to DVWA
print("\n[*] Logging into DVWA...")
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
})
session.get(f"{TARGET}/")
session.post(f"{TARGET}/login.php",
    data={
        'username': 'admin',
        'password': 'test',
        'Login': 'Login',
        'user_token': 'anything'
    }
)
check = session.get(f"{TARGET}/index.php")
if 'Welcome' in check.text:
    print("  [+] Login successful!")
else:
    print("  [-] Login failed!")
    exit()

# Phase 1 - Crawl
print("\n[Phase 1] Crawling target...")
crawler = Crawler(TARGET, session=session)
crawler.crawl(depth=2)
results = crawler.get_results()

# DVWA known vulnerable endpoints
known_vulnerable = [
    {'url': 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit', 'status': 200, 'length': 0},
    {'url': 'http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit', 'status': 200, 'length': 0},
    {'url': 'http://localhost/vulnerabilities/xss_r/?name=test', 'status': 200, 'length': 0},
]
results['endpoints'].extend(known_vulnerable)
print(f"  --> Endpoints found : {len(results['endpoints'])}")
print(f"  --> Forms found     : {len(results['forms'])}")

# Phase 2 - SQLi
print("\n[Phase 2] Testing for SQL Injection...")
sqli = SQLiScanner(session=session)
sqli_findings = sqli.scan(results['forms'], results['endpoints'])

# Phase 3 - XSS
print("\n[Phase 3] Testing for XSS...")
xss = XSSScanner(session=session)
xss_findings = xss.scan(results['forms'], results['endpoints'])

# Phase 4 - CVSS Scoring
print("\n[Phase 4] Applying CVSS Scoring...")
all_findings = sqli_findings + xss_findings
cvss = CVSSScorer()
scored_findings = cvss.score(all_findings)
risk_summary = cvss.get_risk_summary(scored_findings)

# Phase 5 - AI Analysis
print("\n[Phase 5] Generating AI Analysis...")
try:
    ai = AIAnalyzer(model='llama3')
    analysis = ai.analyze(scored_findings, TARGET, risk_summary)
    print("\n" + "=" * 50)
    print("  AI EXECUTIVE SUMMARY")
    print("=" * 50)
    print(analysis)
except Exception as e:
    print(f"  [-] AI failed: {e}")
    print("  [*] Make sure ollama is running: ollama serve")
    analysis = "AI analysis failed. Make sure ollama is running."

# Phase 6 - PDF Report
print("\n[Phase 6] Generating PDF Report...")
os.makedirs("reports", exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_path = f"reports/webaudit_report_{timestamp}.pdf"
generate_report(TARGET, scored_findings, risk_summary, analysis, output_path)

# Summary
print("\n" + "=" * 50)
print("  SCAN COMPLETE")
print("=" * 50)
print(f"  Target            : {TARGET}")
print(f"  Endpoints crawled : {len(results['endpoints'])}")
print(f"  Forms tested      : {len(results['forms'])}")
print(f"  SQLi found        : {len(sqli_findings)}")
print(f"  XSS found         : {len(xss_findings)}")
print(f"  Total vulns       : {len(scored_findings)}")
print(f"\n  Risk Breakdown:")
print(f"    CRITICAL : {risk_summary['CRITICAL']}")
print(f"    HIGH     : {risk_summary['HIGH']}")
print(f"    MEDIUM   : {risk_summary['MEDIUM']}")
print(f"    LOW      : {risk_summary['LOW']}")
print(f"\n  Report saved to : {output_path}")
print("\n  Thank you for using WebAudit!")
print("=" * 50)
