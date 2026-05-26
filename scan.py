import requests
import sys
import os
from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.cvss import CVSSScorer
from modules.ai_analysis import AIAnalyzer
from modules.pdf_report import generate_report
from datetime import datetime

if len(sys.argv) < 2:
    print("Usage: python3 scan.py <target_url>")
    print("Example: python3 scan.py http://testfire.net")
    sys.exit(1)

TARGET = sys.argv[1].rstrip('/')

print("=" * 50)
print("  WebAudit - Intelligent Pentest Framework")
print("=" * 50)
print(f"\n[*] Target: {TARGET}")

session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
})

print("\n[*] Checking target...")
try:
    r = session.get(TARGET, timeout=10)
    print(f"  [+] Target reachable! Status: {r.status_code}")
except Exception as e:
    print(f"  [-] Target unreachable: {e}")
    sys.exit(1)

print("\n[Phase 1] Crawling target...")
crawler = Crawler(TARGET, session=session)
crawler.crawl(depth=2)
results = crawler.get_results()
print(f"  --> Endpoints found : {len(results['endpoints'])}")
print(f"  --> Forms found     : {len(results['forms'])}")

print("\n[Phase 2] Testing for SQL Injection...")
sqli = SQLiScanner(session=session)
sqli_findings = sqli.scan(results['forms'], results['endpoints'])

print("\n[Phase 3] Testing for XSS...")
xss = XSSScanner(session=session)
xss_findings = xss.scan(results['forms'], results['endpoints'])

print("\n[Phase 4] Applying CVSS Scoring...")
all_findings = sqli_findings + xss_findings
cvss = CVSSScorer()
scored_findings = cvss.score(all_findings)
risk_summary = cvss.get_risk_summary(scored_findings)

print("\n[Phase 5] Generating AI Analysis...")
ai = AIAnalyzer(model='llama3')
analysis = ai.analyze(scored_findings, TARGET, risk_summary)
print("\n" + "=" * 50)
print("  AI EXECUTIVE SUMMARY")
print("=" * 50)
print(analysis)

print("\n[Phase 6] Generating PDF Report...")
os.makedirs("reports", exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_path = f"reports/webaudit_report_{timestamp}.pdf"
generate_report(TARGET, scored_findings, risk_summary, analysis, output_path)

print("\n" + "=" * 50)
print("  SCAN SUMMARY")
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
print(f"\n  Report : {output_path}")
print("=" * 50)
