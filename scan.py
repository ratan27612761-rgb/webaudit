import requests
import sys
import os
import argparse
from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.cvss import CVSSScorer
from modules.ai_analysis import AIAnalyzer
from modules.pdf_report import generate_report
from datetime import datetime

VERSION = "1.0.0"

def banner():
    print("""
 ██╗    ██╗███████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║  ██║██║   ██║   
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║  ██║██║   ██║   
 ╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║   
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
    """)
    print(f"  WebAudit v{VERSION} - Intelligent Web Pentest Framework")
    print("  GitHub: https://github.com/ratan27612761-rgb/webaudit")
    print("  For authorized testing only!\n")

def parse_args():
    parser = argparse.ArgumentParser(
        prog='webaudit',
        description='WebAudit - Intelligent Web Penetration Testing Framework',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 scan.py -u http://testfire.net
  python3 scan.py -u http://testfire.net -d 3
  python3 scan.py -u http://testfire.net --no-ai
  python3 scan.py -u http://testfire.net --no-pdf
  python3 scan.py --version
        """
    )
    parser.add_argument(
        '-u', '--url',
        help='Target URL to scan\n  Example: http://testfire.net',
        required=False
    )
    parser.add_argument(
        '-d', '--depth',
        help='Crawl depth (default: 2)',
        type=int,
        default=2
    )
    parser.add_argument(
        '--no-ai',
        help='Skip AI analysis (faster scan)',
        action='store_true'
    )
    parser.add_argument(
        '--no-pdf',
        help='Skip PDF report generation',
        action='store_true'
    )
    parser.add_argument(
        '--version',
        help='Show version number',
        action='store_true'
    )
    return parser.parse_args()

def main():
    banner()
    args = parse_args()

    if args.version:
        print(f"WebAudit version {VERSION}")
        sys.exit(0)

    if not args.url:
        print("  Error: Target URL is required!")
        print("  Usage: python3 scan.py -u http://target.com")
        print("  Help:  python3 scan.py -h")
        sys.exit(1)

    TARGET = args.url.rstrip('/')

    print("=" * 55)
    print(f"  Target : {TARGET}")
    print(f"  Depth  : {args.depth}")
    print(f"  AI     : {'Disabled' if args.no_ai else 'Enabled'}")
    print(f"  PDF    : {'Disabled' if args.no_pdf else 'Enabled'}")
    print("=" * 55)

    # Check target
    print("\n[*] Checking target reachability...")
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    })
    try:
        r = session.get(TARGET, timeout=10)
        print(f"  [+] Target is reachable! Status: {r.status_code}")
    except Exception as e:
        print(f"  [-] Target unreachable: {e}")
        sys.exit(1)

    # Phase 1 - Crawl
    print(f"\n[Phase 1] Crawling target (depth={args.depth})...")
    crawler = Crawler(TARGET, session=session)
    crawler.crawl(depth=args.depth)
    results = crawler.get_results()
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

    # Phase 4 - CVSS
    print("\n[Phase 4] Applying CVSS Scoring...")
    all_findings = sqli_findings + xss_findings
    cvss = CVSSScorer()
    scored_findings = cvss.score(all_findings)
    risk_summary = cvss.get_risk_summary(scored_findings)

    # Phase 5 - AI
    analysis = "AI analysis skipped."
    if not args.no_ai:
        print("\n[Phase 5] Generating AI Analysis...")
        try:
            ai = AIAnalyzer(model='llama3')
            analysis = ai.analyze(scored_findings, TARGET, risk_summary)
            print("\n" + "=" * 55)
            print("  AI EXECUTIVE SUMMARY")
            print("=" * 55)
            print(analysis)
        except Exception as e:
            print(f"  [-] AI analysis failed: {e}")
            print("  [*] Tip: Make sure ollama is running: ollama serve")
            analysis = "AI analysis failed. Make sure ollama is running."
    else:
        print("\n[Phase 5] AI Analysis skipped (--no-ai flag)")

    # Phase 6 - PDF
    if not args.no_pdf:
        print("\n[Phase 6] Generating PDF Report...")
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"reports/webaudit_report_{timestamp}.pdf"
        generate_report(TARGET, scored_findings, risk_summary, analysis, output_path)
    else:
        print("\n[Phase 6] PDF Report skipped (--no-pdf flag)")
        output_path = "N/A"

    # Summary
    print("\n" + "=" * 55)
    print("  SCAN COMPLETE")
    print("=" * 55)
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
    if output_path != "N/A":
        print(f"\n  Report saved : {output_path}")
    print("=" * 55)

if __name__ == "__main__":
    main()
