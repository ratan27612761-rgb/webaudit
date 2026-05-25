import ollama

class AIAnalyzer:
    def __init__(self, model='llama3'):
        self.model = model

    def analyze(self, scored_findings, target, risk_summary):
        print("\n[*] Running AI analysis with Ollama...")

        findings_text = ""
        for i, f in enumerate(scored_findings, 1):
            findings_text += f"""
Finding {i}:
- Type: {f.get('type')}
- URL: {f.get('url')}
- CVSS Score: {f.get('score')} ({f.get('rating')})
- Impact: {f.get('impact')}
- Remediation: {f.get('remediation')}
"""

        prompt = f"""You are a professional penetration tester writing an executive summary for a security assessment report.

Target: {target}
Scan Results:
- Critical vulnerabilities: {risk_summary['CRITICAL']}
- High vulnerabilities: {risk_summary['HIGH']}
- Medium vulnerabilities: {risk_summary['MEDIUM']}
- Low vulnerabilities: {risk_summary['LOW']}

Detailed Findings:
{findings_text}

Write a professional executive summary (3-4 paragraphs) that includes:
1. Overview of the assessment and key findings
2. Business impact of the vulnerabilities found
3. Priority recommendations for remediation
4. Overall risk rating

Write in a professional tone suitable for a security report delivered to a client."""

        print("  [*] Generating narrative (this may take 30-60 seconds)...")
        response = ollama.chat(
            model=self.model,
            messages=[{'role': 'user', 'content': prompt}]
        )
        analysis = response['message']['content']
        print("  [+] AI analysis complete!")
        return analysis

    def get_results(self):
        return []
