class CVSSScorer:
    def __init__(self):
        self.scores = {
            'SQL Injection': {
                'score': 9.8,
                'rating': 'CRITICAL',
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'impact': 'Attacker can read, modify or delete entire database. May lead to full system compromise.',
                'remediation': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.'
            },
            'Reflected XSS': {
                'score': 7.4,
                'rating': 'HIGH',
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
                'impact': 'Attacker can steal session cookies, redirect users to malicious sites.',
                'remediation': 'Encode all user-supplied output. Implement Content Security Policy headers.'
            },
            'Default': {
                'score': 5.0,
                'rating': 'MEDIUM',
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
                'impact': 'Security vulnerability that may lead to unauthorized access.',
                'remediation': 'Review and fix the identified vulnerability following security best practices.'
            }
        }

    def score(self, findings):
        print("\n[*] Applying CVSS scoring...")
        scored = []
        for finding in findings:
            vuln_type = finding.get('type', 'Default')
            cvss_data = self.scores.get(vuln_type, self.scores['Default'])
            scored_finding = {**finding, **cvss_data}
            scored.append(scored_finding)
            print(f"  [*] {vuln_type} at {finding['url']}")
            print(f"      CVSS Score : {cvss_data['score']} ({cvss_data['rating']})")
            print(f"      Vector     : {cvss_data['vector']}")
        return scored

    def get_risk_summary(self, scored_findings):
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in scored_findings:
            rating = f.get('rating', 'MEDIUM')
            summary[rating] = summary.get(rating, 0) + 1
        return summary
