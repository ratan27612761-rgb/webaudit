from fpdf import FPDF
from datetime import datetime

def clean(text):
    replacements = {
        '\u2014': '-', '\u2013': '-', '\u2018': "'", '\u2019': "'",
        '\u201c': '"', '\u201d': '"', '\u2022': '*', '\u2026': '...'
    }
    for k, v in replacements.items():
        text = str(text).replace(k, v)
    return text

class PDFReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(20, 20, 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, '  WebAudit - Penetration Test Report', fill=True, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'WebAudit Security Report | Page {self.page_no()} | CONFIDENTIAL', align='C')

    def cover_page(self, target, date):
        self.add_page()
        self.ln(20)
        self.set_font('Helvetica', 'B', 28)
        self.set_text_color(20, 20, 20)
        self.cell(0, 14, 'PENETRATION TEST REPORT', align='C', ln=True)
        self.ln(4)
        self.set_font('Helvetica', '', 14)
        self.set_text_color(80, 80, 80)
        self.cell(0, 10, 'Web Application Security Assessment', align='C', ln=True)
        self.ln(16)
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(200, 200, 200)
        self.rect(30, self.get_y(), 150, 50, 'DF')
        self.ln(6)
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(20, 20, 20)
        self.cell(0, 8, f'Target:  {clean(target)}', align='C', ln=True)
        self.cell(0, 8, f'Date:    {clean(date)}', align='C', ln=True)
        self.cell(0, 8, 'Type:    Black Box Web Assessment', align='C', ln=True)
        self.cell(0, 8, 'Tool:    WebAudit Intelligent Scanner', align='C', ln=True)
        self.ln(20)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, 'CONFIDENTIAL - For authorized personnel only', align='C', ln=True)

    def section_title(self, title):
        self.ln(6)
        self.set_font('Helvetica', 'B', 13)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f'  {clean(title)}', fill=True, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def risk_summary_table(self, risk_summary):
        self.section_title('RISK SUMMARY')
        cols = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        colors = {
            'CRITICAL': (180, 0, 0),
            'HIGH':     (220, 80, 0),
            'MEDIUM':   (200, 150, 0),
            'LOW':      (0, 140, 0),
        }
        col_width = 45
        self.set_font('Helvetica', 'B', 10)
        for col in cols:
            r, g, b = colors[col]
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.cell(col_width, 10, col, border=1, align='C', fill=True)
        self.ln()
        self.set_text_color(0, 0, 0)
        self.set_font('Helvetica', 'B', 14)
        for col in cols:
            self.cell(col_width, 12, str(risk_summary.get(col, 0)), border=1, align='C')
        self.ln(8)

    def add_finding(self, finding, index):
        self.ln(4)
        self.set_fill_color(245, 245, 245)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 9, f'  Finding {index}: {clean(finding.get("type", "Unknown"))}', fill=True, ln=True)
        self.ln(2)

        # Severity row
        colors = {
            'CRITICAL': (180, 0, 0),
            'HIGH': (220, 80, 0),
            'MEDIUM': (200, 150, 0),
            'LOW': (0, 140, 0),
        }
        rating = finding.get('rating', 'MEDIUM')
        r, g, b = colors.get(rating, (100, 100, 100))
        self.set_font('Helvetica', 'B', 9)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.cell(40, 6, f'Severity: {rating}', fill=True, align='C')
        self.set_fill_color(60, 60, 60)
        self.cell(40, 6, f'CVSS: {finding.get("score", "N/A")}', fill=True, align='C')
        self.set_text_color(0, 0, 0)
        self.ln(10)

        # Details - each on its own line
        details = [
            ('URL',         finding.get('url', 'N/A')),
            ('Payload',     finding.get('payload', 'N/A')),
            ('Evidence',    finding.get('evidence', 'N/A')),
            ('Vector',      finding.get('vector', 'N/A')),
            ('Impact',      finding.get('impact', 'N/A')),
            ('Remediation', finding.get('remediation', 'N/A')),
        ]
        for label, value in details:
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(60, 60, 60)
            self.cell(0, 5, f'{label}:', ln=True)
            self.set_font('Helvetica', '', 9)
            self.set_text_color(0, 0, 0)
            self.set_left_margin(15)
            self.multi_cell(0, 5, clean(str(value)))
            self.set_left_margin(10)
            self.ln(1)

        self.set_draw_color(220, 220, 220)
        self.line(10, self.get_y(), 200, self.get_y())

    def add_executive_summary(self, analysis):
        self.section_title('EXECUTIVE SUMMARY')
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 6, clean(analysis))
        self.set_text_color(0, 0, 0)


def generate_report(target, scored_findings, risk_summary, analysis, output_path):
    print("\n[*] Generating PDF report...")
    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    date = datetime.now().strftime('%d %B %Y')
    pdf.cover_page(target, date)
    pdf.add_page()
    pdf.risk_summary_table(risk_summary)
    pdf.add_executive_summary(analysis)
    pdf.section_title('DETAILED FINDINGS')
    for i, finding in enumerate(scored_findings, 1):
        pdf.add_finding(finding, i)
    pdf.section_title('REMEDIATION SUMMARY')
    pdf.set_font('Helvetica', '', 10)
    remediations = list(set([f.get('remediation', '') for f in scored_findings]))
    for i, rem in enumerate(remediations, 1):
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(0, 7, f'{i}. Remediation:', ln=True)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_left_margin(15)
        pdf.multi_cell(0, 7, clean(rem))
        pdf.set_left_margin(10)
        pdf.ln(1)
    pdf.output(output_path)
    print(f"  [+] Report saved to: {output_path}")
    return output_path
