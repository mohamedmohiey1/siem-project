"""
PDF Report Generator using fpdf
Simple PDF generation for SIEM reports - no external dependencies needed
"""

from fpdf import FPDF
from datetime import datetime


class SIEMReportPDF(FPDF):
    def header(self):
        # Title
        self.set_font('helvetica', 'B', 16)
        self.cell(0, 10, 'SIEM Security Report', border=False, align='C')
        self.ln(5)
        # Date
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', border=False, align='C')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')


def generate_report_pdf(report_data: dict, output_path: str = 'report.pdf'):
    """
    Generate a PDF report from report data
    
    Args:
        report_data: Dictionary containing:
            - total_logs: int
            - total_alerts: int
            - success_rate: float
            - failed_count: int
            - top_ips: list of tuples [(ip, count), ...]
            - recent_alerts: list of alert objects with timestamp, severity, description
        output_path: Path to save the PDF file
    
    Returns:
        str: Path to the generated PDF
    """
    pdf = SIEMReportPDF()
    pdf.add_page()
    
    # Set font
    pdf.set_font('helvetica', size=12)
    
    # ===== STATISTICS SECTION =====
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Statistics', ln=True)
    pdf.ln(2)
    
    pdf.set_font('helvetica', size=11)
    stats = [
        f"Total Logs: {report_data.get('total_logs', 0)}",
        f"Total Alerts: {report_data.get('total_alerts', 0)}",
        f"Success Rate: {report_data.get('success_rate', 0):.1f}%",
        f"Failed Count: {report_data.get('failed_count', 0)}"
    ]
    
    for stat in stats:
        pdf.cell(0, 8, stat, ln=True)
    
    pdf.ln(10)
    
    # ===== TOP IPs SECTION =====
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Top 5 Most Active IP Addresses', ln=True)
    pdf.ln(2)
    
    # Table header
    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(100, 8, 'IP Address', border=True)
    pdf.cell(0, 8, 'Log Count', border=True, ln=True)
    
    pdf.set_font('helvetica', size=11)
    top_ips = report_data.get('top_ips', [])
    for ip, count in top_ips[:5]:
        pdf.cell(100, 8, str(ip), border=True)
        pdf.cell(0, 8, str(count), border=True, ln=True)
    
    pdf.ln(10)
    
    # ===== RECENT ALERTS SECTION =====
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Recent Alerts', ln=True)
    pdf.ln(2)
    
    # Table header
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(50, 8, 'Timestamp', border=True)
    pdf.cell(30, 8, 'Severity', border=True)
    pdf.cell(0, 8, 'Description', border=True, ln=True)
    
    pdf.set_font('helvetica', size=9)
    recent_alerts = report_data.get('recent_alerts', [])
    for alert in recent_alerts[:10]:
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(alert, 'timestamp') else 'N/A'
        severity = str(alert.severity) if hasattr(alert, 'severity') else 'N/A'
        description = str(alert.description)[:50] if hasattr(alert, 'description') else 'N/A'
        
        pdf.cell(50, 8, timestamp, border=True)
        pdf.cell(30, 8, severity, border=True)
        pdf.cell(0, 8, description, border=True, ln=True)
    
    # Output PDF
    pdf.output(output_path)
    return output_path


# Example usage
if __name__ == '__main__':
    # Sample data for testing
    class MockAlert:
        def __init__(self, timestamp, severity, description):
            self.timestamp = timestamp
            self.severity = severity
            self.description = description
    
    from datetime import datetime
    
    sample_report = {
        'total_logs': 1500,
        'total_alerts': 45,
        'success_rate': 98.5,
        'failed_count': 12,
        'top_ips': [
            ('192.168.1.100', 450),
            ('10.0.0.50', 320),
            ('172.16.0.25', 280),
            ('192.168.1.200', 150),
            ('10.0.0.1', 100)
        ],
        'recent_alerts': [
            MockAlert(datetime.now(), 'High', 'Failed login attempt'),
            MockAlert(datetime.now(), 'Medium', 'Unusual traffic detected'),
            MockAlert(datetime.now(), 'Low', 'Port scan detected')
        ]
    }
    
    output_file = generate_report_pdf(sample_report, 'sample_report.pdf')
    print(f"PDF generated: {output_file}")