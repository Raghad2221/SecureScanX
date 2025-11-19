# pdf.py
import os
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

ARTIFACTS_DIR = os.getenv('ARTIFACTS_DIR', 'scans')

def generate_pdf(scan_id: int, results: dict) -> str:
    pdf_path = os.path.join(ARTIFACTS_DIR, f'report_{scan_id}.pdf')
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                            leftMargin=0.5*inch, rightMargin=0.5*inch,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph('Vulnerability Scan Report', styles['Title']))
    story.append(Spacer(1, 12))

    # ZAP Section
    if results.get('zap'):
        story.append(Paragraph('ZAP Findings', styles['Heading2']))
        story.append(Spacer(1, 6))
        data = [['Type', 'Severity', 'URL', 'Description']]
        for a in results['zap']:
            data.append([a.get('type', ''), a.get('severity', ''),
                         (a.get('url', '') or '')[:50], a.get('description', '')])
        table = Table(data, colWidths=[1.5*inch, 1*inch, 2*inch, 2.5*inch])
        table.setStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ])
        story.append(table)
        story.append(Spacer(1, 12))
    else:
        story.append(Paragraph('No ZAP vulnerabilities found.', styles['Normal']))
        story.append(Spacer(1, 12))

    # Nuclei Section
    if results.get('nuclei'):
        story.append(Paragraph('Nuclei Findings', styles['Heading2']))
        story.append(Spacer(1, 6))
        data2 = [['Template', 'Severity', 'Type', 'Matched URL', 'Name']]
        for item in results['nuclei']:
            data2.append([
                item.get('template', ''),
                item.get('severity', ''),
                item.get('type', ''),
                (item.get('matched', '') or '')[:50],
                item.get('name', '')
            ])
        table2 = Table(data2, colWidths=[1.3*inch, 0.8*inch, 0.8*inch, 2.1*inch, 2.0*inch])
        table2.setStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ])
        story.append(table2)
    else:
        story.append(Paragraph('No Nuclei findings recorded.', styles['Normal']))

    doc.build(story)
    return pdf_path