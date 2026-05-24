from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm 
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from io import BytesIO
from datetime import datetime 

def generate_report(findings_data, pcap_filename):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    elements = []

    #styles 
    title_style = ParagraphStyle(
        'title',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1a2332'),
        spaceAfter=0.5*cm
    )

    subtitle_style = ParagraphStyle(
        'subtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#6c757d'),
        spaceAfter=0.2*cm
    )

    heading_style = ParagraphStyle(
        'heading',
        parent=styles['Heading'],
        fontSize=14,
        textColor=colors.HexColor('#1a2332'),
        spaceAfter=0.3*cm,
        spaceBefore=0.5*cm
    )

    #header 
    elements.append(Paragraph('pcap-sentinel', title_style))
    elements.append(Paragraph('Network Threat Detection Report', subtitle_style))
    elements.append(Paragraph(f'Generated: {datetime.now().strftime("%d %B %Y %H %M")}', subtitle_style))
    elements.append(Paragraph(f'File analysed: {pcap_filename}', subtitle_style))
    elements.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
    elements.append(Spacer(1, 0.5*cm))

    #executive summary
    high = len([f for f in findings_data if f.get('Severity') == 'HIGH'])
    medium = len([f for f in findings_data if f.get('Severity') == 'MEDIUM'])
    low = len([f for f in findings_data if f.get('Severity') == 'LOW'])
    total = high + medium + low
    scanners_run = len(set(f.get('scanner') for f in findings_data if f.get('scanner') and f.get('Severity') != 'INFO'))

    elements.append(Paragraph('Executive Summary', heading_style))

    summary_data = [
        ['Metric' , 'Value'],
        ['Total Findings', str(total)],
        ['High Severity', str(high)],
        ['Medium Severity', str(medium)],
        ['Low Severity', str(low)],
        ['Scanners Run', str(scanners_run)],
    ]

    summary_table = Table(summary_data, colWidths=[10*cm, 7*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a2332')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f4f6f9'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.5*cm))
            
    
    return buffer