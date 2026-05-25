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
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#1a2332'),
        spaceAfter=0.3*cm,
        spaceBefore=0.5*cm
    )

    #header 
    elements.append(Paragraph('pcap-sentinel', title_style))
    elements.append(Paragraph('Network Threat Detection Report', subtitle_style))
    elements.append(Paragraph(f'Generated: {datetime.now().strftime("%d %B %Y %H:%M")}', subtitle_style))
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

    #threat scores section 
    elements.append(Paragraph('Top IP Threat Scores', heading_style))

    severity_points = {"HIGH": 10, "MEDIUM": 5, "LOW": 1}
    threat_scores = {}
    threat_highest_severity = {}

    for f in findings_data:
        src = f.get('src')
        severity = f.get('Severity')
        if src and severity in severity_points:
            threat_scores[src] = threat_scores.get(src, 0) + severity_points[severity]
            current = threat_highest_severity.get(src, 'LOW')
            if severity == 'HIGH' or (severity == 'MEDIUM' and current == 'LOW'):
                threat_highest_severity[src] = severity

    top_threats = sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)[:10]

    threat_data = [['Rank', 'Source IP', 'Highest Severity', 'Threat Score']]
    for i, (ip, score) in enumerate(top_threats, 1):
        sev = threat_highest_severity.get(ip, "LOW")
        threat_data.append([str(i), ip, sev, str(score)])

    threat_table = Table(threat_data, colWidths=[2*cm, 7*cm, 5*cm, 3*cm])
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a2332')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f4f6f9'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('ALIGN', (3,0), (3,-1), 'CENTER'),
    ]))

    elements.append(threat_table)
    elements.append(Spacer(1, 0.5*cm))

    # high risk ports section
    elements.append(Paragraph('High Risk Ports Detected', heading_style))

    summary = next((f for f in findings_data if f.get('Severity') == 'INFO'), None)

    if summary and summary.get('risky_ports'):
        ports_data = [['Port / Service', 'Hit Count']]
        for entry in summary.get('risky_ports', []):
            parts = entry.split(':')
            if len(parts) == 2:
                ports_data.append([parts[0].strip(), parts[1].replace('hits', '').strip()])
            else:
                ports_data.append([entry, ''])

        ports_table = Table(ports_data, colWidths=[12*cm, 5*cm])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a2332')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f4f6f9'), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (1,0), (1,-1), 'CENTER'),
        ]))

        elements.append(ports_table)
    else:
        elements.append(Paragraph('No high risk ports detected.', subtitle_style))

    elements.append(Spacer(1, 0.5*cm))

    # detailed findings section
    elements.append(Paragraph('Detailed Findings', heading_style))

    findings_table_data = [['Severity', 'Source IP', 'Ports Probed', 'Risky Ports Hit', 'Scanner']]

    for f in findings_data:
        if f.get('Severity') in ['HIGH', 'MEDIUM', 'LOW']:
            findings_table_data.append([
                f.get('Severity', ''),
                f.get('src', ''),
                str(f.get('ports_probed', '')),
                str(f.get('risky_ports_count', '')),
                f.get('scanner', ''),
            ])

    findings_table = Table(findings_table_data, colWidths=[3*cm, 6*cm, 3*cm, 3*cm, 3*cm])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a2332')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f4f6f9'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (2,0), (3,-1), 'CENTER'),
        ('TEXTCOLOR', (0,1), (0,-1), colors.HexColor('#dc3545')),
    ]))

    # colour code severity column
    for i, f in enumerate(findings_data):
        if f.get('Severity') == 'HIGH':
            findings_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, i+1), (0, i+1), colors.HexColor('#dc3545'))
            ]))
        elif f.get('Severity') == 'MEDIUM':
            findings_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, i+1), (0, i+1), colors.HexColor('#fd7e14'))
            ]))
        elif f.get('Severity') == 'LOW':
            findings_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, i+1), (0, i+1), colors.HexColor('#28a745'))
            ]))

    elements.append(findings_table)
    elements.append(Spacer(1, 0.5*cm))
            
    doc.build(elements)
    buffer.seek(0)
    return buffer