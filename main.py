import whois
import ssl
import socket
import os
import argparse
from rich.console import Console
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from textwrap import wrap
import json
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return str(e)

def ssl_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                certificate = sslsock.getpeercert()
                return str(certificate)
    except Exception as e:
        return str(e)
    
def format_json(json_str):
    try:
        json_data = json.loads(json_str)
        formatted_json = json.dumps(json_data, indent=2)
        return formatted_json
    except json.JSONDecodeError:
        return json_str
    
def format_cell(text, style):
    # Ensure text is a string
    text = str(text) if text is not None else "None"
    return Paragraph(text, style)

    
def parse_json_for_table(json_str):
    try:
        json_data = json.loads(json_str)
        table_data = [["Key", "Value"]]
        for key, value in json_data.items():
            if value is None:
                value = "None"  # Convert None to a string
            elif isinstance(value, list):
                value = ', '.join(str(v) if v is not None else "None" for v in value)
            elif isinstance(value, dict):
                value = json.dumps(value, indent=2)  # Nested JSON formatting
            table_data.append([key, str(value)])  # Ensure all values are strings
        return table_data
    except json.JSONDecodeError:
        return [["Error", "Invalid JSON data"]]

def create_pdf(domain, whois_info, ssl_info, output_dir):
    pdf_filename = os.path.join(output_dir, f"{domain}_scan_results.pdf")
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Custom style for the title
    title_style = styles['Title'].clone('TitleStyle')
    title_style.textColor = colors.darkblue
    title_style.alignment = 1  # Center alignment

    # Custom style for table cells
    cell_style = ParagraphStyle('CellStyle')
    cell_style.wordWrap = 'CJK'  # Allows word wrapping in cells
    cell_style.fontSize = 10
    cell_style.leading = 12  # Space between lines

    # Title
    title = f"Domain Scan Report for: {domain}"
    elements.append(Paragraph(title, title_style))

    # WHOIS Information Subtitle and Table
    elements.append(Paragraph("WHOIS Information:", styles['Heading2']))
    whois_data = parse_json_for_table(format_json(whois_info))
    whois_data_formatted = [[format_cell(cell, cell_style) for cell in row] for row in whois_data]
    whois_table = Table(whois_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
    whois_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                     ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                     ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
    elements.append(whois_table)

    # SSL Certificate Information Subtitle and Table
    elements.append(Paragraph("SSL Certificate Information:", styles['Heading2']))
    ssl_data = parse_json_for_table(format_json(ssl_info))
    ssl_data_formatted = [[format_cell(cell, cell_style) for cell in row] for row in ssl_data]
    ssl_table = Table(ssl_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
    ssl_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                   ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                   ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
    elements.append(ssl_table)

    doc.build(elements)
    return pdf_filename

def save_text_file(domain, whois_info, ssl_info, output_dir):
    txt_filename = os.path.join(output_dir, f"{domain}_scan_results.txt")
    with open(txt_filename, 'w') as file:
        file.write("WHOIS Information:\n")
        file.write(whois_info + "\n\n")
        file.write("SSL Certificate Information:\n")
        file.write(ssl_info + "\n")
    return txt_filename

def draw_wrapped_text(c, text, x, y, max_width, font="Helvetica", font_size=12, bold=False):
    if bold:
        c.setFont("Helvetica-Bold", font_size)
    else:
        c.setFont(font, font_size)
    wrapped_text = wrap(text, max_width)
    for line in wrapped_text:
        c.drawString(x, y, line)
        y -= 15
    return y

def main():
    parser = argparse.ArgumentParser(description="Domain Scan Tool")
    parser.add_argument("domain", help="Domain to scan")
    args = parser.parse_args()

    domain = args.domain
    console = Console()
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    whois_info = whois_lookup(domain)
    ssl_info = ssl_certificate_info(domain)

    # Save results to TXT and PDF
    txt_filename = save_text_file(domain, whois_info, ssl_info, output_dir)
    pdf_filename = create_pdf(domain, whois_info, ssl_info, output_dir)

    console.print(f"\n[bold magenta]Results saved to {txt_filename} and {pdf_filename}[/]")

if __name__ == "__main__":
    main()
