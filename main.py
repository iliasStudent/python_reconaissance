import whois
import ssl
import socket
import os
import argparse
import json
from rich.console import Console
from rich.table import Table as RichTable
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as RLTable, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

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
    text = str(text) if text is not None else "None"
    return Paragraph(text, style)

def parse_json_for_table(json_str):
    try:
        json_data = json.loads(json_str)
        table_data = [["Key", "Value"]]
        for key, value in json_data.items():
            if value is None:
                value = "None"
            elif isinstance(value, list):
                value = ', '.join(str(v) if v is not None else "None" for v in value)
            elif isinstance(value, dict):
                value = json.dumps(value, indent=2)
            table_data.append([key, str(value)])
        return table_data
    except json.JSONDecodeError:
        return [["Error", "Invalid JSON data"]]

def create_pdf(domain, whois_info, ssl_info, output_dir):
    pdf_filename = os.path.join(output_dir, f"{domain}_scan_results.pdf")
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    title_style = styles['Title'].clone('TitleStyle')
    title_style.textColor = colors.darkblue
    title_style.alignment = 1

    cell_style = ParagraphStyle('CellStyle')
    cell_style.wordWrap = 'CJK'
    cell_style.fontSize = 10
    cell_style.leading = 12

    title = f"Domain Scan Report for: {domain}"
    elements.append(Paragraph(title, title_style))

    elements.append(Paragraph("WHOIS Information:", styles['Heading2']))
    whois_data = parse_json_for_table(format_json(whois_info))
    whois_data_formatted = [[format_cell(cell, cell_style) for cell in row] for row in whois_data]
    whois_table = RLTable(whois_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
    whois_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                     ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                     ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
    elements.append(whois_table)

    elements.append(Paragraph("SSL Certificate Information:", styles['Heading2']))
    ssl_data = parse_json_for_table(format_json(ssl_info))
    ssl_data_formatted = [[format_cell(cell, cell_style) for cell in row] for row in ssl_data]
    ssl_table = RLTable(ssl_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
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

def print_results_to_console(whois_info, ssl_info):
    console = Console()

    whois_data = parse_json_for_table(format_json(whois_info))
    whois_table = RichTable(title="WHOIS Information", show_header=True, header_style="bold magenta")
    whois_table.add_column("Key", style="dim", width=12)
    whois_table.add_column("Value")
    for key, value in whois_data[1:]:
        whois_table.add_row(key, value)
    console.print(whois_table)

    ssl_data = parse_json_for_table(format_json(ssl_info))
    ssl_table = RichTable(title="SSL Certificate Information", show_header=True, header_style="bold magenta")
    ssl_table.add_column("Key", style="dim", width=12)
    ssl_table.add_column("Value")
    for key, value in ssl_data[1:]:
        ssl_table.add_row(key, value)
    console.print(ssl_table)

def main():
    parser = argparse.ArgumentParser(description="Domain Scan Tool")
    parser.add_argument("domain", help="Domain to scan")
    args = parser.parse_args()

    domain = args.domain
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    whois_info = whois_lookup(domain)
    ssl_info = ssl_certificate_info(domain)

    print_results_to_console(whois_info, ssl_info)

    txt_filename = save_text_file(domain, whois_info, ssl_info, output_dir)
    pdf_filename = create_pdf(domain, whois_info, ssl_info, output_dir)

    console = Console()
    console.print(f"\n[bold magenta]Results saved to {txt_filename} and {pdf_filename}[/]")

if __name__ == "__main__":
    main()
