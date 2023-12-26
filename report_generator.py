import os
import json
from rich.console import Console
from rich.table import Table as RichTable
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as RLTable, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import ip_lookup
import internetdb_lookup

class ReportGenerator:

    @staticmethod
    def format_cell(text, style):
        text = str(text) if text is not None else "None"
        return Paragraph(text, style)

    @staticmethod    
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

    @staticmethod
    def create_pdf(domain, whois_info, ssl_info, output_dir):
        # Here internetdb
        # Get the IP address for the domain
        ip_address = ip_lookup.IpLookup.get_ip_address(domain)
        # Fetch internetdb information based on the IP address
        internetdb_info = internetdb_lookup.InternetdbLookup.fetch_json_internetdb_ipbased(ip_address)
        # Rename keys in the internetdb_info dictionary
        ordered_internetdb_info = {}
        for key, value in internetdb_info.items():
            if key == "ports":
                ordered_internetdb_info["open ports"] = value
            elif key == "cpes":
                ordered_internetdb_info["detected services"] = value
            elif key == "vulns":
                ordered_internetdb_info["vulnerabilities"] = value
            else:
                ordered_internetdb_info[key] = value
        internetdb_info = ordered_internetdb_info

        # End internetdb

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

        # IP address section
        elements.append(Paragraph(f"IP Address: {ip_lookup.IpLookup.get_ip_address(domain)}", styles['Heading2']))
        # WHOIS section
        elements.append(Paragraph("WHOIS Information:", styles['Heading2']))
        whois_data = ReportGenerator.parse_json_for_table(whois_info) if isinstance(whois_info, str) else ReportGenerator.parse_ssl_for_table(whois_info)
        whois_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in whois_data]
        whois_table = RLTable(whois_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
        whois_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                        ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
        elements.append(whois_table)

        # SSL section
        elements.append(Paragraph("SSL Certificate Information:", styles['Heading2']))
        ssl_data = ReportGenerator.parse_json_for_table(ssl_info) if isinstance(ssl_info, str) else ReportGenerator.parse_ssl_for_table(ssl_info)
        ssl_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in ssl_data]
        ssl_table = RLTable(ssl_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
        ssl_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                    ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
        elements.append(ssl_table)

        # InternetDB Information Section
        elements.append(Paragraph("InternetDB Information:", styles['Heading2']))
        internetdb_data = ReportGenerator.parse_json_for_table(json.dumps(internetdb_info))
        internetdb_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in internetdb_data]
        internetdb_table = RLTable(internetdb_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
        internetdb_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                              ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                              ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
        elements.append(internetdb_table)

        doc.build(elements)
        return pdf_filename
    
    
    @staticmethod
    def save_text_file(domain, whois_info, ssl_info, output_dir):
        txt_filename = os.path.join(output_dir, f"{domain}_scan_results.txt")
        with open(txt_filename, 'w') as file:
            file.write("WHOIS Information:\n")
            file.write(whois_info + "\n\n")

            file.write("SSL Certificate Information:\n")
            if isinstance(ssl_info, dict):
                formatted_ssl_info = json.dumps(ssl_info, indent=2)
                file.write(formatted_ssl_info + "\n")
            else:
                file.write(ssl_info + "\n")
        return txt_filename

    @staticmethod
    def print_results_to_console(whois_info, ssl_info):
        console = Console()

        

        # WHOIS Information
        whois_data = ReportGenerator.parse_json_for_table(whois_info) if isinstance(whois_info, str) else ReportGenerator.parse_ssl_for_table(whois_info)
        whois_table = RichTable(title="WHOIS Information", show_header=True, header_style="bold magenta")
        whois_table.add_column("Key", style="dim", width=12)
        whois_table.add_column("Value")
        for key, value in whois_data[1:]:
            whois_table.add_row(key, value)
        console.print(whois_table)

        # SSL Information
        ssl_data = ReportGenerator.parse_json_for_table(ssl_info) if isinstance(ssl_info, str) else ReportGenerator.parse_ssl_for_table(ssl_info)
        ssl_table = RichTable(title="SSL Certificate Information", show_header=True, header_style="bold magenta")
        ssl_table.add_column("Key", style="dim", width=12)
        ssl_table.add_column("Value")
        for key, value in ssl_data[1:]:
            ssl_table.add_row(key, value)
        console.print(ssl_table)

        # InternetDB Information
        # Fetch internetdb information
        # ip_address = ip_lookup.IpLookup.get_ip_address(domain)
        # internetdb_info = internetdb_lookup.InternetdbLookup.fetch_json_internetdb_ipbased(ip_address)

    @staticmethod
    def flatten_ssl_data(value):
        if isinstance(value, (list, tuple)):
            return ', '.join(ReportGenerator.flatten_ssl_data(item) for item in value)
        elif isinstance(value, dict):
            return json.dumps(value, indent=2)
        else:
            return str(value)

    @staticmethod    
    def parse_ssl_for_table(ssl_info):
        table_data = [["Key", "Value"]]
        for key, value in ssl_info.items():
            formatted_value = ReportGenerator.flatten_ssl_data(value)
            # Check if the value is too long and split it
            if key == "subjectAltName" and len(formatted_value) > 500:  # Example threshold
                formatted_value = formatted_value[:500] + '... [Truncated]'
            table_data.append([key, formatted_value])
        return table_data