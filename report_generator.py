import os
import json
from rich.console import Console
from rich.table import Table as RichTable
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as RLTable, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import ip_lookup

class ReportGenerator:

    @staticmethod
    def format_cell(text, style):
        # Formatteert de tekst voor een cel in de tabel met de opgegeven stijl.
        text = str(text) if text is not None else "None"
        return Paragraph(text, style)

    @staticmethod    
    def parse_json_for_table(json_str, max_length=100):
        # Converteert JSON-string naar tabeldata. Lange waarden worden ingekort.
        try:
            json_data = json.loads(json_str)
            table_data = [["Key", "Value"]]
            for key, value in json_data.items():
                formatted_value = ReportGenerator.flatten_ssl_data(value)
                # Truncate lange waarden
                if isinstance(formatted_value, str) and len(formatted_value) > max_length:
                    formatted_value = formatted_value[:max_length] + '... [Truncated]'
                table_data.append([key, formatted_value])
            return table_data
        except json.JSONDecodeError:
            return [["Error", "Invalid JSON data"]]

    @staticmethod
    def create_pdf(domain, whois_info, ssl_info, internetdb_info, found_links, http_headers, output_dir):
        # Creëert een PDF-bestand met de scanresultaten voor het opgegeven domein.

        pdf_filename = os.path.join(output_dir, f"{domain}_scan_results.pdf")
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Titelstijl instellen
        title_style = styles['Title'].clone('TitleStyle')
        title_style.textColor = colors.darkblue
        title_style.alignment = 1

        # Celstijl instellen
        cell_style = ParagraphStyle('CellStyle')
        cell_style.fontSize = 10
        cell_style.leading = 12

        # Titel schrijven
        title = f"Domain Scan Report for: {domain}"
        elements.append(Paragraph(title, title_style))

        # IP-adres sectie schrijven
        elements.append(Paragraph(f"IP Address: {ip_lookup.IpLookup.get_ip_address(domain)}", styles['Heading2']))

        # WHOIS-sectie schrijven als er om WHOIS-informatie werd gevraagd.
        if(whois_info is not None):
            elements.append(Paragraph("WHOIS Information:", styles['Heading2']))
            whois_data = ReportGenerator.parse_json_for_table(whois_info) if isinstance(whois_info, str) else ReportGenerator.parse_ssl_for_table(whois_info)
            whois_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in whois_data]
            whois_table = RLTable(whois_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
            whois_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                            ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
            elements.append(whois_table)

        # SSL-sectie schrijven als er om SSL-informatie werd gevraagd.
        if(ssl_info is not None):
            elements.append(Paragraph("SSL Certificate Information:", styles['Heading2']))
            ssl_data = ReportGenerator.parse_json_for_table(ssl_info) if isinstance(ssl_info, str) else ReportGenerator.parse_ssl_for_table(ssl_info)
            ssl_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in ssl_data]
            ssl_table = RLTable(ssl_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
            ssl_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                        ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
            elements.append(ssl_table)

        # security-sectie schrijven als er om internetdb-informatie werd gevraagd.
        if(internetdb_info is not None):
            elements.append(Paragraph("Security Scan Information:", styles['Heading2']))
            internetdb_data = ReportGenerator.parse_json_for_table(json.dumps(internetdb_info))
            internetdb_data_formatted = [[ReportGenerator.format_cell(cell, cell_style) for cell in row] for row in internetdb_data]
            internetdb_table = RLTable(internetdb_data_formatted, colWidths=[doc.width/3.0, 2*doc.width/3.0])
            internetdb_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                                ('ALIGN', (1, 1), (-1, -1), 'LEFT')]))
            elements.append(internetdb_table)

        # Links-sectie schrijven als er links zijn gevonden.
        if found_links:
            elements.append(Paragraph("Crawled Links:", styles['Heading2']))
            for link in found_links:
                elements.append(Paragraph(link, cell_style))

        # HTTP Headers sectie schrijven als er HTTP header informatie beschikbaar is.
        if http_headers:
            elements.append(Paragraph("HTTP Headers:", styles['Heading2']))
            for header, value in http_headers.items():
                header_paragraph = Paragraph(f"{header}: {value}", cell_style)
                elements.append(header_paragraph)

        # Bouw de PDF
        doc.build(elements)
        return pdf_filename
    
    
    @staticmethod
    def save_text_file(domain, whois_info, ssl_info, internetdb_info, found_links, http_headers, output_dir):
        # Creëert een tekstbestand met de scanresultaten.
        txt_filename = os.path.join(output_dir, f"{domain}_scan_results.txt")
        with open(txt_filename, 'w') as file:
            # WHOIS-sectie schrijven als er om WHOIS-informatie werd gevraagd.
            if(whois_info is not None):
                file.write("WHOIS Information:\n")
                file.write(whois_info + "\n\n")

            # SSL-sectie schrijven als er om SSL-informatie werd gevraagd.
            if(ssl_info is not None):
                file.write("SSL Certificate Information:\n")
                if isinstance(ssl_info, dict):
                    formatted_ssl_info = json.dumps(ssl_info, indent=2)
                    file.write(formatted_ssl_info + "\n")
                else:
                    file.write(ssl_info + "\n")

            # security-sectie schrijven als er om internetdb-informatie werd gevraagd.
            if(internetdb_info is not None):
                file.write("InternetDB Information:\n")
                file.write(json.dumps(internetdb_info, indent=2) + "\n")

            # Links-sectie schrijven als er links zijn gevonden.
            if found_links:
                file.write("Found Links:\n")
                for link in found_links:
                    file.write(link + "\n")
                file.write("\n")

            # HTTP Headers sectie schrijven als er HTTP header informatie beschikbaar is.
            if http_headers:
                file.write("HTTP Headers:\n")
                for header, value in http_headers.items():
                    file.write(f"{header}: {value}\n")
                file.write("\n")  # Extra newline toevoegen.
            
        return txt_filename

    @staticmethod
    def print_results_to_console(whois_info, ssl_info, internetdb_info, found_links, http_headers):
        # Creëert een console-uitvoer met behulp van de Rich-library.
        console = Console()

        # WHOIS-sectie outputten als er om WHOIS-informatie werd gevraagd.
        if(whois_info is not None):
            whois_data = ReportGenerator.parse_json_for_table(whois_info) if isinstance(whois_info, str) else ReportGenerator.parse_ssl_for_table(whois_info)
            whois_table = RichTable(title="WHOIS Information", show_header=True, header_style="bold magenta")
            whois_table.add_column("Key", style="dim", width=12)
            whois_table.add_column("Value")
            for key, value in whois_data[1:]:
                whois_table.add_row(key, value)
            console.print(whois_table)

        # SSL-sectie outputten als er om SSL-informatie werd gevraagd.
        if(ssl_info is not None):
            ssl_data = ReportGenerator.parse_json_for_table(ssl_info) if isinstance(ssl_info, str) else ReportGenerator.parse_ssl_for_table(ssl_info)
            ssl_table = RichTable(title="SSL Certificate Information", show_header=True, header_style="bold magenta")
            ssl_table.add_column("Key", style="dim", width=12)
            ssl_table.add_column("Value")
            for key, value in ssl_data[1:]:
                ssl_table.add_row(key, value)
            console.print(ssl_table)

        # Security-sectie outputten als er om internetdb-informatie werd gevraagd.
        if(internetdb_info is not None):
            internetdb_data = ReportGenerator.parse_json_for_table(json.dumps(internetdb_info))
            internetdb_table = RichTable(title="Security Scan Information", show_header=True, header_style="bold magenta")
            internetdb_table.add_column("Key", style="dim", width=12)
            internetdb_table.add_column("Value")
            for key, value in internetdb_data[1:]:
                internetdb_table.add_row(key, value)
            console.print(internetdb_table)

        # Links-sectie outputten als er links zijn gevonden.
        if found_links:
            links_table = RichTable(title="Crawled Links", show_header=True, header_style="bold magenta")
            links_table.add_column("URL", style="dim")
            for link in found_links:
                links_table.add_row(link)
            console.print(links_table)

        # HTTP Headers sectie outputten als er HTTP header informatie beschikbaar is.
        if http_headers:
            headers_table = RichTable(title="HTTP Headers", show_header=True, header_style="bold magenta")
            headers_table.add_column("Header", style="dim", width=20)
            headers_table.add_column("Value")
            for header, value in http_headers.items():
                headers_table.add_row(header, value)
            console.print(headers_table)

    @staticmethod
    def flatten_ssl_data(value):
        # Helpt bij het formatteren van geneste datastructuren voor weergave in tabellen.
        if isinstance(value, (list, tuple)):
            return ', '.join(ReportGenerator.flatten_ssl_data(item) for item in value)
        elif isinstance(value, dict):
            return json.dumps(value, indent=2)
        else:
            return str(value)

    @staticmethod    
    def parse_ssl_for_table(ssl_info):
        # Converteert SSL-informatie naar een formaat geschikt voor weergave in een tabel.
        table_data = [["Key", "Value"]]
        for key, value in ssl_info.items():
            formatted_value = ReportGenerator.flatten_ssl_data(value)
            # Als de waarde te lang is, dan knippen we een stuk.
            if key == "subjectAltName" and len(formatted_value) > 500:  # Drempelwaarde
                formatted_value = formatted_value[:500] + '... [Truncated]'
            table_data.append([key, formatted_value])
        return table_data