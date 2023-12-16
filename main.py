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

def create_pdf(domain, whois_info, ssl_info, output_dir):
    pdf_filename = os.path.join(output_dir, f"{domain}_scan_results.pdf")
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter  # Width and height of the page

    # Centered Title
    title = f"Domain Scan Report for: {domain}"
    title_font_size = 16
    c.setFont("Helvetica-Bold", title_font_size)
    title_width = c.stringWidth(title, "Helvetica-Bold", title_font_size)
    c.setFillColor(colors.darkblue)
    c.drawString((width - title_width) / 2, 750, title)  # Center the title

    # WHOIS Information
    c.setFont("Helvetica", 12)
    c.setFillColor(colors.black)
    y_position = 720
    y_position = draw_wrapped_text(c, "WHOIS Information:", 50, y_position, 80)
    y_position -= 15  # Add space between title and content
    y_position = draw_wrapped_text(c, whois_info, 50, y_position, 80)

    # SSL Certificate Information
    y_position -= 30  # Add space between sections
    y_position = draw_wrapped_text(c, "SSL Certificate Information:", 50, y_position, 80)
    y_position -= 15
    y_position = draw_wrapped_text(c, ssl_info, 50, y_position, 80)

    c.save()
    return pdf_filename

def save_text_file(domain, whois_info, ssl_info, output_dir):
    txt_filename = os.path.join(output_dir, f"{domain}_scan_results.txt")
    with open(txt_filename, 'w') as file:
        file.write("WHOIS Information:\n")
        file.write(whois_info + "\n\n")
        file.write("SSL Certificate Information:\n")
        file.write(ssl_info + "\n")
    return txt_filename

def draw_wrapped_text(c, text, x, y, max_width):
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
