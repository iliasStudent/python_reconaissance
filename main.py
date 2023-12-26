from rich.console import Console
import os
import argparse
import whois_lookup
import ssl_certificate_info
import report_generator


def main():
    parser = argparse.ArgumentParser(description="Domain Scan Tool")
    parser.add_argument("domain", help="Domain to scan")
    args = parser.parse_args()

    domain = args.domain
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    whois_info = whois_lookup.WHOISLookup.lookup(domain)
    ssl_info = ssl_certificate_info.SSLCertificateInfo.lookup(domain)

    report_generator.ReportGenerator.print_results_to_console(whois_info, ssl_info)

    txt_filename = report_generator.ReportGenerator.save_text_file(domain, whois_info, ssl_info, output_dir)
    pdf_filename = report_generator.ReportGenerator.create_pdf(domain, whois_info, ssl_info, output_dir)

    console = Console()
    console.print(f"\n[bold magenta]Results saved to {txt_filename} and {pdf_filename}[/]")

if __name__ == "__main__":
    main()
