from rich.console import Console
import os
import argparse
import whois_lookup
import ssl_certificate_info
import report_generator
import internetdb_lookup
import ip_lookup


def main():
    parser = argparse.ArgumentParser(description="Domain Scan Tool")
    parser.add_argument("domain", help="Domain to scan")
    # parser.add_argument("--scan_type", help="Type of scan to perform ('whois (w)', 'ssl (s)', 'internetdb (i)', 'all (a)')", choices=['whois', 'ssl', 'internetdb', 'all', "w", "s", "i", "a"], default='all')
    parser.add_argument("-w", "--whois", help="Perform WHOIS scan", action="store_true")
    parser.add_argument("-s", "--ssl", help="Perform SSL scan", action="store_true")
    parser.add_argument("-i", "--internetdb", help="Perform InternetDB scan", action="store_true")
    args = parser.parse_args()

    # Set all to True if none are specified
    if not (args.whois or args.ssl or args.internetdb):
        args.whois = args.ssl = args.internetdb = True

    domain = args.domain

    print(args)
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    whois_info = None
    ssl_info = None
    internetdb_info = None
    if(args.whois):
        whois_info = whois_lookup.WHOISLookup.lookup(domain)
    if(args.ssl):
        ssl_info = ssl_certificate_info.SSLCertificateInfo.lookup(domain)
    if(args.internetdb):
        internetdb_info = internetdb_lookup.InternetdbLookup.fetch_json_internetdb_ipbased(ip_lookup.IpLookup.get_ip_address(domain))

    if(args.internetdb):
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
        

    report_generator.ReportGenerator.print_results_to_console(whois_info, ssl_info, internetdb_info)

    txt_filename = report_generator.ReportGenerator.save_text_file(domain, whois_info, ssl_info, internetdb_info, output_dir)
    pdf_filename = report_generator.ReportGenerator.create_pdf(domain, whois_info, ssl_info, internetdb_info, output_dir)

    console = Console()
    console.print(f"\n[bold magenta]Results saved to {txt_filename} and {pdf_filename}[/]")

if __name__ == "__main__":
    main()
