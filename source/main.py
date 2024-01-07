############################
# TargetVision             #
# Coder: Ilias Elal-Lati   #
############################

from rich.console import Console
import os
import argparse
import whois_lookup
import ssl_certificate_info
import report_generator
import internetdb_lookup
import ip_lookup
import crawler
import http_header

# Dit is de main section
def main():
    # Hier zorgen we ervoor dat de gebruiker parameters moet meegeven bij het gebruik van het programma.
    # De gebruiker moet verplicht meegeven welke domeinnaam dat die wilt scannen.
    parser = argparse.ArgumentParser(description="Domain Scan Tool")
    parser.add_argument("domain", help="Domain to scan")
    
    # Hier bieden we de mogelijkheid aan de gebruiker om een beperkte scan uit te voeren.
    # Een gebruiker die bijvoorbeeld enkel info over het SSL-certificaat wenst te hebben, moet enkel de -s of --ssl parameter meegeven.
    parser.add_argument("-w", "--whois", help="Perform WHOIS scan", action="store_true")
    parser.add_argument("-s", "--ssl", help="Perform SSL scan", action="store_true")
    parser.add_argument("-i", "--internetdb", help="Perform InternetDB scan", action="store_true")
    parser.add_argument("-c", "--crawl", help="Perform crawl hyperlinks", action="store_true")
    parser.add_argument("-t", "--header", help="Retrieve the http headers", action="store_true")
    args = parser.parse_args()

    # Hier zorgen we ervoor dat  alle scans standaard worden uitgevoerd indien de gebruiker niet specifieert welke scans dat die wilt uitvoeren.
    # Dit doen we door alle variabelen op True te zetten.
    if not (args.whois or args.ssl or args.internetdb or args.crawl or args.header):
        args.whois = args.ssl = args.internetdb = args.crawl = args.header = True

    # Domeinnaam extraheren van de parameter.
    domain = args.domain

    # Aanmaken van een output directory als deze nog niet bestaat.
    # In de output directory worden PDF en TXT bestanden gegenereert.
    
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Initialiseren van variabelen voor de opslag van scanresultaten.
    whois_info = None
    ssl_info = None
    internetdb_info = None
    crawling_info = None
    header_info = None

    # Uitvoeren van de gevraagde scans door de gebruiker.
    if(args.whois):
        whois_info = whois_lookup.WHOISLookup.lookup(domain)
    if(args.ssl):
        ssl_info = ssl_certificate_info.SSLCertificateInfo.lookup(domain)
    if(args.internetdb):
        internetdb_info = internetdb_lookup.InternetdbLookup.fetch_json_internetdb_ipbased(ip_lookup.IpLookup.get_ip_address(domain))
    if(args.header):
        header_info = http_header.HTTPHeaderFetcher.get_http_headers(domain)
    if(args.crawl):
        starting_url = f"https://{domain}"
        max_depth = 20  # Diepte van crawling (aantal subdirectories)
        max_links = int(input("Hoeveel links wil je maximaal crawlen?: "))
        crawling_info = crawler.Crawler.crawl(starting_url, max_depth, max_links)


    # Structuur van het resultaat van internetdb verbeteren voor een betere presentatie.
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
        
    # Printen van de resultaten naar de console.
    report_generator.ReportGenerator.print_results_to_console(whois_info, ssl_info, internetdb_info, crawling_info, header_info)

    # Opslaan van de resultaten in een tekstbestand en PDF en de paden naar deze bestanden opslaan in variabelen.
    txt_filename = report_generator.ReportGenerator.save_text_file(domain, whois_info, ssl_info, internetdb_info, crawling_info, header_info, output_dir)
    pdf_filename = report_generator.ReportGenerator.create_pdf(domain, whois_info, ssl_info, internetdb_info, crawling_info, header_info, output_dir)

    # Gebruik maken van de Rich-library
    # Aangeven waar de resultaten zijn opgeslagen. 
    console = Console()
    console.print(f"\n[bold magenta]Results saved to {txt_filename} and {pdf_filename}[/]")

# Zorgt ervoor dat de main functie wordt uitgevoerd wanneer het script zelf wordt gestart (aangesproken).
if __name__ == "__main__":
    main()
