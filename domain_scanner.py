# import report_generator
# import ssl_certificate_info
# import whois_lookup
# import os
# from rich.console import Console

# class DomainScanner:
#     def __init__(self, domain):
#         self.domain = domain
#         self.output_dir = "output"
#         self.prepare_output_directory()

#     def prepare_output_directory(self):
#         if not os.path.exists(self.output_dir):
#             os.makedirs(self.output_dir)

#     def scan(self):
#         whois_info = whois_lookup.WHOISLookup.lookup(self.domain)
#         ssl_info = ssl_certificate_info.SSLCertificateInfo.get_info(self.domain)

#         report_generator.ReportGenerator.print_to_console(whois_info, ssl_info)
#         report_generator.ReportGenerator.save_text_file(self.domain, whois_info, ssl_info, self.output_dir)
#         report_generator.ReportGenerator.create_pdf(self.domain, whois_info, ssl_info, self.output_dir)

#         console = Console()
#         console.print(f"\n[bold magenta]Results saved in {self.output_dir}[/]")