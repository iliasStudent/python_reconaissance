import whois
import requests
# import sslyze
import socket
import shodan
import ssl
import socket
from flask import Flask, request, render_template


app = Flask(__name__)

# Your existing functions remain here (whois_lookup, ssl_certificate_info)
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return str(w)  # Convert the result to string
    except Exception as e:
        return str(e)


def ssl_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                certificate = sslsock.getpeercert()
                # You can format certificate as a string or a dictionary
                return str(certificate)  # Convert to string for simplicity
    except Exception as e:
        return str(e)
    
# def shodan_scan(host):
#     api = shodan.Shodan(SHODAN_API_KEY)
    
#     try:
#         host_info = api.host(host)
#         open_ports = [item['port'] for item in host_info['data']]
#         return open_ports
#     except shodan.APIError as e:
#         return str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form['domain']

    # WHOIS Information
    whois_info = whois_lookup(domain)

    # SSL Certificate Information
    ssl_info = ssl_certificate_info(domain)

    return render_template('results.html', domain=domain, whois_info=whois_info, ssl_info=ssl_info)

if __name__ == '__main__':
    app.run(debug=True)






def main():
    pass
    # domain = input("Enter the domain to scan: ")
    
    # # WHOIS Information
    # print("\n[+] WHOIS Information:")
    # print(whois_lookup(domain))

    # # SSL Certificate Information
    # print("\n[+] SSL Certificate Information:")
    # print(ssl_certificate_info(domain))

if __name__ == "__main__":
    main()
