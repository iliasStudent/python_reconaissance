import ssl
import socket

class SSLCertificateInfo:
    # Geeft alle informatie omtrent het SSL-certificaat op basis van de domeinnaam.
    @staticmethod
    def lookup(domain):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                    certificate = sslsock.getpeercert()
                    return certificate  # Geeft een dictionary terug.
        except Exception as e:
            return str(e)