import socket

class IpLookup:
    @staticmethod
    def get_ip_address(domain):
        try:
            # IP-adres krijgen van de domeinnaam
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            # Error behandelen bv. (hostname not found)
            return f"Error: {e}"