import socket

class IpLookup:
    @staticmethod
    def get_ip_address(domain):
        try:
            # Get the IP address of the domain
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            # Handle error (e.g., hostname not found)
            return f"Error: {e}"