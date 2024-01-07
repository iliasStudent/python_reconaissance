import requests

class HTTPHeaderFetcher:
    @staticmethod
    def get_http_headers(domain):
        # Haal HTTP-headers van de opgegeven domein op en retourneer deze.
        try:
            response = requests.get(f"http://{domain}")
            return response.headers
        except requests.RequestException as e:
            print(f"Error making request: {e}")
            return {}