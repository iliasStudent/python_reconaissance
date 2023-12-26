import requests

class InternetdbLookup:
    @staticmethod
    def fetch_json_internetdb_ipbased(ip):
        try:
            response = requests.get(f"https://internetdb.shodan.io/{ip}")
            response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code
            return response.json()  # Returns JSON from the response
        except requests.RequestException as e:
            return {"Error": str(e)}