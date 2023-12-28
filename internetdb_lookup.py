import requests

# API van shodan gebruiken voor security scan.
class InternetdbLookup:
    @staticmethod
    def fetch_json_internetdb_ipbased(ip):
        try:
            response = requests.get(f"https://internetdb.shodan.io/{ip}")
            response.raise_for_status()  # Geeft een HTTPError als de HTTP request een niet geslaagde status code retourneert
            return response.json()  # Geeft JSON antwoord terug.
        except requests.RequestException as e:
            return {"Error": str(e)}