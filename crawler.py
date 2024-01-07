import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:

    @staticmethod
    def is_same_domain(url1, url2):
        # Controleert of twee URL's tot hetzelfde domein behoren.
        # Dit wordt gedaan om te voorkomen dat de crawler niet uit de hand loopt en andere domeinen begint te scannen.
        return urlparse(url1).netloc == urlparse(url2).netloc

    @staticmethod
    def crawl(starting_url, max_depth, max_links):
        # Start een webcrawling-sessie vanaf een start-URL (starting_url).
        # max_depth bepaalt hoe diep de crawler zal gaan (hoeveel subdirectories).
        # max_links is het maximale aantal links dat verzameld zal worden.
        def _crawl(url, max_depth, visited, link_count):
            # Interne hulpfunctie voor recursieve crawling.
            # url: de huidige URL om te crawlen.
            # max_depth: huidige diepte van de crawling.
            # visited: set van reeds bezochte URL's om duplicaten te voorkomen.
            # link_count: houdt bij hoeveel links er reeds zijn verzameld.

            # Controleer of de huidige URL al bezocht is, of dat de maximale diepte/links bereikt zijn.
            if url in visited or max_depth <= 0 or not Crawler.is_same_domain(url, starting_url) or link_count[0] >= max_links:
                return

            # Voeg de huidige URL toe aan de bezochte set en verhoog de linkteller.
            visited.add(url)
            link_count[0] += 1
            print(f"Crawling: {url}")

            try:
                # Verzoek om de HTML-content van de URL te krijgen.
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Zoek naar alle hyperlinks op de huidige pagina en crawl elk ervan.
                for link in soup.find_all('a', href=True):
                    if link_count[0] >= max_links:
                        break
                    absolute_link = urljoin(url, link['href'])
                    _crawl(absolute_link, max_depth - 1, visited, link_count)
            except requests.RequestException:
                pass  # Negeer mislukte requests

        # Initializeer de sets en tellers voor de crawling sessie.
        visited = set()
        link_count = [0]
        _crawl(starting_url, max_depth, visited, link_count)
        return visited
