# TargetVision
### Overzicht
Het zal waarschijnlijk bekend voorkomen. Tijdens het pentesten van een website probeer je zoveel mogelijk informatie te vergaren. Je voert handmatig een DNS-lookup uit via de command line om het IP-adres te achterhalen, bezoekt de WHOIS-website, controleert de SSL-certificaten, opent voortdurend nieuwe tabbladen en voor je het weet, ben je het IP-adres vergeten of is de informatie uit de WHOIS-tool vervlogen. Dit proces is niet alleen inefficiënt en tijdrovend maar ook foutgevoelig, met het risico op het vergeten van cruciale gegevens.

Om deze uitdagingen het hoofd te bieden, komt een geïntegreerde scan tool zoals TargetVision als een uiterst praktische oplossing naar voren. Deze tool automatiseert deze taken en bundelt ze in één overzichtelijke interface en PDF, waardoor je aanzienlijk efficiënter kunt werken. Hierdoor voorkom je niet alleen tijdverlies en fouten door handmatige invoer, maar je bent ook verzekerd van consistente resultaten. TargetVision biedt zo een gestroomlijnde en betrouwbare aanpak om informatie te verzamelen en het risico op het vergeten van belangrijke details te minimaliseren.

### Beschrijving
TargetVision is ontworpen om uitgebreide informatie te verstrekken over domeinen door verschillende scans uit te voeren zoals WHOIS, SSL-certificaat, open poorten, CVE's, hostnames, CDN, services, web crawler en http header scan. Het is ideaal voor bug bounty hunters, security professionals, systeembeheerders of iedereen die inzicht wil krijgen in de status en beveiliging van een domein.

In de broncode zijn uitgebreide commentaren toegevoegd om ervoor te zorgen dat de code niet alleen gemakkelijk te begrijpen is, maar ook eenvoudig uit te breiden en te troubleshooten in latere stadia.

### Functionaliteiten

**WHOIS Scan**:  
Verkrijgt WHOIS-informatie van een domein, wat nuttig is voor het identificeren van de eigenaar, domein registrar en andere registratiegegevens.

**SSL Certificaat Scan**:  
Controleert de SSL-certificaat van een domein voor beveiligingsdoeleinden.
Met behulp van deze scan kun je uitgebreide informatie verkrijgen, waaronder bijvoorbeeld de Subject Alternate Name (SAN). Hiermee kun je ontdekken welke andere verborgen domeinen in het bezit zijn van de eigenaar van de website.

**InternetDB Scan**:  
- poort scan
- CVE scan
- Aangeboden services scan
- Hostname scan
- Content Delivery Network scan

Haalt gegevens op van de InternetDB API van Shodan voor verdere analyse van de domeinbeveiliging, waaronder informatie over geopende poorten, gedetecteerde diensten en bekende kwetsbaarheden.
Deze scan vereist meerdere requests, wat door backbones als verdachte pakketjes of een potentiële DDoS-aanval kan worden beschouwd.
Het gebruik van de API heeft dus als voordeel dat jouw IP-adres niet op een blacklist komt te staan aangezien de daadwerkelijke requests worden uitgevoerd door de Shodan-servers.

**Web crawler**:  
De webcrawler is een geavanceerde tool ontworpen om systematisch door websites te navigeren en informatie te verzamelen. 
Het is speciaal ontwikkeld om binnen een specifiek domein en zijn subdomeinen te opereren, terwijl het navigeert door hyperlinks tot een opgegeven diepte.
Deze functie onthult verborgen links in één oogopslag en biedt direct een overzicht van de inhoud van de website.

**HTTP Header**:  
Met deze functie heb je een overzicht van de HTTP header van de website.
Het biedt uitgebreide informatie over de server, aangeboden services en de versies daarvan. Het vormt een waardevolle bron voor pentesters.

**Rapportage**:  
Genereert gedetailleerde rapporten in zowel PDF- als tekstformaat, naast het weergeven van informatie in de console.

**Gebruiksgemak**:  
Biedt een eenvoudige command-line interface voor het uitvoeren van scans en het bekijken van rapporten.

### Installatie
1. Doe een git clone van deze repository

2. Voordat je de tool kan gebruiken, dien je de benodigde dependencies te installeren. 
Dit kan je doen door het volgende commando uit te voeren:  
```pip install -r requirements.txt```

### Gebruik
Om de tool te gebruiken, voer je het script uit met de domeinnaam als argument. Je kan ook specifieke scans selecteren door bepaalde flags mee te geven.

**Beschikbare flags:**
- -w = WHOIS scan
- -s = SSL certificaat scan
- -i = InternetDB scan
- -c = Web crawler scan
- -t = HTTP Headers scan
  
**Hieronder vind je een voorbeeld van hoe je het script kan gebruiken:**

Alle scans: ```python main.py www.voorbeelddomein.com```

Alleen WHOIS-scan: ```python main.py www.voorbeelddomein.com -w```

Alleen SSL-scan: ```python main.py www.voorbeelddomein.com -s```

Alleen security-scan:  ```python main.py www.voorbeelddomein.com -i```

Alleen SSL & WHOIS -scan: ```python main.py www.voorbeelddomein.com -ws```


Als geen specifieke scanoptie is opgegeven, voert het script standaard alle beschikbare scans uit.

### Uitvoer

De tool genereert rapporten in PDF- en tekstformaat in de opgegeven output directory. Deze bestanden bevatten de verzamelde informatie in een georganiseerd en leesbaar formaat.

### Belangrijk om te weten
Soms kan de verkregen informatie zo groot zijn dat deze niet meer in de tabel past. Als gevolg hiervan zul je mogelijk de aanduiding "truncated" zien, wat betekent dat de overige informatie is ingekort en weggelaten.

Je kunt de volledige set informatie terugvinden in het bijbehorende .txt-bestand binnen de output folder.

### Have fun!
Voer een scan uit op www.ap.be en op www.ba.be .  
Je ziet een hoop vulnerabilities staan.  
Niet goed he!
