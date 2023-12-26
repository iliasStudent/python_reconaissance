import whois

class WHOISLookup:
    @staticmethod
    def lookup(domain):
        try:
            w = whois.whois(domain)
            return str(w)
        except Exception as e:
            return str(e)