import os
import requests

def virus_total_search(domain):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"domain": domain, "apikey": os.getenv('API_KEY_VIRUSTOTAL')}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get("subdomains", [])
    else:
        print("Erreur avec l'API VirusTotal.")
        return []
