import requests
from datetime import datetime

OTX_API_KEY = "5cb13ee75e1a58da9369dd8861f5e4da46f722447408733269b58ecd7c826557"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HEADERS = { "X-OTX-API-KEY": OTX_API_KEY }

def fetch_otx_iocs():
    response = requests.get(OTX_PULSES_URL, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        iocs = []
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                iocs.append({
                    "indicator": indicator["indicator"],
                    "type": indicator["type"],
                    "description": pulse.get("name", ""),
                    "source": "AlienVault OTX",
                    "date": datetime.strptime(indicator["created"], "%Y-%m-%dT%H:%M:%S"),
                    "tags": pulse.get("tags", []),
                })
        return iocs
    else:
        print("Fail
