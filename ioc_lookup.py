import requests

VT_API_KEY = "41a599bae7daf9e0dde06bbf6da27d52924f3dd187b931d318f0a25a446e3567"
VT_URL = "https://www.virustotal.com/api/v3/search"

HEADERS = { "x-apikey": VT_API_KEY }

def lookup_ioc(ioc_value):
    response = requests.get(f"{VT_URL}?query={ioc_value}", headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        try:
            result = data['data'][0]
            return {
                "id": result["id"],
                "type": result["type"],
                "last_analysis_stats": result["attributes"]["last_analysis_stats"],
                "last_modification_date": result["attributes"]["last_modification_date"]
            }
        except:
            return {"error": "IOC not found or malformed response"}
    else:
        return {"error": f"Lookup failed ({response.status_code})"}
