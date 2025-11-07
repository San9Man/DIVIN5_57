import os
import requests

# Get the API key from environment variables
ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY')

def check_alienvault(ip):
    """
    Calls the real AlienVault OTX API.
    """
    if not ALIENVAULT_API_KEY:
        print("Warning: ALIENVAULT_API_KEY not set.")
        return {"source": "AlienVault OTX", "categories": [], "error": "API key not set"}

    url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
    headers = {
        'Accept': 'application/json',
        'X-OTX-API-KEY': ALIENVAULT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        if not data:
            return {"source": "AlienVault OTX", "categories": [], "geolocation": {}}

        categories = []
        
        # Get categories from "pulses" (threat reports)
        pulses = data.get('pulse_info', {}).get('pulses', [])
        for pulse in pulses:
            tags = pulse.get('tags', [])
            for tag in tags:
                # Avoid generic tags
                if tag.lower() not in ['ip', 'malicious', 'alienvault']:
                    categories.append(tag)

        # Standardize geolocation
        geolocation = {
            "country": data.get('country_name', 'Unknown'),
            "country_code": data.get('country_code', 'XX'),
            "city": data.get('city', 'Unknown'),
            "isp": data.get('asn', 'Unknown').split(' ', 1)[-1] if data.get('asn') else 'Unknown',
            "org": data.get('asn', 'Unknown').split(' ', 1)[-1] if data.get('asn') else 'Unknown',
            "asn_name": data.get('asn', 'Unknown').split(' ', 1)[-1] if data.get('asn') else 'Unknown',
        }

        return {
            "source": "AlienVault OTX",
            "ip": ip,
            "categories": list(set(categories)),  # Remove duplicates
            "reports": len(pulses),
            "raw_score": len(pulses) * 5,  # Simple score based on pulse count
            "asn": data.get('asn', 'AS0 Unknown').split(' ')[0],
            "geolocation": geolocation
        }

    except requests.exceptions.RequestException as e:
        print(f"Error calling AlienVault OT: {e}")
        return {"source": "AlienVault OTX", "categories": [], "error": str(e)}