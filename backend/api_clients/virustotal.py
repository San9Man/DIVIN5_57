import os
import requests

# Get the API key from environment variables
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

def check_virustotal(ip):
    """
    Calls the real VirusTotal API (v3).
    """
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VIRUSTOTAL_API_KEY not set.")
        return {"source": "VirusTotal", "categories": [], "error": "API key not set"}

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'Accept': 'application/json',
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json().get('data', {}).get('attributes', {})
        if not data:
            return {"source": "VirusTotal", "categories": [], "geolocation": {}}

        categories = []
        
        # Get categories from analysis results
        analysis_results = data.get('last_analysis_results', {})
        for engine_name, result in analysis_results.items():
            category = result.get('category')
            if category not in ['harmless', 'undetected', None]:
                categories.append(category)

        # Also check community reputation
        if data.get('reputation', 0) < -10:
             categories.append("malicious")

        # Standardize geolocation
        geolocation = {
            "country": data.get('country', 'Unknown'),
            "country_code": data.get('country', 'XX'),
            "isp": data.get('as_owner', 'Unknown'),
            "org": data.get('as_owner', 'Unknown'),
            "asn_name": data.get('as_owner', 'Unknown')
        }

        return {
            "source": "VirusTotal",
            "ip": ip,
            "categories": list(set(categories)),  # Remove duplicates
            "reports": data.get('last_analysis_stats', {}).get('malicious', 0),
            "raw_score": data.get('reputation', 0),
            "asn": f"AS{data.get('asn', '')}",
            "geolocation": geolocation
        }

    except requests.exceptions.RequestException as e:
        print(f"Error calling VirusTotal: {e}")
        return {"source": "VirusTotal", "categories": [], "error": str(e)}