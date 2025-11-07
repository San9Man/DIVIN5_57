import os
import requests
from datetime import datetime

# Get the API key from environment variables
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

def check_abuseipdb(ip):
    """
    Calls the real AbuseIPDB API.
    """
    if not ABUSEIPDB_API_KEY:
        print("Warning: ABUSEIPDB_API_KEY not set.")
        return {"source": "AbuseIPDB", "categories": [], "error": "API key not set"}

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': True  # Request full details
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an error for bad status codes
        
        data = response.json().get('data', {})
        if not data:
            # IP not found in AbuseIPDB, which is normal
            return {"source": "AbuseIPDB", "categories": [], "reports": 0, "geolocation": {}}

        categories = data.get('reportCategories', [])
        
        # Standardize geolocation
        geolocation = {
            "country": data.get('countryName', 'Unknown'),
            "country_code": data.get('countryCode', 'XX'),
            "city": data.get('city', 'Unknown'),
            "region": data.get('region', 'Unknown'),
            "isp": data.get('isp', 'Unknown'),
            "org": data.get('organization', 'Unknown'),
            "asn_name": data.get('isp', 'Unknown')
        }

        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "categories": list(set(categories)),  # Remove duplicates
            "reports": data.get('totalReports', 0),
            "raw_score": data.get('abuseConfidenceScore', 0),
            "asn": f"AS{data.get('asn', '')}",
            "geolocation": geolocation
        }

    except requests.exceptions.RequestException as e:
        print(f"Error calling AbuseIPDB: {e}")
        return {"source": "AbuseIPDB", "categories": [], "error": str(e)}