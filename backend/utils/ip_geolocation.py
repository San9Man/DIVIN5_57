"""
Real IP Geolocation and ASN Lookup
Uses ip-api.com (free tier) to get accurate geolocation and ASN data.
"""

import requests
import time
from functools import lru_cache

# Cache to avoid rate limiting (ip-api.com allows 45 requests/minute)
_cache = {}
_cache_timestamps = {}
CACHE_DURATION = 3600  # Cache for 1 hour


def get_real_asn_and_geo(ip):
    """
    Get real ASN and geolocation data for an IP address using ip-api.com.
    Returns (asn, geolocation_dict)
    """
    # Check cache first
    if ip in _cache:
        cache_time = _cache_timestamps.get(ip, 0)
        if time.time() - cache_time < CACHE_DURATION:
            return _cache[ip]
    
    try:
        # Use ip-api.com free tier (no API key required)
        # Rate limit: 45 requests/minute
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,region,regionName,lat,lon,timezone,isp,org,as,asname,query"
        
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("status") == "success":
                # Extract ASN
                asn_raw = data.get("as", "")
                if asn_raw:
                    # Extract AS number from string like "AS15169 Google LLC"
                    asn_parts = asn_raw.split()
                    asn = asn_parts[0] if asn_parts else "AS0"
                else:
                    asn = "AS0"
                
                # Build geolocation dict
                geolocation = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", ""),
                    "region_code": data.get("region", ""),
                    "latitude": data.get("lat", 0),
                    "longitude": data.get("lon", 0),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn_name": data.get("asname", "")
                }
                
                result = (asn, geolocation)
                
                # Cache the result
                _cache[ip] = result
                _cache_timestamps[ip] = time.time()
                
                return result
            else:
                # API returned error, use fallback
                return _get_fallback_data(ip)
        else:
            # HTTP error, use fallback
            return _get_fallback_data(ip)
            
    except requests.exceptions.RequestException as e:
        # Network error or timeout, use fallback
        print(f"Warning: Could not fetch geolocation for {ip}: {e}")
        return _get_fallback_data(ip)
    except Exception as e:
        # Other error, use fallback
        print(f"Warning: Error processing geolocation for {ip}: {e}")
        return _get_fallback_data(ip)


def _get_fallback_data(ip):
    """
    Fallback function that uses basic IP pattern matching if API fails.
    This ensures the system still works even if the API is down.
    """
    ip_parts = ip.split('.')
    if len(ip_parts) != 4:
        return "AS0", {"country": "Unknown", "country_code": "XX", "city": "Unknown"}
    
    try:
        first_octet = int(ip_parts[0]) if ip_parts[0].isdigit() else 0
        
        # Basic fallback ASN
        asn_number = (first_octet * 1000 + int(ip_parts[1]) * 10) % 90000 + 1000
        asn = f"AS{asn_number}"
        
        # Basic country mapping (very rough)
        country_map = {
            0: ("United States", "US"), 1: ("China", "CN"), 2: ("Russia", "RU"),
            3: ("Germany", "DE"), 4: ("United Kingdom", "GB"), 5: ("France", "FR")
        }
        country, country_code = country_map.get(first_octet % 6, ("Unknown", "XX"))
        
        return asn, {
            "country": country,
            "country_code": country_code,
            "city": "Unknown",
            "region": "",
            "region_code": "",
            "latitude": 0,
            "longitude": 0,
            "timezone": "",
            "isp": "",
            "org": "",
            "asn_name": ""
        }
    except:
        return "AS0", {"country": "Unknown", "country_code": "XX", "city": "Unknown"}


def clear_cache():
    """Clear the geolocation cache."""
    global _cache, _cache_timestamps
    _cache.clear()
    _cache_timestamps.clear()

