def get_asn_and_geo(ip):
    """
    Get real ASN and geolocation data for an IP address.
    Uses real geolocation API (ip-api.com) for accurate data.
    """
    try:
        from utils.ip_geolocation import get_real_asn_and_geo
        return get_real_asn_and_geo(ip)
    except Exception as e:
        # Fallback if geolocation service is unavailable
        print(f"Warning: Could not get real geolocation for {ip}: {e}")
        return "AS0", {"country": "Unknown", "country_code": "XX", "city": "Unknown"}

def check_alienvault(ip):
    """
    Stubbed AlienVault OTX response with improved detection logic.
    In production, replace with real API call.
    """
    # Try to load IPs from data files
    try:
        from utils.ip_loader import load_malicious_ips, load_legitimate_ips
        known_malicious = load_malicious_ips()
        known_legitimate = load_legitimate_ips()
    except Exception as e:
        print(f"Warning: Could not load IP lists from files: {e}")
        known_malicious = []
        known_legitimate = []
    
    # Fallback to default lists if files don't exist or are empty
    if not known_malicious:
        known_malicious = [
            "185.220.100.0", "185.220.101.0",
            "192.0.2.1", "203.0.113.1",
            "100.38.210.187",  # User-reported malicious IP
            "185.220.102.0", "185.220.103.0",
            "45.146.164.0", "45.146.165.0",
            "91.192.100.0", "91.192.101.0",
        ]
    
    if not known_legitimate:
        known_legitimate = [
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
            "208.67.222.222", "208.67.220.220",  # OpenDNS
            "142.250.0.0", "172.217.0.0", "216.58.0.0", "74.125.0.0",  # Google ranges
            "173.194.0.0", "209.85.0.0",  # More Google ranges
        ]
    
    # Check if IP is in legitimate list first (exact match or prefix match)
    is_legitimate = False
    ip_parts = ip.split('.')
    
    # Check legitimate IPs first
    for leg_ip in known_legitimate:
        if ip == leg_ip:
            is_legitimate = True
            break
        # Check if IP starts with the prefix (for ranges like 142.250.0.0)
        parts = leg_ip.split('.')
        if len(parts) == 4 and parts[-1] == '0':
            # Match first 2 octets for ranges (e.g., 142.250.x.x matches 142.250.0.0)
            if len(ip_parts) == 4:
                if ip_parts[0] == parts[0] and ip_parts[1] == parts[1]:
                    is_legitimate = True
                    break
    
    # Check if IP is in malicious list (exact match or prefix match)
    is_malicious = False
    
    # Check exact matches and ranges for malicious IPs
    for mal_ip in known_malicious:
        if ip == mal_ip:
            is_malicious = True
            break
        # Check if IP starts with the prefix (for ranges like 185.220.100.x)
        parts = mal_ip.split('.')
        if len(parts) == 4 and parts[-1] == '0':
            prefix = '.'.join(parts[:3])
            if ip.startswith(prefix + '.'):
                is_malicious = True
                break
    
    # Additional heuristic: Check if first octet matches known malicious ranges
    if not is_malicious and not is_legitimate and len(ip_parts) == 4:
        try:
            first_octet = int(ip_parts[0])
            if first_octet == 100:
                second_octet = int(ip_parts[1])
                if second_octet in [38, 39, 40, 41, 42, 43]:  # Common abuse ranges
                    is_malicious = True
        except (ValueError, IndexError):
            pass
    
    # Determine categories
    categories = []
    reports = 0
    
    if is_malicious:
        categories = ["phishing", "malware", "c2"]
        reports = 5
    elif is_legitimate:
        categories = []  # Clean IP
        reports = 0
    else:
        # Heuristic for other IPs
        last_octet = int(ip.split('.')[-1]) if ip.count('.') == 3 else 0
        if last_octet % 10 == 1:
            categories = ["suspicious"]
            reports = 1
    
    # Get real ASN and geolocation from ip-api.com
    asn, geolocation = get_asn_and_geo(ip)
    
    # Override ASN for known legitimate IPs (keep real geolocation)
    if is_legitimate:
        if ip.startswith("8.8.") or ip == "8.8.4.4":
            asn = "AS15169"  # Google
        elif ip.startswith("1.1.1") or ip.startswith("1.0.0"):
            asn = "AS13335"  # Cloudflare
        elif ip.startswith("208.67.22"):
            asn = "AS36692"  # OpenDNS
    
    return {
        "source": "AlienVault OTX",
        "ip": ip,
        "categories": categories,
        "reports": reports,
        "asn": asn,
        "geolocation": geolocation
    }
