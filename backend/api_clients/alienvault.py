def check_alienvault(ip):
    # Stubbed response (replace with real API call)
    return {
        "source": "AlienVault",
        "ip": ip,
        "categories": ["phishing"] if ip.endswith("1") else [],
        "reports": 2,
        "asn": "AS12345",
        "geolocation": {"country": "US"}
    }
