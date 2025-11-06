def check_abuseipdb(ip):
    # Stubbed response (replace with real API call)
    return {
        "source": "AbuseIPDB",
        "ip": ip,
        "categories": ["spam", "botnet"] if ip.endswith("1") else [],
        "reports": 5,
        "asn": "AS12345",
        "geolocation": {"country": "US"}
    }
