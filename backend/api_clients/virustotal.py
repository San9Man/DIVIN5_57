def check_virustotal(ip):
    # Stubbed response (replace with real API call)
    return {
        "source": "VirusTotal",
        "ip": ip,
        "categories": ["malware"] if ip.endswith("1") else [],
        "reports": 3,
        "asn": "AS12345",
        "geolocation": {"country": "US"}
    }
