def correlate_results(normalized_data):
    all_categories = set()
    asn = ""
    geolocation = {}
    related_domains = []  # Demo stub
    
    for source, details in normalized_data.items():
        all_categories.update(details.get("categories", []))
        if not asn and details.get("asn"):
            asn = details.get("asn")
        if not geolocation and details.get("geolocation"):
            geolocation = details.get("geolocation")
    
    return {
        "categories": list(all_categories),
        "asn": asn,
        "geolocation": geolocation,
        "related_domains": related_domains,
        "per_source": normalized_data
    }
