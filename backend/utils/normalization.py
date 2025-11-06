def normalize_results(api_results):
    normalized = {}
    for res in api_results:
        source = res.get("source")
        normalized[source] = {
            "categories": res.get("categories", []),
            "reports": res.get("reports", 0),
            "asn": res.get("asn", ""),
            "geolocation": res.get("geolocation", {}),
        }
    return normalized
