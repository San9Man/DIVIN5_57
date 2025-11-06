def calculate_score(data):
    """
    Simple prototype scoring:
    - Each source has weight
    - Each threat type counts as points
    """
    weights = {"AbuseIPDB": 0.4, "VirusTotal": 0.4, "AlienVault": 0.2}
    score = 0
    
    for source, details in data.items():
        threat_count = len(details.get("categories", []))
        score += threat_count * weights.get(source, 0)
    
    # Determine risk
    if score > 2:
        risk = "Malicious"
    elif score > 0.5:
        risk = "Suspicious"
    else:
        risk = "Benign"
    
    return round(score, 2), risk
