from flask import Flask, request, jsonify
from api_clients.abuseipdb import check_abuseipdb
from api_clients.virustotal import check_virustotal
from api_clients.alienvault import check_alienvault
from threat_scoring import calculate_score
from utils.normalization import normalize_results
from utils.correlation import correlate_results
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

@app.route("/query", methods=["POST"])
def query_ip():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    # Fetch data from APIs (stub/demo)
    abuse_data = check_abuseipdb(ip)
    vt_data = check_virustotal(ip)
    av_data = check_alienvault(ip)

    # Normalize & correlate
    normalized = normalize_results([abuse_data, vt_data, av_data])
    correlated = correlate_results(normalized)

    # Score
    score, risk = calculate_score(correlated)

    # Build final report
    report = {
        "ip": ip,
        "score": score,
        "risk": risk,
        "categories": correlated.get("categories", []),
        "asn": correlated.get("asn", ""),
        "geolocation": correlated.get("geolocation", {}),
        "related_domains": correlated.get("related_domains", []),
        "per_source": normalized
    }

    return jsonify(report)

if __name__ == "__main__":
    app.run(debug=True)
