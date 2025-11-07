from api_clients.abuseipdb import check_abuseipdb
from flask import Flask, request, jsonify, send_from_directory
from api_clients.virustotal import check_virustotal
from api_clients.alienvault import check_alienvault
from threat_scoring import calculate_score
from utils.normalization import normalize_results
from utils.correlation import correlate_results
from flask_cors import CORS
import os
try:
    # Attempt to load .env file if python-dotenv is installed
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    # python-dotenv not available; environment variables should be set externally
    pass
from datetime import datetime

app = Flask(__name__)
# Configure CORS to allow all origins for development
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/query": {"origins": "*"}})

# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "message": "Backend is running"})

# Reload IP lists from data files
@app.route("/api/reload-ips", methods=["POST"])
def reload_ips():
    try:
        from utils.ip_loader import reload_ip_lists, load_malicious_ips, load_legitimate_ips
        reload_ip_lists()
        malicious_count = len(load_malicious_ips())
        legitimate_count = len(load_legitimate_ips())
        return jsonify({
            "status": "success",
            "message": "IP lists reloaded",
            "malicious_ips_loaded": malicious_count,
            "legitimate_ips_loaded": legitimate_count
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to reload IP lists: {str(e)}"
        }), 500

# API routes must be defined BEFORE catch-all routes
# Frontend-compatible API endpoint
@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze_target():
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        return response
    
    # Get JSON data with error handling
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400
    
    target = data.get("target", "").strip()
    target_type = data.get("type", "ip").lower()
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    # For now, only IP addresses are supported by the backend
    if target_type != "ip":
        return jsonify({
            "error": f"Target type '{target_type}' not yet supported. Only 'ip' is currently supported."
        }), 400
    
    try:
        # Fetch data from APIs
        abuse_data = check_abuseipdb(target)
        vt_data = check_virustotal(target)
        av_data = check_alienvault(target)

        # Normalize & correlate
        normalized = normalize_results([abuse_data, vt_data, av_data])
        correlated = correlate_results(normalized)

        # Score - use normalized data (has source names as keys)
        score, risk = calculate_score(normalized)
    except Exception as e:
        return jsonify({
            "error": f"Analysis failed: {str(e)}",
            "details": "An error occurred while analyzing the IP address."
        }), 500
    
    # Convert score to 0-100 scale (multiply by appropriate factor)
    overall_score = min(100, max(0, int(score * 20)))  # Scale the score appropriately
    
    # Determine if malicious
    malicious = risk == "Malicious" or overall_score >= 60
    
    # Transform to frontend format
    sources = []
    findings = []
    correlations = []
    mitigation = []
    
    # Map source names
    source_map = {
        "AbuseIPDB": abuse_data,
        "VirusTotal": vt_data,
        "AlienVault OTX": av_data
    }
    
    for source_name, source_data in source_map.items():
        categories = source_data.get("categories", [])
        detected = len(categories) > 0
        
        # Calculate source score (0-100)
        source_score = min(100, len(categories) * 25) if detected else 0
        
        sources.append({
            "name": source_name,
            "detected": detected,
            "score": source_score,
            "timestamp": datetime.now().isoformat()
        })
        
        # Add findings from categories
        for category in categories:
            severity = "High" if source_score >= 70 else "Medium" if source_score >= 40 else "Low"
            findings.append({
                "type": category,
                "severity": severity,
                "source": source_name,
                "details": f"Detected as {category} by {source_name}"
            })
    
    # Add correlations
    if correlated.get("related_domains"):
        correlations.append(f"Related domains found: {', '.join(correlated['related_domains'][:3])}")
    if correlated.get("asn"):
        asn = correlated['asn']
        # Try to get ASN name from geolocation data
        geo = correlated.get("geolocation", {})
        asn_name = geo.get("asn_name", "") or geo.get("org", "")
        if asn_name and asn_name != "Unknown" and asn_name:
            correlations.append(f"ASN: {asn} ({asn_name})")
        else:
            correlations.append(f"ASN: {asn}")
    if correlated.get("geolocation"):
        geo = correlated["geolocation"]
        if geo.get("country"):
            city = geo.get("city", "")
            region = geo.get("region", "")
            country = geo.get("country", "")
            
            # Build location string
            location_parts = []
            if city and city != "Unknown":
                location_parts.append(city)
            if region:
                location_parts.append(region)
            location_parts.append(country)
            
            location_str = ", ".join(location_parts)
            correlations.append(f"Geolocation: {location_str}")
            
            # Add ISP/Organization if available
            if geo.get("isp"):
                correlations.append(f"ISP: {geo['isp']}")
            elif geo.get("org"):
                correlations.append(f"Organization: {geo['org']}")
    
    # Add mitigation recommendations
    if malicious or overall_score >= 60:
        mitigation.append("Block this IP address in firewall rules")
        mitigation.append("Add to threat intelligence blocklist")
        mitigation.append("Monitor network traffic from this source")
    elif overall_score >= 40:
        mitigation.append("Monitor this IP address for suspicious activity")
        mitigation.append("Review logs for any connections from this source")
    else:
        mitigation.append("No immediate action required")
    
    # Build response in frontend format
    response = {
        "overallScore": overall_score,
        "malicious": malicious,
        "sources": sources,
        "findings": findings,
        "correlations": correlations,
        "mitigation": mitigation,
        "timestamp": datetime.now().isoformat()
    }
    
    return jsonify(response)

# API route (original endpoint for backward compatibility)
@app.route("/query", methods=["POST"])
def query_ip():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400
    
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    # Fetch data from APIs
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

# Serve main frontend page
@app.route("/")
def index():
    return send_from_directory('../frontend', 'index.html')

# Serve static files (CSS, JS) - only for known file extensions
# This must be LAST to avoid catching API routes
@app.route("/<path:filename>")
def static_files(filename):
    # Only serve files with known extensions to avoid conflicts with API routes
    if '.' in filename and filename.rsplit('.', 1)[1].lower() in ['html', 'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico']:
        return send_from_directory('../frontend', filename)
    else:
        # If it's not a static file, return 404
        return jsonify({"error": "Not found"}), 404

if __name__ == "__main__":
    app.run(host='127.0.0.1', debug=True, port=5000)  
