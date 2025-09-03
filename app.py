# app.py - Cyber Threat Intelligence (CTI) Dashboard
"""
CTI Dashboard - Flask + MongoDB
--------------------------------
Features:
- Aggregate OSINT feeds (Feodo, URLHaus, OpenPhish, OTX).
- Lookup IOCs via VirusTotal, AbuseIPDB, AlienVault OTX.
- Store/query IOCs in MongoDB.
- Dashboard with trends, top malicious IPs/domains.
- IOC tagging + export (CSV, JSON).
"""

from dotenv import load_dotenv
load_dotenv()

import os
import datetime
import requests
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient

from export_routes import export_bp

app = Flask(__name__)
app.register_blueprint(export_bp)

# Load API keys
VT_API_KEY = os.getenv("VT_API_KEY", "demo")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "demo")
OTX_API_KEY = os.getenv("OTX_API_KEY", "demo")

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]
ioc_collection = db["iocs"]

# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def dashboard():
    recent = list(ioc_collection.find().sort("timestamp", -1).limit(10))
    for r in recent:
        r["_id"] = str(r["_id"])
        if r.get("timestamp"):
            r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            r["timestamp"] = ""

    # IOC distribution
    type_counts = {}
    for r in ioc_collection.find():
        t = r.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    # IOC trends (count per day)
    pipeline = [
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    trend_data = list(ioc_collection.aggregate(pipeline))

    # ✅ Stats for dashboard cards
    stats = {
        "total": ioc_collection.count_documents({}),
        "ips": ioc_collection.count_documents({"type": "ip"}),
        "domains": ioc_collection.count_documents({"type": "domain"}),
        "urls": ioc_collection.count_documents({"type": "url"})
    }

    return render_template(
        "dashboard.html",
        recent=recent,
        chart_data=type_counts,
        trend_data=trend_data,
        stats=stats
    )

@app.route("/lookup", methods=["GET"])
def lookup():
    query = request.args.get("q")
    results = {}
    threat_level = "Unknown"

    if not query:
        return render_template("lookup.html", query=None, results=None, threat_level=threat_level)

    # Local DB check
    db_hit = ioc_collection.find_one({"value": query})
    if db_hit:
        db_hit["_id"] = str(db_hit["_id"])
        db_hit["timestamp"] = str(db_hit.get("timestamp", ""))
        results["local_db"] = db_hit

    # VirusTotal lookup
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        headers = {"x-apikey": VT_API_KEY}
        vt_resp = requests.get(vt_url, headers=headers)
        if vt_resp.status_code == 200:
            vt_data = vt_resp.json()
            results["virustotal"] = vt_data
            positives = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if positives > 10:
                threat_level = "High"
            elif positives > 0:
                threat_level = "Medium"
            else:
                threat_level = "Low"
    except Exception as e:
        results["virustotal_error"] = str(e)

    # AbuseIPDB lookup
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": query, "maxAgeInDays": "90"}
        abuse_resp = requests.get(abuse_url, headers=headers, params=params)
        if abuse_resp.status_code == 200:
            abuse_data = abuse_resp.json()
            results["abuseipdb"] = abuse_data
    except Exception as e:
        results["abuseipdb_error"] = str(e)

    # OTX lookup
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        otx_resp = requests.get(otx_url, headers=headers)
        if otx_resp.status_code == 200:
            results["otx"] = otx_resp.json()
    except Exception as e:
        results["otx_error"] = str(e)

    return render_template("lookup.html", query=query, results=results, threat_level=threat_level)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
