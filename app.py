# app.py - Cyber Threat Intelligence (CTI) Dashboard
"""
CTI Dashboard - Flask + MongoDB
--------------------------------
Features:
- Aggregate OSINT feeds (Feodo, URLHaus, OpenPhish).
- Lookup IOCs via VirusTotal and AbuseIPDB.
- Store/query IOCs in MongoDB.
- Dashboard with trends, top malicious IPs/domains.
- IOC tagging + export (CSV, JSON, PDF).
"""

from dotenv import load_dotenv
load_dotenv()  # load .env file automatically

import os
import datetime
import requests
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient

from export_routes import export_bp  # import AFTER Flask is imported

app = Flask(__name__)                # 🔥 define app
app.register_blueprint(export_bp)   # ✅ register blueprint AFTER defining app

# Load API keys
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "41a599bae7daf9e0dde06bbf6da27d52924f3dd187b931d318f0a25a446e3567")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "1e52632884bce3e18719e72c86c0ca0b002205d399ed4148525bd989e3731a01d4e9b15ecf06ecf6")

# Flask app
app = Flask(__name__)
app.register_blueprint(export_bp)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]
ioc_collection = db["iocs"]

# ---------- Data Collection (placeholder OSINT feed fetcher) ----------
def fetch_osint_feeds():
    # Example IOC
    sample = {
        "type": "url",
        "value": "http://malicious-example.com",
        "timestamp": datetime.datetime.utcnow(),
        "tags": ["phishing"]
    }
    ioc_collection.insert_one(sample)

# ---------- Routes ----------
@app.route("/")
def dashboard():
    recent = list(ioc_collection.find().sort("timestamp", -1).limit(10))
    for r in recent:
        r["_id"] = str(r["_id"])
        r["timestamp"] = r.get("timestamp", "").strftime("%Y-%m-%d %H:%M:%S") if r.get("timestamp") else ""

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

    return render_template("dashboard.html",
                           recent=recent,
                           chart_data=type_counts,
                           trend_data=trend_data)

@app.route("/lookup")
def lookup():
    query = request.args.get("q")
    results = {}

    # Local DB
    db_hit = ioc_collection.find_one({"value": query})
    if db_hit:
        db_hit["_id"] = str(db_hit["_id"])
        db_hit["timestamp"] = str(db_hit.get("timestamp", ""))
        results["local_db"] = db_hit

    # VirusTotal
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        headers = {"x-apikey": VT_API_KEY}
        vt_resp = requests.get(vt_url, headers=headers)
        if vt_resp.status_code == 200:
            results["virustotal"] = vt_resp.json()
    except Exception as e:
        results["virustotal_error"] = str(e)

    # AbuseIPDB
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": query, "maxAgeInDays": "90"}
        abuse_resp = requests.get(abuse_url, headers=headers, params=params)
        if abuse_resp.status_code == 200:
            results["abuseipdb"] = abuse_resp.json()
    except Exception as e:
        results["abuseipdb_error"] = str(e)

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
