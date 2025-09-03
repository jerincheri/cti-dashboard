from flask import Blueprint, jsonify, send_file
import csv
import io
from pymongo import MongoClient

# Create a Flask Blueprint
export_bp = Blueprint("export", __name__)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]
ioc_collection = db["iocs"]

@export_bp.route("/export/<string:format>")
def export_data(format):
    iocs = list(ioc_collection.find())

    # Clean and format data
    for ioc in iocs:
        ioc["_id"] = str(ioc["_id"])  # convert ObjectId to string
        ioc["timestamp"] = ioc.get("timestamp", "").strftime("%Y-%m-%d %H:%M:%S") if ioc.get("timestamp") else ""
        ioc["tags"] = ", ".join(ioc.get("tags", []))  # convert list to string
        ioc["threat_level"] = ioc.get("threat_level", "")

    # Export as JSON
    if format == "json":
        return jsonify(iocs)

    # Export as CSV
    elif format == "csv":
        output = io.StringIO()
        fieldnames = ["_id", "value", "type", "description", "tags", "threat_level", "source", "timestamp"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(iocs)
        output.seek(0)

        return send_file(
            io.BytesIO(output.read().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name="iocs.csv"
        )

    # Invalid format
    return jsonify({"error": "Invalid format. Use 'csv' or 'json'."}), 400
