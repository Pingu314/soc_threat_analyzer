import logging
from flask import Flask
from src.main import run_pipeline

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Run the detection pipeline once at startup and cache the result.
# This avoids re-parsing logs and making repeated ipinfo.io API calls on
# every request to /alerts.  Restart the server to pick up new log data.
_cached_alerts: list = run_pipeline()


@app.route("/")
def home():
    return {
        "message": "SOC Dashboard running",
        "endpoint": "/alerts",
        "description": "View detected security alerts",
    }


@app.route("/alerts")
def alerts():
    return {"alerts": _cached_alerts, "total_alerts": len(_cached_alerts)}


if __name__ == "__main__":
    app.run(debug=False)
