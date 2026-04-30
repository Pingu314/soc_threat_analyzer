import logging
from flask import Flask

from src.main import run_pipeline

app = Flask(__name__)
logger = logging.getLogger(__name__)

_cached_alerts: list | None = None


def _get_alerts() -> list:
    global _cached_alerts
    if _cached_alerts is None:
        _cached_alerts = run_pipeline()
    return _cached_alerts


@app.route("/")
def home():
    """Return a JSON welcome message with the available /alerts endpoint"""
    return {"message": "SOC Dashboard running",
            "endpoint": "/alerts",
            "description": "View detected security alerts"}


@app.route("/alerts")
def alerts():
    """Return all cached alerts as JSON with a total count"""
    data = _get_alerts()
    return {"alerts": data, "total_alerts": len(data)}


if __name__ == "__main__":
    app.run(debug=False)