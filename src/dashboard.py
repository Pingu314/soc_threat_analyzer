import logging
from flask import Flask
from src.main import run_pipeline

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route("/")
def home():
    return {"message": "SOC Dashboard running",
            "endpoint": "/alerts",
            "description": "View detected security alerts"}

@app.route("/alerts")
def alerts():
    result = run_pipeline()
    return {"alerts": result,
            "total_alerts": len(result)}

if __name__ == "__main__":
    app.run(debug=False)