from flask import Flask
from src.main import run_pipeline

app = Flask(__name__)

@app.route("/")
def home():
    return {"message": "SOC Dashboard running",
            "endpoint": "/alerts",
            "description": "View detected security alerts"}

@app.route("/alerts")
def alerts():
    return {"alerts": run_pipeline(),
            "total_alerts": len(run_pipeline())}

if __name__ == "__main__":
    app.run(debug=True)