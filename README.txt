# SOC Threat Analyzer

A Python-based Security Operations Center (SOC) simulation tool that detects brute-force login attempts, enriches them with threat intelligence, and prioritizes alerts using risk scoring

## Scenario
This project simulates a SOC environment where multiple failed login attempts may indicate a brute-force attack
The goal is to:
- Detect suspicious login behavior
- Enrich alerts with threat intelligence
- Prioritize incidents using a risk scoring model

## Detection logic
- Groups failed login attempts by IP
- Applies time-window correlation
- Triggers alert when threshold is exceeded

## Example alert


## Features
- Log parsing and analysis
- Brute-force detection using time-window correlation
- IP enrichment via external threat intelligence APIs
- Risk scoring system based on attack intensity and origin
- Alert prioritization using severity levels
- CSV export for further analysis

## Architecture
Logs -> Parser -> Detection Engine -> Threat Intelligence -> Risk Scoring -> Alerts

## Technologies
- Python
- REST APIs
- Security Monitoring Concepts

## Use Case
Simulates real-world SOC analyst workflows including detection and incident prioritization

## Future Improvements
- SIEM integration (Splunk/ELK)
- Real-time log ingestion
- Dashboard visualization (Flask-based UI)
- Alert correlation across multiple sources

## Limitations
- Uses public IP API (no enterprise threat feed)
- Simulated log data (no real production logs)

## How to Run
bash
pip install -r requirements.txt
python src/main.py

## Data Source
Sample logs are simulated to reflect common authentication patterns and brute-force attacks

## Disclaimer
This project is for educational purposes and simulates SOC workflows using synthetic data