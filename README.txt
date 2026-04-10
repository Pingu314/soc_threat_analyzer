# SOC Threat Analyzer

A Python-based Security Operations Center (SOC) simulation tool that detects brute-force attacks and enriches them with threat intelligence

## Features
- Log parsing and analysis
- Brute-force detection using time windows
- IP enrichment via threat intelligence APIs
- Risk scoring system
- CSV alert export

## Architecture
Logs → Detection → Threat Intelligence → Risk Scoring → Alerts

## Technologies
- Python
- REST APIs
- Security Monitoring Concepts

## Use Case
Simulates real-world SOC analyst workflows including detection and incident prioritization

## Future Improvements
- SIEM integration (Splunk/ELK)
- Real-time monitoring
- Dashboard visualization

## Limitations
- Uses public IP API (no enterprise threat feed)

## How to Run

bash
pip install -r requirements.txt
python src/main.py

## Data Source
Sample logs are simulated to reflect common authentication patterns and brute-force attacks

## Disclaimer
This project is for educational purposes and simulates SOC workflows using synthetic data