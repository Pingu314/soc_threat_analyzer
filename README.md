# SOC Threat Analyzer

A Python-based Security Operations Center (SOC) simulation tool that detects brute-force login attempts, enriches them with threat intelligence, and prioritizes alerts using risk scoring.

## Scenario

This project simulates a SOC environment where multiple failed login attempts may indicate a brute-force attack.

Goals:

* Detect suspicious login behavior via time-window correlation
* Enrich alerts with threat intelligence (ipinfo.io)
* Prioritize incidents using a risk scoring model
* Map detections to MITRE ATT\&CK (T1110 – Brute Force)

## Architecture

```
Logs → Parser → Detection Engine → Threat Intelligence → Risk Scoring → Alerts (CSV)
```

## Example Alert Output

```
{"ip": "185.220.101.1",
 "count": 4,
 "country": "DE",
 "org": "AS205100 F3 Netze e.V.",
 "risk\_score": 12,
 "severity": "HIGH",
 "mitre\_technique": "T1110"}
```

## Features

* Log parsing with error handling and skip-logging
* Brute-force detection using time-window correlation (configurable threshold)
* IP enrichment via ipinfo.io with in-memory caching
* Private IP detection (10.x, 192.168.x, 172.16.x) – no wasted API calls
* Risk scoring based on attack intensity, country, and org
* MITRE ATT\&CK mapping
* Alert export to CSV
* Flask dashboard at `/alerts`
* Full logging via Python `logging` module
* Unit tests with pytest

## Technologies

* Python 3.10+
* Flask (dashboard API)
* requests (threat intelligence)
* ipinfo.io (public IP enrichment API)
* pytest (unit testing)
* MITRE ATT\&CK (T1110)

## How to Run

```bash
pip install -r requirements.txt
python src/main.py
```

For the Flask dashboard:

```bash
python src/dashboard.py
# → http://localhost:5000/alerts
```

For tests:

```bash
pip install pytest
python -m pytest tests/
```

## Configuration

Edit `config/settings.py`:

```python
THRESHOLD = 3        # failed logins to trigger alert
WINDOW\_MINUTES = 5   # time window for correlation
```

## Risk Scoring

|Factor|Points|
|-|-|
|Each failed login|+3|
|Suspicious country (RU, CN, KP)|+5|
|Tor exit node|+5|

|Score|Severity|
|-|-|
|0–5|LOW|
|6–11|MEDIUM|
|12+|HIGH|

## Limitations

* Uses public ipinfo.io API (no enterprise threat feed)
* Simulated log data (no real production logs)
* In-memory cache (resets on restart)

## Future Improvements

* SIEM integration (Splunk/ELK)
* Real-time log ingestion
* Persistent cache (Redis)
* Dashboard visualization
* Alert correlation across multiple sources
* AbuseIPDB or VirusTotal integration

## Disclaimer

This project is for educational purposes and simulates SOC workflows using synthetic data

