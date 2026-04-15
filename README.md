# SOC Threat Analyzer

A Python-based Security Operations Center (SOC) simulation tool that detects authentication-based attacks, enriches alerts with threat intelligence, and prioritizes incidents using risk scoring mapped to MITRE ATT&CK.

> I built this project while studying for CompTIA Security+ and working through
> TryHackMe SOC Level 1. My goal was to simulate real SOC Tier 1 workflows in
> code — detection, enrichment and triage — rather than just reading about them.
> I learn best hands-on.

## Scenario

This project simulates a SOC environment where authentication log analysis is used to detect active attack patterns. The pipeline mirrors real SOC Tier 1 workflows:

```
Ingest -> Parse -> Detect -> Enrich -> Score -> Alert
```

## Detection Rules (SIGMA-based)

All rules are defined as functional SIGMA-style dicts in `src/detector.py`. Thresholds and time windows are driven by `config/settings.py` — no hardcoded values.

| Rule ID | Rule | MITRE Technique | Trigger |
|---------|------|----------------|---------|
| bf-001 | Brute Force Detection | T1110.001 – Password Guessing | ≥3 failed logins from one IP within 5 min |
| ps-001 | Password Spraying Detection | T1110.003 – Password Spraying | ≥3 distinct users targeted from one IP within 10 min |
| it-001 | Impossible Travel Detection | T1078 – Valid Accounts | Same user from ≥2 distinct IPs within 5 min |

## Example Output

Running `python -m src.main` against the sample logs produces 8 alerts across all three rules:

```text
$ python -m src.main

[bf-001] Brute force from 185.220.101.1 (4 attempts)
[bf-001] Brute force from 192.168.1.10 (3 attempts)
[bf-001] Brute force from 1.1.1.1 (3 attempts)
[bf-001] Brute force from 45.83.64.1 (5 attempts)
[ps-001] Password spraying from 45.83.64.1 targeting ['admin', 'guest', 'operator', 'root', 'test']
[it-001] Impossible travel for 'admin' across ['1.1.1.1', '192.168.1.10']
[it-001] Impossible travel for 'jsmith' across ['103.21.244.0', '185.220.101.1']
[it-001] Impossible travel for 'root' across ['45.83.64.1', '8.8.8.8']

Total alerts after deduplication: 8
```

**Sample enriched alerts (JSON):**

```json
{
  "rule_id": "bf-001",
  "rule": "Brute Force Detection",
  "mitre": "T1110.001",
  "sigma_severity": "high",
  "ip": "185.220.101.1",
  "user": "multiple",
  "count": 4,
  "country": "DE",
  "org": "AS60729 Stiftung Erneuerbare Freiheit",
  "risk_score": 12,
  "severity": "HIGH"
}
{
  "rule_id": "ps-001",
  "rule": "Password Spraying Detection",
  "mitre": "T1110.003",
  "sigma_severity": "high",
  "ip": "45.83.64.1",
  "user": "multiple",
  "count": 5,
  "country": "DE",
  "org": "AS208843 Alpha Strike Labs GmbH",
  "risk_score": 25,
  "severity": "HIGH",
  "distinct_users": "admin, guest, operator, root, test"
}
{
  "rule_id": "it-001",
  "rule": "Impossible Travel Detection",
  "mitre": "T1078",
  "sigma_severity": "medium",
  "ip": "multiple",
  "user": "jsmith",
  "count": 2,
  "country": "Unknown",
  "org": "Unknown",
  "risk_score": 10,
  "severity": "MEDIUM",
  "distinct_ips": "103.21.244.0, 185.220.101.1"
}
```


## Architecture

```
logs.txt
   │
   ▼
parser.py       -> parses log entries, skips malformed lines
   │
   ▼
detector.py     -> runs all SIGMA rules, deduplicates alerts
   ├─ bf-001    Brute Force       (T1110.001)
   ├─ ps-001    Password Spraying (T1110.003)
   └─ it-001    Impossible Travel (T1078)
   │
   ▼
threat_intel.py -> ipinfo.io enrichment with in-memory cache
                  private IP detection (RFC 1918)
   │
   ▼
risk_scoring.py -> calculates risk score, severity, MITRE label
   │
   ▼
main.py         -> prints alerts + exports to output/alerts.csv
dashboard.py    -> Flask REST API at /alerts
```

## Risk Scoring

| Factor | Points |
|--------|--------|
| Each login event counted for the alert | +3 |
| Suspicious country (RU, CN, KP) | +5 |
| Tor exit node detected in org | +5 |
| Each distinct user targeted (spraying) | +2 |
| Each distinct IP (impossible travel) | +2 |

| Score | Severity |
|-------|----------|
| 0–5 | LOW |
| 6–11 | MEDIUM |
| 12+ | HIGH |

## Features

- Log parsing with per-line error handling and skip-logging
- Three functional SIGMA-based detection rules
- Alert deduplication across detection passes
- IP enrichment via ipinfo.io with in-memory caching
- Private IP detection (RFC 1918) — no wasted API calls
- MITRE ATT&CK sub-technique mapping
- CSV export with full alert context
- Flask REST dashboard at `/alerts`
- Structured logging via Python `logging` module
- 33 unit and integration tests with pytest and shared fixtures

## Technologies

- Python 3.10+
- Flask (REST dashboard)
- requests + ipinfo.io (threat intelligence)
- pytest (unit testing)
- MITRE ATT&CK (T1110.001, T1110.003, T1078)
- SIGMA rule format

## Project Structure

```
soc_threat_analyzer/
├── config/
│   └── settings.py         # single source of truth for all config
├── data/
│   ├── logs.txt            # sample authentication logs
│   └── ips.txt             # sample IP list
├── src/
│   ├── main.py             # pipeline orchestration + CSV export
│   ├── parser.py           # log file parser
│   ├── detector.py         # SIGMA rules + all detection logic
│   ├── threat_intel.py     # ipinfo.io enrichment with caching
│   ├── risk_scoring.py     # scoring + severity + MITRE mapping
│   └── dashboard.py        # Flask REST API
├── tests/
│   ├── conftest.py         # shared pytest fixtures
│   └── test_all.py         # 32 unit + integration tests
├── output/
│   └── alerts.csv          # generated output (gitignored)
├── requirements.txt
└── .gitignore
```

## How to Run

```bash
pip install -r requirements.txt
python -m src.main
```

Flask dashboard:
```bash
python -m src.dashboard
# → http://localhost:5000/alerts
```

Tests:
```bash
python -m pytest tests/ -v
```

## Configuration

Edit `config/settings.py` to tune detection behaviour — no changes needed elsewhere:

```python
THRESHOLD = 3            # brute force: failed login threshold
WINDOW_MINUTES = 5       # brute force: time window
SPRAY_THRESHOLD = 3      # spraying: distinct user threshold
SPRAY_WINDOW_MINUTES = 10
TRAVEL_THRESHOLD = 2     # impossible travel: distinct IP threshold
TRAVEL_WINDOW_MINUTES = 5
SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP"]
SEVERITY_HIGH = 12
SEVERITY_MEDIUM = 6
```

## Limitations

- Uses public ipinfo.io API (no enterprise threat feed)
- Simulated log data (no real production logs)
- In-memory cache resets on restart

## Future Improvements

- SIEM integration (Splunk / ELK)
- Real-time log ingestion
- AbuseIPDB or VirusTotal integration
- Persistent cache (Redis)
- Alert correlation across multiple sources
- Dashboard visualization

## Disclaimer

This project is for educational purposes and simulates SOC workflows using synthetic data.
