# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---
## [1.1.0] - 2026-05-13
### Added
 
**Pipeline**
- `run_pipeline(log_path, ...)` - accepts a custom log file path instead of hardcoded `data/logs.txt`
- `run_pipeline_multi(log_paths, ...)` - multi-file ingestion with cross-file correlation; all entries merged before detection so impossible travel and spraying are detected across host boundaries
- `collect_log_files(path)` - flat directory scan returning all `.log` and `.txt` files
- `collect_log_files_recursive(path)` - recursive directory scan
- `_enrich_alerts()` — extracted enrichment logic, shared between single and multi-file pipelines
- `_save_csv(alerts, output_path)` - extracted CSV export with configurable output path
- Runtime threshold overrides for all three detection rules via function arguments
**CLI**
- `--logs` - analyze a single custom log file
- `--logs-dir` - analyze all `.log`/`.txt` files in a directory
- `--recursive` - recurse into subdirectories (used with `--logs-dir`)
- `--output` - custom CSV output path (default: `output/alerts.csv`)
- `--no-export` - skip CSV export
- `--threshold`, `--window` - brute-force overrides
- `--spray-threshold`, `--spray-window` - password spraying overrides
- `--travel-threshold`, `--travel-window` - impossible travel overrides
**Dashboard**
- `POST /upload` - accepts one or more `.log`/`.txt` files via multipart form-data; multiple files are merged before detection (cross-file correlation)
- `GET /alerts/summary` - severity counts and per-rule breakdown
- `DELETE /cache` - reset cached sample-data alerts
- `GET /` - updated endpoint listing with parameter docs
**Tests**
- `test_dashboard.py` - 16 tests covering all dashboard endpoints
- `test_main.py` - 14 tests covering `_build_arg_parser` and `__main__` execution paths via subprocess
- `test_pipeline.py` - fully rewritten, 27 tests covering `run_pipeline`, `run_pipeline_multi`, `collect_log_files`, `collect_log_files_recursive`, `_save_csv`
- `test_threat_intel.py` - extended with 8 `get_ip_info` tests (timeout, cache, HTTP errors, missing fields)
- `test_scoring.py` - extended with 3 additional coverage tests (PRIVATE country, CN/KP suspicious countries)
- Total: 113 tests, 93% coverage
**Threat Intel**
- `IPINFO_TOKEN` env var support - token passed as query parameter to ipinfo.io
- `.env` + `.env.example` added
### Changed
- `run_pipeline()` now accepts `log_path` and threshold override parameters
- `dashboard.py` - full REST API replacing static `/alerts`-only endpoint
- `pyproject.toml` - `fail_under` raised to 90, `main.py`/`dashboard.py` included in coverage
- README updated: badges, install commands, full CLI reference, dashboard endpoints with curl examples, updated project structure
---
## [1.0.0] - 2026-04-23
### Added
- SIGMA-based detection rules: brute force (T1110.001), password spraying (T1110.003), impossible travel (T1078)
- IP enrichment via ipinfo.io with in-memory caching
- Risk scoring and severity labelling (HIGH/MEDIUM/LOW)
- Alert deduplication across detection passes
- CSV export and Flask REST dashboard at /alerts
- 35 pytest tests
