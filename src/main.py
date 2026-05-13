import argparse
import csv
import logging
import os
import pathlib

from src.detector import run_all_detections
from src.parser import parse_log
from src.risk_scoring import calculate_risk, get_severity
from src.threat_intel import get_ip_info

DEFAULT_LOG_PATH = pathlib.Path(__file__).parent.parent / "data" / "logs.txt"
DEFAULT_OUTPUT_PATH = "output/alerts.csv"
LOG_EXTENSIONS = {".log", ".txt"}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def collect_log_files(path: str | pathlib.Path) -> list[pathlib.Path]:
    """Collect log files from a file path or directory (non-recursive).

    Args:
        path: File path (.log/.txt) or directory path.

    Returns:
        Sorted list of Path objects for all valid log files found.
    """
    p = pathlib.Path(path)
    if p.is_file():
        if p.suffix.lower() in LOG_EXTENSIONS:
            return [p]
        logger.warning(f"Skipping unsupported file type: {p}")
        return []
    if p.is_dir():
        files = sorted(
            f for f in p.iterdir()
            if f.is_file() and f.suffix.lower() in LOG_EXTENSIONS
        )
        logger.info(f"Found {len(files)} log file(s) in {p}")
        return files
    logger.error(f"Path does not exist: {p}")
    return []


def collect_log_files_recursive(path: str | pathlib.Path) -> list[pathlib.Path]:
    """Recursively collect all log files from a directory tree.

    Args:
        path: Root directory to scan.

    Returns:
        Sorted list of Path objects for all valid log files found.
    """
    p = pathlib.Path(path)
    if p.is_file():
        return collect_log_files(p)
    files = sorted(
        f for f in p.rglob("*")
        if f.is_file() and f.suffix.lower() in LOG_EXTENSIONS
    )
    logger.info(f"Found {len(files)} log file(s) recursively in {p}")
    return files


def _enrich_alerts(alerts: list[dict]) -> list[dict]:
    """Enrich raw detection alerts with IP intel and risk scoring."""
    final_alerts = []
    for alert in alerts:
        ip = alert.get("ip")
        intel = get_ip_info(ip) if ip else None
        risk = calculate_risk(alert, intel)
        result = {
            "rule_id":        alert["rule_id"],
            "rule":           alert["rule"],
            "mitre":          alert["mitre"],
            "sigma_severity": alert["sigma_severity"],
            "ip":             ip or "multiple",
            "user":           alert.get("user") or "multiple",
            "count":          alert["count"],
            "country":        intel["country"] if intel else "Unknown",
            "org":            intel["org"] if intel else "Unknown",
            "risk_score":     risk,
            "severity":       get_severity(risk),
        }
        if "distinct_users" in alert:
            result["distinct_users"] = ", ".join(alert["distinct_users"])
        if "distinct_ips" in alert:
            result["distinct_ips"] = ", ".join(alert["distinct_ips"])
        final_alerts.append(result)
    return final_alerts


def _detection_kwargs(args_or_dict: dict) -> dict:
    """Build detection kwargs from overrides, falling back to settings.py."""
    from config.settings import (THRESHOLD, WINDOW_MINUTES, SPRAY_THRESHOLD,
                                  SPRAY_WINDOW_MINUTES, TRAVEL_THRESHOLD,
                                  TRAVEL_WINDOW_MINUTES)
    g = args_or_dict.get
    return {
        "threshold":             g("threshold") or THRESHOLD,
        "window_minutes":        g("window_minutes") or WINDOW_MINUTES,
        "spray_threshold":       g("spray_threshold") or SPRAY_THRESHOLD,
        "spray_window_minutes":  g("spray_window_minutes") or SPRAY_WINDOW_MINUTES,
        "travel_threshold":      g("travel_threshold") or TRAVEL_THRESHOLD,
        "travel_window_minutes": g("travel_window_minutes") or TRAVEL_WINDOW_MINUTES,
    }


def run_pipeline(
    log_path: str | pathlib.Path = DEFAULT_LOG_PATH,
    threshold: int | None = None,
    window_minutes: int | None = None,
    spray_threshold: int | None = None,
    spray_window_minutes: int | None = None,
    travel_threshold: int | None = None,
    travel_window_minutes: int | None = None,
) -> list[dict]:
    """Run the full SOC detection pipeline on a single log file.

    Args:
        log_path: Path to the authentication log file.
        threshold: Override brute-force failed login threshold.
        window_minutes: Override brute-force time window.
        spray_threshold: Override password spraying distinct user threshold.
        spray_window_minutes: Override password spraying time window.
        travel_threshold: Override impossible travel distinct IP threshold.
        travel_window_minutes: Override impossible travel time window.

    Returns:
        A list of fully enriched and scored alert dicts.
    """
    kwargs = _detection_kwargs({
        "threshold": threshold, "window_minutes": window_minutes,
        "spray_threshold": spray_threshold, "spray_window_minutes": spray_window_minutes,
        "travel_threshold": travel_threshold, "travel_window_minutes": travel_window_minutes,
    })
    logger.info(f"Log file: {log_path}")
    logs = parse_log(str(log_path))
    logger.info(f"Parsed {len(logs)} log entries.")
    alerts = run_all_detections(logs, **kwargs)
    logger.info(f"Detected {len(alerts)} alert(s).")
    return _enrich_alerts(alerts)


def run_pipeline_multi(
    log_paths: list[pathlib.Path],
    threshold: int | None = None,
    window_minutes: int | None = None,
    spray_threshold: int | None = None,
    spray_window_minutes: int | None = None,
    travel_threshold: int | None = None,
    travel_window_minutes: int | None = None,
) -> list[dict]:
    """Run the pipeline across multiple log files with cross-file correlation.

    All log entries are merged before detection - impossible travel and
    password spraying are detected across file boundaries.

    Args:
        log_paths: List of log file paths to process.
        threshold: Override brute-force failed login threshold.
        window_minutes: Override brute-force time window.
        spray_threshold: Override password spraying distinct user threshold.
        spray_window_minutes: Override password spraying time window.
        travel_threshold: Override impossible travel distinct IP threshold.
        travel_window_minutes: Override impossible travel time window.

    Returns:
        A list of fully enriched and scored alert dicts.
    """
    kwargs = _detection_kwargs({
        "threshold": threshold, "window_minutes": window_minutes,
        "spray_threshold": spray_threshold, "spray_window_minutes": spray_window_minutes,
        "travel_threshold": travel_threshold, "travel_window_minutes": travel_window_minutes,
    })

    all_logs = []
    for path in log_paths:
        try:
            entries = parse_log(str(path))
            logger.info(f"  {path.name}: {len(entries)} entries")
            all_logs.extend(entries)
        except Exception as e:
            logger.warning(f"  Skipping {path.name}: {e}")

    logger.info(f"Total: {len(all_logs)} entries across {len(log_paths)} file(s)")

    if not all_logs:
        logger.warning("No log entries parsed. No alerts generated.")
        return []

    alerts = run_all_detections(all_logs, **kwargs)
    logger.info(f"Detected {len(alerts)} alert(s) after cross-file correlation.")
    return _enrich_alerts(alerts)


def _save_csv(alerts: list[dict], output_path: str) -> None:
    """Write enriched alerts to a CSV file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fieldnames = ["rule_id", "rule", "mitre", "sigma_severity", "ip", "user", "count",
                  "country", "org", "risk_score", "severity", "distinct_users", "distinct_ips"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)
    logger.info(f"Saved {len(alerts)} alert(s) to {output_path}")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "SOC Threat Analyzer — detect brute force, password spraying and "
            "impossible travel in authentication logs."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    input_group = p.add_mutually_exclusive_group()
    input_group.add_argument(
        "--logs", default=None,
        help="Path to a single log file (.log or .txt)",
    )
    input_group.add_argument(
        "--logs-dir", default=None,
        help="Path to a directory — all .log/.txt files will be processed",
    )
    p.add_argument("--recursive", action="store_true",
                   help="Recursively scan subdirectories (with --logs-dir)")
    p.add_argument("--output", default=DEFAULT_OUTPUT_PATH,
                   help="Path for CSV output")
    p.add_argument("--no-export", action="store_true",
                   help="Skip CSV export")
    p.add_argument("--threshold", type=int, default=None,
                   help="Brute-force failed login threshold")
    p.add_argument("--window", type=int, default=None,
                   help="Brute-force time window in minutes")
    p.add_argument("--spray-threshold", type=int, default=None,
                   help="Password spraying distinct user threshold")
    p.add_argument("--spray-window", type=int, default=None,
                   help="Password spraying time window in minutes")
    p.add_argument("--travel-threshold", type=int, default=None,
                   help="Impossible travel distinct IP threshold")
    p.add_argument("--travel-window", type=int, default=None,
                   help="Impossible travel time window in minutes")
    return p


def main() -> None:
    """CLI entrypoint for soc-analyze"""
    args = _build_arg_parser().parse_args()

    override_kwargs = {
        "threshold":             args.threshold,
        "window_minutes":        args.window,
        "spray_threshold":       args.spray_threshold,
        "spray_window_minutes":  args.spray_window,
        "travel_threshold":      args.travel_threshold,
        "travel_window_minutes": args.travel_window,
    }

    if args.logs_dir:
        root = pathlib.Path(args.logs_dir)
        log_files = (collect_log_files_recursive(root) if args.recursive
                     else collect_log_files(root))
        if not log_files:
            print(f"No .log or .txt files found in {root}")
            raise SystemExit(1)
        alerts = run_pipeline_multi(log_files, **override_kwargs)
    else:
        log_path = pathlib.Path(args.logs) if args.logs else DEFAULT_LOG_PATH
        alerts = run_pipeline(log_path=log_path, **override_kwargs)

    for alert in alerts:
        print(alert)

    if not args.no_export and alerts:
        _save_csv(alerts, args.output)


if __name__ == "__main__":
    main()
