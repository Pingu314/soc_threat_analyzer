import logging
import os
import tempfile

from flask import Flask, jsonify, request

from src.main import run_pipeline, run_pipeline_multi

app = Flask(__name__)
logger = logging.getLogger(__name__)

_cached_alerts: list | None = None
_ALLOWED_EXTENSIONS = {".log", ".txt"}


def _allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and "." + filename.rsplit(".", 1)[1].lower() in _ALLOWED_EXTENSIONS
    )


def _get_alerts() -> list[dict]:
    global _cached_alerts
    if _cached_alerts is None:
        _cached_alerts = run_pipeline()
    return _cached_alerts


def _int_param(name: str) -> int | None:
    val = request.args.get(name)
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def _override_kwargs() -> dict:
    return {
        "threshold":             _int_param("threshold"),
        "window_minutes":        _int_param("window"),
        "spray_threshold":       _int_param("spray_threshold"),
        "spray_window_minutes":  _int_param("spray_window"),
        "travel_threshold":      _int_param("travel_threshold"),
        "travel_window_minutes": _int_param("travel_window"),
    }


@app.route("/")
def home() -> dict:
    """Return a JSON welcome message with all available endpoints."""
    return {
        "message": "SOC Dashboard running",
        "endpoints": {
            "GET  /alerts":         "Alerts from sample data (data/logs.txt)",
            "GET  /alerts/summary": "Severity counts and rule breakdown",
            "POST /upload":         "Analyze one or more log files (.log or .txt)",
            "DELETE /cache":        "Clear cached sample-data alerts",
        },
        "upload_params": {
            "threshold":        "Brute-force login threshold",
            "window":           "Brute-force time window (minutes)",
            "spray_threshold":  "Password spraying distinct user threshold",
            "spray_window":     "Password spraying time window (minutes)",
            "travel_threshold": "Impossible travel distinct IP threshold",
            "travel_window":    "Impossible travel time window (minutes)",
        },
    }


@app.route("/alerts")
def alerts() -> dict:
    """Return all cached alerts from sample data with a total count."""
    data = _get_alerts()
    return {"alerts": data, "total_alerts": len(data)}


@app.route("/alerts/summary")
def alerts_summary() -> dict:
    """Return severity counts and per-rule breakdown for sample data."""
    data = _get_alerts()
    severity_counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    rule_counts: dict[str, int] = {}
    for alert in data:
        sev = alert.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rule_id = alert.get("rule_id", "unknown")
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
    return {
        "total_alerts": len(data),
        "by_severity": severity_counts,
        "by_rule": rule_counts,
    }


@app.route("/upload", methods=["POST"])
def upload() -> tuple:
    """Analyze one or more uploaded log files.

    Accepts multipart/form-data with one or more 'file' fields.
    Multiple files are merged before detection - cross-file correlation applies.

    Optional query parameters (override settings.py defaults):
        threshold, window, spray_threshold, spray_window,
        travel_threshold, travel_window

    Returns:
        JSON with alerts list, total_alerts count, and files_processed.
    """
    files = request.files.getlist("file")

    if not files or all(not f.filename for f in files):
        return jsonify({
            "error": "No files provided. Send one or more .log or .txt files as 'file' fields."
        }), 400

    invalid = [f.filename for f in files if f.filename and not _allowed_file(f.filename)]
    if invalid:
        return jsonify({
            "error": f"Invalid file type(s): {invalid}. Allowed: .log, .txt"
        }), 400

    tmp_paths = []
    try:
        for f in files:
            if not f.filename:
                continue
            tmp = tempfile.NamedTemporaryFile(mode="wb", suffix=".log", delete=False)
            f.save(tmp)
            tmp.close()
            tmp_paths.append((tmp.name, f.filename))

        import pathlib
        path_objects = [pathlib.Path(p) for p, _ in tmp_paths]
        filenames = [name for _, name in tmp_paths]

        kwargs = _override_kwargs()

        if len(path_objects) == 1:
            result_alerts = run_pipeline(log_path=path_objects[0], **kwargs)
        else:
            result_alerts = run_pipeline_multi(path_objects, **kwargs)

        return jsonify({
            "files_processed": filenames,
            "total_alerts": len(result_alerts),
            "alerts": result_alerts,
        }), 200

    except Exception as e:
        logger.exception(f"Pipeline failed for uploaded file(s): {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        for tmp_path, _ in tmp_paths:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


@app.route("/cache", methods=["DELETE"])
def clear_cache() -> tuple:
    """Clear the cached sample data alerts."""
    global _cached_alerts
    _cached_alerts = None
    return jsonify({"message": "Cache cleared. Next /alerts call re-runs the pipeline."}), 200


if __name__ == "__main__":
    app.run(debug=False)
