import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def parse_log(file_path: str) -> list[dict]:
    """Parse an authentication log file into a list of structured log entries.

    Each line must follow the format:
        <timestamp> <field> <field> <STATUS> user=<username> ip=<ip_address>

    Malformed or unparseable lines are silently skipped and counted.
    A warning is emitted at the end if any lines were skipped.

    Args:
        file_path: Path to the log file to parse.

    Returns:
        A list of dicts, each with keys:
            - 'timestamp' (datetime): parsed event time
            - 'status'    (str):      login result, e.g. 'FAILED' or 'SUCCESS'
            - 'user'      (str):      username from the log line
            - 'ip'        (str):      source IP address
    """
    logs = []
    skipped = 0

    with open(file_path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split()
                timestamp = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
                status = parts[3]
                user = parts[4].split("=")[1]
                ip = parts[5].split("=")[1]

                logs.append({"timestamp": timestamp,
                             "status": status,
                             "user": user,
                             "ip": ip})

            except (ValueError, IndexError, AttributeError) as e:
                skipped += 1
                logger.debug(f"Skipped line {line_num}: {e!r} | Content: {line!r}")

    if skipped:
        logger.warning(f"Skipped {skipped} unparseable line(s) in {file_path}")
    return logs