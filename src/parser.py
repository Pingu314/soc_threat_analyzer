import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def parse_log(file_path: str) -> list[dict]:
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

            except Exception as e:
                skipped += 1
                logger.debug(f"Skipped line {line_num}: {e} | Content: '{line}'")

    if skipped:
        logger.warning(f"Skipped {skipped} unparseable line(s) in {file_path}")
    return logs