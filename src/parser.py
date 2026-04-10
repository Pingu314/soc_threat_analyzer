from datetime import datetime

def parse_log(file_path):
    logs = []
    with open(file_path, "r") as f:
        for line in f:
            try:
                parts = line.strip().split()
                timestamp = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
                status = parts[3]
                user = parts[4].split("=")[1]
                ip = parts[5].split("=")[1]

                logs.append({"timestamp": timestamp,
                            "status": status,
                            "user": user,
                            "ip": ip})
            except Exception:
                continue
    return logs
