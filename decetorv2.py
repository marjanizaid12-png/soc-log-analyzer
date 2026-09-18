import re
import json

# -----------------------------
# Configuration
# -----------------------------

THRESHOLD = 3

LOG_FILE = "security.log"
ALERT_FILE = "alerts.json"

# -----------------------------
# Regex pattern
# -----------------------------

pattern = (
    r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s"
    r"(LOGIN\s(?:SUCCESS|FAILED)):\s"
    r"user=([\w.-]+)\sfrom\s"
    r"(\d+\.\d+\.\d+\.\d+)$"
)

# -----------------------------
# Failed-login counter
# -----------------------------

failed_counts = {}

# -----------------------------
# Read security log
# -----------------------------

with open(LOG_FILE, "r") as file:

    for line in file:
        line = line.strip()

        match = re.search(pattern, line)
        print("Line:", line)
        print("Match:", match)
        if match:
            timestamp, status, username, ip = match.groups()

            # Only count failed logins
            if status == "LOGIN FAILED":

                failed_counts[ip] = failed_counts.get(ip, 0) + 1

                # Brute-force detection
                if failed_counts[ip] >= THRESHOLD:

                    alert = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "username": username,
                        "failed_attempts": failed_counts[ip],
                        "severity": "HIGH",
                        "detection": "Possible brute-force attack"
                    }

                    print("Possible brute-force attack")
                    print(f"IP: {ip}")
                    print(f"Username: {username}")
                    print(f"Failed Attempts: {failed_counts[ip]}")
                    print("-" * 40)

                    # Save alert to JSON
                    with open(ALERT_FILE, "w") as file:
                        json.dump(alert, file, indent=4)