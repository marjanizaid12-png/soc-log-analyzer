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
    r"(LOGIN\s(?:SUCCESS|FAILED)):\suser="
    r"([\w.-]+)\sfrom\s"
    r"(\d+\.\d+\.\d+\.\d+)$"
)

# -----------------------------
# Failed-login counter
# -----------------------------

failed_counts = {}

# -----------------------------
# V2.1: Track alerted IPs
# Prevent duplicate alerts
# -----------------------------

alerted_ips = set()

# -----------------------------
# V2.2: Store multiple alerts
# -----------------------------

alerts = []

# -----------------------------
# Read security log
# -----------------------------

with open(LOG_FILE, "r") as file:

    for line in file:

        line = line.strip()

        # -----------------------------
        # Apply Regex
        # -----------------------------

        match = re.search(pattern, line)

        if match:

            timestamp, status, username, ip = match.groups()

            # -----------------------------
            # Only count failed logins
            # -----------------------------

            if status == "LOGIN FAILED":

                failed_counts[ip] = failed_counts.get(ip, 0) + 1

                # -----------------------------
                # Brute-force detection
                # V2.1: Prevent duplicate alerts
                # -----------------------------

                if (
                    failed_counts[ip] >= THRESHOLD
                    and ip not in alerted_ips
                ):

                    # -----------------------------
                    # Create alert
                    # -----------------------------

                    alert = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "username": username,
                        "failed_attempts": failed_counts[ip],
                        "severity": "HIGH",
                        "detection": "Possible brute-force attack"
                    }

                    # -----------------------------
                    # Display alert
                    # -----------------------------

                    print("Possible brute-force attack")
                    print(f"IP: {ip}")
                    print(f"Username: {username}")
                    print(f"Failed Attempts: {failed_counts[ip]}")
                    print("-" * 40)

                    # -----------------------------
                    # V2.2:
                    # Add alert to alert list
                    # -----------------------------

                    alerts.append(alert)

                    # -----------------------------
                    # Remember alerted IP
                    # -----------------------------

                    alerted_ips.add(ip)

# -----------------------------
# V2.2:
# Save ALL alerts to JSON
# -----------------------------

with open(ALERT_FILE, "w") as file:

    json.dump(
        alerts,
        file,
        indent=4
    )

print(f"Total alerts generated: {len(alerts)}")
print(f"Alerts saved to: {ALERT_FILE}")