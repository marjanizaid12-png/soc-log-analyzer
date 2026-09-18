import re
import json
from datetime import datetime, timedelta

# -----------------------------
# Configuration
# -----------------------------

THRESHOLD = 3
TIME_WINDOW = 60  # seconds

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
# V2.3:
# Store failed login events
# -----------------------------

failed_events = {}

# -----------------------------
# V2.1:
# Prevent duplicate alerts
# -----------------------------

alerted_ips = set()

# -----------------------------
# V2.2:
# Store multiple alerts
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
            # Convert timestamp
            # -----------------------------

            event_time = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            # -----------------------------
            # Only process failed logins
            # -----------------------------

            if status == "LOGIN FAILED":

                # Create list for new IP
                if ip not in failed_events:
                    failed_events[ip] = []

                # Add current failed event
                failed_events[ip].append(
                    {
                        "time": event_time,
                        "username": username
                    }
                )

                # -----------------------------
                # Remove events outside
                # the time window
                # -----------------------------

                window_start = event_time - timedelta(
                    seconds=TIME_WINDOW
                )

                failed_events[ip] = [
                    event
                    for event in failed_events[ip]
                    if event["time"] >= window_start
                ]

                # -----------------------------
                # Count failures inside
                # the current time window
                # -----------------------------

                failure_count = len(failed_events[ip])

                # -----------------------------
                # Brute-force detection
                # -----------------------------

                if (
                    failure_count >= THRESHOLD
                    and ip not in alerted_ips
                ):

                    alert = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "username": username,
                        "failed_attempts": failure_count,
                        "time_window_seconds": TIME_WINDOW,
                        "severity": "HIGH",
                        "detection": "Possible brute-force attack"
                    }

                    # -----------------------------
                    # Display alert
                    # -----------------------------

                    print("Possible brute-force attack")
                    print(f"IP: {ip}")
                    print(f"Username: {username}")
                    print(f"Failed Attempts: {failure_count}")
                    print(f"Time Window: {TIME_WINDOW} seconds")
                    print("-" * 40)

                    # -----------------------------
                    # V2.2:
                    # Store alert
                    # -----------------------------

                    alerts.append(alert)

                    # -----------------------------
                    # V2.1:
                    # Remember alerted IP
                    # -----------------------------

                    alerted_ips.add(ip)

# -----------------------------
# Save ALL alerts
# -----------------------------

with open(ALERT_FILE, "w") as file:

    json.dump(
        alerts,
        file,
        indent=4
    )

# -----------------------------
# Final result
# -----------------------------

print(f"Total alerts generated: {len(alerts)}")
print(f"Alerts saved to: {ALERT_FILE}")