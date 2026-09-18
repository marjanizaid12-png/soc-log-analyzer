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
# Store failed events
# -----------------------------

failed_events = {}

# -----------------------------
# Prevent duplicate alerts
# -----------------------------

alerted_ips = set()

# -----------------------------
# Store multiple alerts
# -----------------------------

alerts = []


# ============================================================
# V2.4 - Severity
# ============================================================

def get_severity(failure_count):

    if failure_count >= 7:
        return "CRITICAL"

    elif failure_count >= 5:
        return "HIGH"

    elif failure_count >= 3:
        return "MEDIUM"

    return None


# ============================================================
# V2.5 - Detection Rule 1
# Brute-force detection
# ============================================================

def detect_brute_force(failure_count):

    if failure_count >= THRESHOLD:
        return True

    return False


# ============================================================
# V2.5 - Detection Rule 2
# Multiple usernames targeted
# ============================================================

def detect_multiple_users(events):

    usernames = set()

    for event in events:
        usernames.add(event["username"])

    if len(usernames) >= 3:
        return True

    return False


# ============================================================
# V2.5 - Detection Rule 3
# Repeated attack
# ============================================================

def detect_repeated_attack(failure_count):

    if failure_count >= 5:
        return True

    return False


# ============================================================
# Read security log
# ============================================================

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

                # Add event
                failed_events[ip].append(
                    {
                        "time": event_time,
                        "username": username
                    }
                )

                # -----------------------------
                # Remove events outside window
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
                # Count failures
                # -----------------------------

                failure_count = len(
                    failed_events[ip]
                )

                # -----------------------------
                # V2.5 Detection Rules
                # -----------------------------

                detection_rules = []

                # Rule 1
                if detect_brute_force(failure_count):

                    detection_rules.append(
                        "Brute-force login detection"
                    )

                # Rule 2
                if detect_multiple_users(
                    failed_events[ip]
                ):

                    detection_rules.append(
                        "Multiple usernames targeted"
                    )

                # Rule 3
                if detect_repeated_attack(
                    failure_count
                ):

                    detection_rules.append(
                        "Repeated failed-login attack"
                    )

                # -----------------------------
                # Determine severity
                # -----------------------------

                severity = get_severity(
                    failure_count
                )

                # -----------------------------
                # Generate alert
                # -----------------------------

                if (
                    detection_rules
                    and ip not in alerted_ips
                ):

                    alert = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "username": username,
                        "failed_attempts": failure_count,
                        "time_window_seconds": TIME_WINDOW,
                        "severity": severity,
                        "detection_rules": detection_rules
                    }

                    # -----------------------------
                    # Display alert
                    # -----------------------------

                    print("SOC ALERT")
                    print("=" * 40)

                    print(
                        "IP:",
                        ip
                    )

                    print(
                        "Username:",
                        username
                    )

                    print(
                        "Failed Attempts:",
                        failure_count
                    )

                    print(
                        "Time Window:",
                        TIME_WINDOW,
                        "seconds"
                    )

                    print(
                        "Severity:",
                        severity
                    )

                    print("Detection Rules:")

                    for rule in detection_rules:
                        print(
                            f"- {rule}"
                        )

                    print("=" * 40)

                    # -----------------------------
                    # Store alert
                    # -----------------------------

                    alerts.append(alert)

                    # -----------------------------
                    # Prevent duplicate alerts
                    # -----------------------------

                    alerted_ips.add(ip)


# ============================================================
# Save all alerts
# ============================================================

with open(ALERT_FILE, "w") as file:

    json.dump(
        alerts,
        file,
        indent=4
    )


# ============================================================
# Final result
# ============================================================

print()
print("Analysis completed.")
print(f"Total alerts generated: {len(alerts)}")
print(f"Alerts saved to: {ALERT_FILE}")