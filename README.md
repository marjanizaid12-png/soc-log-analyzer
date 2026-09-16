# SOC Log Analyzer

A beginner-friendly Python-based Security Operations Center (SOC) log analyzer that detects repeated failed login attempts and identifies potential brute-force activity.

## V1 Features

- Reads login events from a text log file.
- Counts failed login attempts by IP address.
- Detects potential brute-force activity using a configurable threshold.
- Displays the suspicious IP address and number of failed attempts.
- Uses sample log data for testing.

## How It Works

The analyzer reads `more_logs.txt` and checks the login events.

If an IP address reaches or exceeds the configured failure threshold, the program generates an alert.

Example:

```text
Potential brute force attack detected from
IP: 192.168.1.99, Failed Attempts: 5
