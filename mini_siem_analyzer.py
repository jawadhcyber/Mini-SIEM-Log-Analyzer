import csv
from collections import Counter

LOG_FILE = "security_events.log"
REPORT_FILE = "siem_report.csv"

failed_logins = Counter()
alerts = []

try:
    with open(LOG_FILE, "r") as file:
        for line in file:
            parts = line.strip().split(",")

            if len(parts) < 4:
                continue

            timestamp = parts[0].strip()
            event_type = parts[1].strip()
            username = parts[2].strip()
            source_ip = parts[3].strip()

            if event_type == "FAILED_LOGIN":
                failed_logins[source_ip] += 1

            elif event_type == "MALWARE_ALERT":
                alerts.append([
                    timestamp,
                    event_type,
                    username,
                    source_ip,
                    "HIGH",
                    "Malware-related alert detected"
                ])

            elif event_type == "PHISHING_ALERT":
                alerts.append([
                    timestamp,
                    event_type,
                    username,
                    source_ip,
                    "MEDIUM",
                    "Possible phishing activity"
                ])

except FileNotFoundError:
    print(f"Error: {LOG_FILE} was not found.")
    exit()

for ip, count in failed_logins.items():

    if count >= 5:
        severity = "HIGH"
        description = "Possible brute-force attack"

    elif count >= 3:
        severity = "MEDIUM"
        description = "Suspicious failed login activity"

    else:
        severity = "LOW"
        description = "Low-volume failed login activity"

    alerts.append([
        "",
        "FAILED_LOGIN",
        "",
        ip,
        severity,
        description
    ])

print("=== Mini SIEM Log Analyzer ===")
print()

for alert in alerts:
    print(f"Event Type: {alert[1]}")
    print(f"Source IP: {alert[3]}")
    print(f"Severity: {alert[4]}")
    print(f"Finding: {alert[5]}")
    print()

with open(REPORT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    writer.writerow([
        "Timestamp",
        "Event Type",
        "Username",
        "Source IP",
        "Severity",
        "Finding"
    ])

    writer.writerows(alerts)

print(f"SIEM report saved to {REPORT_FILE}")
