Mini SIEM Log Analyzer

A Python-based mini Security Information and Event Management (SIEM) project that analyzes simulated security events, applies basic detection rules, assigns severity levels, and generates a CSV security report.

This project demonstrates how different security events can be collected and analyzed in one place for basic SOC monitoring.

Features

- Reads security events from a log file
- Processes multiple event types
- Detects repeated failed login activity
- Identifies simulated malware alerts
- Identifies simulated phishing alerts
- Assigns LOW, MEDIUM, or HIGH severity
- Displays security findings
- Generates a CSV SIEM report

Events Analyzed

The current version processes:

- "FAILED_LOGIN"
- "MALWARE_ALERT"
- "PHISHING_ALERT"

Detection Rules

Failed Logins

- 5 or more failed logins from an IP → HIGH
- 3–4 failed logins → MEDIUM
- 1–2 failed logins → LOW

Malware Alert

"MALWARE_ALERT" → HIGH

Phishing Alert

"PHISHING_ALERT" → MEDIUM

Example Findings

Event Type| Source IP| Severity| Finding
MALWARE_ALERT| 10.0.0.25| HIGH| Malware-related alert detected
PHISHING_ALERT| 172.16.0.10| MEDIUM| Possible phishing activity
FAILED_LOGIN| 192.168.1.50| HIGH| Possible brute-force attack
FAILED_LOGIN| 192.168.1.75| MEDIUM| Suspicious failed login activity

Project Files

- "mini_siem_analyzer.py" — Main SIEM analysis script
- "security_events.log" — Sample security event data
- "siem_report.csv" — Generated security report
- "README.md" — Project documentation

How It Works

1. Reads events from "security_events.log".
2. Parses the timestamp, event type, username, and source IP.
3. Counts failed login attempts by IP address.
4. Processes malware and phishing alerts.
5. Applies predefined detection rules.
6. Assigns severity levels.
7. Displays security findings.
8. Exports the findings to "siem_report.csv".

Technologies

- Python
- CSV
- "collections.Counter"
- Log parsing
- Google Colab
- GitHub

SOC Skills Demonstrated

- SIEM fundamentals
- Security event monitoring
- Log parsing and analysis
- Detection-rule implementation
- Brute-force activity detection
- Alert classification
- Severity assignment
- Security reporting
- Python security automation

Limitations

This is a simplified educational SIEM simulation using predefined rules and sample data. It is not a replacement for a production SIEM platform.

Real SOC environments may correlate data from endpoints, firewalls, authentication systems, network devices, threat-intelligence sources, and other security tools before determining whether activity represents a genuine security incident.

Future Improvements

- Add timestamp-based event correlation
- Add IOC matching
- Include usernames in failed-login findings
- Add configurable detection rules
- Add alert status and analyst notes
- Generate summary statistics
- Add visual dashboards
- Support additional security event types

Ethical Use

This project is intended for cybersecurity education, defensive security monitoring, and authorized security analysis.

Author

Jawad Hussain

Computer Science Graduate | Aspiring Cybersecurity Analyst
