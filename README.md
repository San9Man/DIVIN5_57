#DIVIN5 TICE

[![Email](https://img.shields.io/badge/email-connect-red.svg)](https://groups.google.com/g/divin5-tcie)


DIVIN5 TICE is a powerful, automated tool designed to solve a critical problem for security analysts: **data fragmentation**. When investigating a suspicious IP address, analysts must manually check multiple, siloed threat intelligence feeds (like AbuseIPDB, VirusTotal, etc.), wasting valuable time and making it difficult to see the full picture.

TICE is a **Correlation Engine** that automates this entire process. It queries multiple data sources simultaneously, then intelligently normalizes, de-duplicates, and analyzes the results to provide a single, high-confidence, actionable report.

This engine is designed to power dashboards, security playbooks (SOAR), and the **Dual-Persona Cybersecurity AI Agent** for providing both public-facing advice and deep-level intelligence for officials.

---

## 🚀 Key Features

* **Multi-Source Aggregation:** Automatically queries a wide range of threat intelligence feeds from a single input IP.
* **Intelligent Correlation:** Doesn't just list data. TICE calculates a composite **"Correlation Value"** (a unified risk score) based on multi-source consensus, threat type, and recency.
* **Structured Database Output:** All findings are normalized and saved in a structured format, perfect for feeding into a database (e.g., SQLite, PostgreSQL, JSON) for historical analysis and dashboarding.
* **Extensible:** Built in a modular way to easily add new threat intelligence sources.

---

## 🔌 Supported Data Sources

TICE correlates data from top-tier public intelligence feeds, including:

* ✅ **AbuseIPDB:** Gathers reports from a global community of webmasters and security analysts.
* ✅ **VirusTotal:** Checks the IP against over 90+ antivirus scanners and blocklisting services.
* ✅ **AlienVault OTX:** Correlates the IP with known threat campaigns and "Pulses."
* *(And more...)*
