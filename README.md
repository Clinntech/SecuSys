# SecuSys v3.0: Full-Stack Network Vulnerability Auditor
**Python Automation | Cisco Network Hardening | Flask Web Engine**

## Overview
SecuSys is an automated security audit tool designed to bridge the gap between network reconnaissance and defensive remediation. Developed with a "Purple Team" mindset, the tool not only identifies open network ports but also cross-references them with a custom vulnerability database to generate real-time security analysis and actionable Cisco IOS configurations.

## All-Rounder Skill Integration
This project demonstrates a multi-disciplinary approach to IT and Security:
- **Cybersecurity:** Logic built for vulnerability detection and risk prioritization.
- **Networking:** Automated generation of Cisco Access Control Lists (ACLs) to mitigate identified threats.
- **Python:** Multi-layered logic handling TCP/IP sockets and automated reporting.
- **Web Development:** Responsive dashboard built using the Flask framework for a professional UI.

## Key Features
- **Dynamic Audit Ranges:** Supports Well-Known ports (1-1024), Common Web services, or Custom user-defined ranges.
- **Automated "Cisco Fixes":** Generates the specific CLI commands needed to secure a router or switch interface based on scan findings.
- **Intelligent Fallback:** Uses "Zero Trust" logic to provide security recommendations for non-standard or unknown services.
- **Exportable Artifacts:** Automatically generates a time-stamped security audit (.txt) that can be downloaded via the browser for reporting.

## Technology Stack
- **Backend:** Python 3.x, Flask
- **Frontend:** HTML5, CSS, JavaScript
- **Networking:** Socket library for TCP Handshakes
- **Documentation:** Markdown

## Getting Started
1. **Clone the repo:** `git clone https://github.com/Clinntech/SecuSys.git`
2. **Setup Env:** `python -m venv venv` and `.\venv\Scripts\activate`
3. **Install Dependencies:** `pip install flask`
4. **Run Server:** `python app.py`
5. **Access UI:** Open browser to `http://127.0.0.1:8080`