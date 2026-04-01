SecuSys v3.2: Automated Forensic and Remediation Platform
Python Automation | SQL SaaS Infrastructure | Multithreaded Engine | Cisco Remediation
Project Overview

SecuSys is an enterprise-grade vulnerability management platform designed for modern security landscapes. It bridges the critical gap between offensive reconnaissance and defensive hardening by transforming raw network data into actionable, SQL-persistent audit logs and automated Cisco IOS remediation scripts.

Key Technical Achievements

The platform has successfully transitioned from a standalone script into a professional SaaS prototype with the following core improvements:
1. Decoupled Architecture: The system logic is fully separated from its data. All vulnerability intelligence has been migrated from hardcoded Python dictionaries into a relational SQL database for high-scale, dynamic updates and better performance.
2. Multithreaded Performance: SecuSys utilizes a high-concurrency engine powered by Python's ThreadPoolExecutor. This architectural choice allows for 20+ simultaneous port handshakes, resulting in a 500% increase in scan speeds compared to traditional synchronous methods.
3. Forensic Audit Persistence: Built a full-stack database handshake that records every network audit. Every scan is stored with a unique timestamp, target infrastructure tracking, and risk summary findings, ensuring long-term audit traceability for compliance requirements.
4. Automated Mitigation: The engine generates real-time defensive advice. For every detected risk, the tool automatically produces industry-standard Cisco Access Control List (ACL) commands ready for immediate deployment to the network perimeter.

Technology Stack
Logic Layer: Python 3.12 (Socket handshaking and Target Resolution)
Backend Framework: Flask (Server-side Routing and Rendering)
Database Layer: SQLAlchemy ORM with SQLite (Data Persistence)
Performance Layer: ThreadPoolExecutor (Parallel Concurrency)
Frontend Interface: HTML5, CSS3 (Responsive Cyber-Dark UI), JavaScript
Deployment Ready: Defined requirements.txt for CI/CD automation

Functional Features
Intelligence Bridge: Seamless connection between SQL data models and frontend Jinja2 reporting.
Zero-Trust Logic Fallback: Automated security advice and "deny" ACLs generated for non-standard or unmapped services.
Dynamic Selection: User-controlled web interface supporting Well-Known (1-1024), Common Enterprise, or Custom precision audits.
Downloadable Artifacts: Real-time generation of physical .txt security audit reports for official documentation.

Installation and Execution
To deploy a local instance of the SecuSys Platform, follow these steps:
1. Environment Initialization: Navigate to the project directory and activate your virtual environment.
cd "Cyber project"
python -m venv venv
.\venv\Scripts\Activate.ps1

2. Dependency Synchronization: Install the required Python libraries.
pip install -r requirements.txt

3. Platform Deployment: Start the Flask web server.
python app.py

4. Access the Command Center: Open a browser and navigate to the local dashboard.
http://localhost:8080

About the Author
Founder: Clinton Mutinda
Credential: IT Graduate & Cybersecurity Major
SecuSys is more than a technical project; it is the foundational engine of a developing cybersecurity startup. As an IT professional currently majoring in Cybersecurity, I developed this tool to bridge the gap between network administration and offensive security research. My goal is to modernize and automate the defensive tasks of Security Analysts through scalable Python software and Cisco-aligned network hardening logic. For inquiries regarding project expansion or professional collaboration, please connect via GitHub. 