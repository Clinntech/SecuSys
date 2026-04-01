from concurrent.futures import ThreadPoolExecutor #multithreading
from flask import Flask, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import socket
import os
# This line borrows the function 
from main import scan_port, generate_analysis, save_report_to_file

app = Flask(__name__)
# --- NEW: DATABASE CONFIGURATION ---
# We are creating a local SQLite file named 'secusys.db'
# change this later to a Cloud Database (PostgreSQL)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'secusys.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- NEW: SCAN HISTORY MODEL ---
# This is a 'Table' that will store every audit SecuSys ever does
class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    #store ports found as strings, "80,22,443"
    ports_found = db.Column(db.String(500))

    #Store risk level value
    threat_summary = db.Column(db.Text)

    def __repr__(self):
        return f'<Audit {self.target_ip} on {self.scan_date}>'

# --- NEW: VULNERABILITY INTELLIGENCE MODEL ---
class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    port = db.Column(db.Integer, unique=True, nullable=False)
    service = db.Column(db.String(50))
    risk = db.Column(db.String(20))
    description = db.Column(db.Text)
    fix = db.Column(db.Text)
    cisco_acl = db.Column(db.Text)

    def __repr__(self):
       return f'<Knowledge Base Port {self.port}>'

#remember last scanned IP for download button
last_scanned_ip = ""


@app.route('/')
def index():
    #Shows starting page
    #Fetch the total number of audits from the database
    total_audits = AuditRecord.query.count()
    # NEW UPDATED LOGIC: Pull recent history from the database to fill the UI table
    history_logs = AuditRecord.query.order_by(AuditRecord.scan_date.desc()).limit(5).all()
    
    return render_template('index.html', audit_count = total_audits, history = history_logs)

@app.route('/scan' , methods=['POST'])
def scan():
    global last_scanned_ip
    #Get IP from website's search bar
    target = request.form.get('target_ip').strip()
    #choice from dropdown
    scan_type = request.form.get('scan_type')
    results = []

    #Determine range based choice
    if scan_type == "common":
        ports_to_scan = [21,22,23,80, 443, 445, 3306, 3389]
    elif scan_type == "well-known":
        ports_to_scan = range(1, 1025)
    elif scan_type == "custom":
        try:
            # We use 'if start_str else 1' so the site doesn't crash if they leave it blank
            start = int(request.form.get('start_port') or 1)
            end = int(request.form.get('end_port') or 1024)
            ports_to_scan = range(start, end + 1)
        except ValueError:
            ports_to_scan = [80] # Safe fallback if they type letters instead of numbers
    else: 
        ports_to_scan = [80, 8000, 8080]

    try:
        ip = socket.gethostbyname(target)
        last_scanned_ip = ip # Save this globally for the download route

        #Speed
        #1. NEW DYNAMIC DATABASE SCAN LOGIC (Fixing the Database Lookup)
        def thread_scan(port):
            with app.app_context():
                if scan_port(ip, port):
                # Search our new 'Vulnerability' intelligence table in SQL
                    kb_match = Vulnerability.query.filter_by(port=port).first()

                    from main import generate_analysis
                    return generate_analysis(port, db_match=kb_match)
            return None
        
        #2. ThreadPoolExecutor, run scan in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            thread_results = list(executor.map(thread_scan, ports_to_scan))

        #3. Collect findings that aren't none
        results = [r for r in thread_results if r is not None]

        #Save to Hard Drive, Creates the .txt file in the background
    
        
        # 4. STARTUP PERSISTENCE HANDSHAKE (Save results to database history)
        summary_text = f"Audit Success: Identified {len(results)} vulnerabilities." if results else "Hardened: No vulnerabilities detected."
        new_audit = AuditRecord(
            target_ip=target,
            ports_found=str(len(results)),
            threat_summary=summary_text
        )
        db.session.add(new_audit)
        db.session.commit() # Writing the audit to secusys.db history

        if results:
            save_report_to_file(ip, results)

    except Exception as e:
        db.session.rollback()
        print (f"[DATABASE ERROR] Handshake failed: {e}")


    # 5. RE-REFRESH Dashboard Logic: Re-fetch variables before the page reloads
    total_audits = AuditRecord.query.count()
    history_logs = AuditRecord.query.order_by(AuditRecord.scan_date.desc()).limit(5).all()

    # Pass the fresh audit_count and history to ensure UI matches the DB
    return render_template('index.html', results=results, target=target, audit_count=total_audits, history=history_logs)

#The Download Route
@app.route('/download')
def download():
    global last_scanned_ip
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)
    else:
        return "<h3>No report found. Please run a scan first!</h3>"

if __name__ == '__main__':
    app.run(debug=True, port=8080)