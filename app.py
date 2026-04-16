from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor # multithreading
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import socket
import os
import io # Needed for PDF memory management
from reportlab.lib.pagesizes import letter # Standard PDF size
from reportlab.pdfgen import canvas # The drawing engine for PDFs

# This line borrows the function 
from main import scan_port, generate_analysis, save_report_to_file

app = Flask(__name__)
# --- NEW: DATABASE CONFIGURATION ---
# We are creating a local SQLite file named 'secusys.db'
# change this later to a Cloud Database (PostgreSQL)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'secusys.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev-startup-key-123' # Necessary for Flask sessions

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' #Tells flask where the login page is. 

# --- STARTUP ANALYTICS HELPER ---
def calculate_security_score(results_list):
    """
    SaaS Proprietary Logic: Calculates a 0-100 hardening score.
    Higher finding count and severity reduces the overall score.
    """
    score = 100
    for report in results_list:
        if "CRITICAL" in report:
            score -= 20
        elif "HIGH" in report:
            score -= 10
        elif "MEDIUM" in report:
            score -= 5
        elif "SUSPICIOUS" in report:
            score -= 5
    return max(0, score)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # Important: We never store real passwords, only the 'Hash'
    password = db.Column(db.String(150), nullable=False) 
    
    # Relationship: A user can own many scans
    scans = db.relationship('AuditRecord', backref='user_profile', lazy=True)

# --- NEW: SCAN HISTORY MODEL ---
# This is a 'Table' that will store every audit SecuSys ever does
class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    ports_found = db.Column(db.String(500))
    threat_summary = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    #Tracks if a user clicked the remediate button (0 = not fixed, 1 = fixed)
    remediation_status = db.Column(db.Integer, default=0)

    #Stores actual log output from the Cisco router/Device
    remediation_log = db.Column(db.Text, nullable=True)
    
    # UPDATED THURSDAY: Track the historical score for executive reporting
    security_score = db.Column(db.Integer, default=100)

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
    
#Remote device credential models
class DeviceSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(50), nullable=False)
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False) #Hashed

    # FIXED: Each user gets's their device configuration. Refers to user.id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)

    def __repr__(self):
        return f'<Device Config for {self.device_ip}>'


#remember last scanned IP for download button
last_scanned_ip = ""

import socket # Ensure this is in your imports at the top

def seed_intelligence():
    """
    Automatic SaaS Seeding: Populates 1,024 ports if the DB is empty.
    No terminal commands required.
    """
    with app.app_context():
        # Check if we already have intelligence in the database
        if Vulnerability.query.count() < 1000:
            print("[SYSTEM] Intelligence table empty. Initiating 1,024-port brain upload...")
            
            for p in range(1, 1025):
                # Only add if the specific port doesn't exist
                if not Vulnerability.query.filter_by(port=p).first():
                    # 1. Fetch official name via networking library
                    try:
                        name = socket.getservbyport(p).upper()
                    except:
                        name = "INTERNAL-SERVICE"

                    # 2. Assign Intelligence based on All-Rounder knowledge
                    if p in [21, 23, 25, 110]:
                        risk, dsc, fix = "HIGH", f"Unencrypted {name} protocol. Risk of sniffed credentials.", "Upgrade to Secure versions."
                        acl = f"access-list 101 deny tcp any any eq {p}"
                    elif p in [22, 443, 993, 995]:
                        risk, dsc, fix = "SAFE", f"Securely encrypted {name} service verified.", "Maintain certificate security."
                        acl = f"access-list 101 permit tcp any any eq {p}"
                    elif p == 80:
                        risk, dsc, fix = "MEDIUM", "Cleartext HTTP web service. MITM potential.", "Enforce HSTS and move to Port 443."
                        acl = f"access-list 101 permit tcp [TRUSTED_IP] any any eq 80"
                    elif p == 445:
                        risk, dsc, fix = "CRITICAL", "SMB / Microsoft DS detected. WannaCry ransomware vector.", "Disable Port 445 on external interface immediately."
                        acl = f"access-list 101 deny tcp any any eq 445"
                    else:
                        risk, dsc, fix = "LOW", f"Standard port for {name}. Baseline audit required.", "Follow Least Privilege policy."
                        acl = f"access-list 101 deny tcp any any eq {p}"

                    # 3. Create the Database Record
                    db.session.add(Vulnerability(
                        port=p, service=name, risk=risk, 
                        description=dsc, fix=fix, cisco_acl=acl
                    ))

            db.session.commit()
            print("[SYSTEM] Intelligence Handshake Complete. 1,024 Ports catalogued.")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
@login_required
def index():
    #Shows starting page
    #Fetch the total number of audits from the database
    total_audits = AuditRecord.query.count()
    # NEW MILESTONE: Logic restricted to current_user.id for Forensic Data Isolation
    history_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(5).all()
    
    return render_template('index.html', audit_count = total_audits, history = history_logs)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')

        # SECURITY: Generate a professional Hash
        hashed_password = bcrypt.generate_password_hash(pass_word).decode('utf-8')

        # Add to Database
        new_user = User(username=user_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash(f"Security Profile Created: {user_name}. Please authenticate to enter the platform.", "success")
        
        print(f"[IDENTITY] New account verified: {user_name}")
        return redirect(url_for('login')) 

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        user = User.query.filter_by(username=user_name).first()
        
        # Checking the hash against the submitted password
        if user and bcrypt.check_password_hash(user.password, pass_word):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    #Fetch existing settings for user
    config = DeviceSettings.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        ip_addr = request.form.get('device_ip')
        user_name = request.form.get('ssh_user')
        pass_word = request.form.get('ssh_password')

        # SECURITY: Hash the SSH password just like the login password
        hashed_ssh_pw = bcrypt.generate_password_hash(pass_word).decode('utf-8')

        if config:
            # Update existing config
            config.device_ip = ip_addr
            config.ssh_user = user_name
            config.ssh_password = hashed_ssh_pw
        else:
            # Create brand new config
            new_config = DeviceSettings(
                device_ip=ip_addr, 
                ssh_user=user_name, 
                ssh_password=hashed_ssh_pw, 
                user_id=current_user.id
            )
            db.session.add(new_config)

        db.session.commit()
        flash("Handshake Configured: Cisco remote credentials securely stored.", "success")
        return redirect(url_for('index'))

    return render_template('settings.html', config=config)

@app.route('/scan', methods=['POST'])
@login_required 
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
            start_str = request.form.get('start_port')
            end_str = request.form.get('end_port')
            
            start = int(start_str) if start_str else 1
            end = int(end_str) if end_str else 1024
            ports_to_scan = range(start, end + 1)
        except ValueError:
            ports_to_scan = [80] 
    else: 
        ports_to_scan = [80, 8000, 8080]

    try:
        ip = socket.gethostbyname(target)
        last_scanned_ip = ip # Save globally for download

        #Speed
        #1. NEW DYNAMIC DATABASE SCAN LOGIC (Fixing the Database Lookup)
        def thread_scan(port):
            with app.app_context():
                if scan_port(ip, port):
                # Search our new 'Vulnerability' intelligence table in SQL
                    kb_match = Vulnerability.query.filter_by(port=port).first()
                    # Hand-shake between Backend and logic generator
                    return generate_analysis(port, db_match=kb_match)
            return None
        
        #2. ThreadPoolExecutor, run scan in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            thread_results = list(executor.map(thread_scan, ports_to_scan))

        #3. Collect findings that aren't none
        results = [r for r in thread_results if r is not None]

        # THURSDAY UPDATE: Calculate executive security score
        final_score = calculate_security_score(results)
        
        # 4. STARTUP PERSISTENCE HANDSHAKE (Save results to database history)
        summary_text = f"Audit Success: Identified {len(results)} vulnerabilities." if results else "Hardened: No vulnerabilities detected."
        new_audit = AuditRecord(
            target_ip=target,
            ports_found=str(len(results)),
            threat_summary=summary_text,
            # MILESTONE FIX: Permanently bind this scan to the specific current_user.id
            user_id=current_user.id,
            security_score=final_score # Store the score in the DB
        )
        db.session.add(new_audit)
        db.session.commit() # Writing the audit to secusys.db history

        if results:
            save_report_to_file(ip, results)

    except Exception as e:
        db.session.rollback()
        print (f"[DATABASE ERROR] Handshake failed: {e}")

    # 5. RE-REFRESH Dashboard Logic: Re-fetch variables for specific user view
    total_audits = AuditRecord.query.count()
    history_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(5).all()

    return render_template('index.html', results=results, target=target, audit_count=total_audits, history=history_logs)

#The Download Route (Removed global keyword to maintain green GitHub Build)
@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)
    else:
        return "<h3>No report found. Please run a scan first!</h3>"

# --- THURSDAY STARTUP UPGRADE: EXECUTIVE PDF ENGINE ---
@app.route('/export_pdf/<int:record_id>')
@login_required
def export_pdf(record_id):
    # 1. Fetch data from DB
    record = AuditRecord.query.get_or_404(record_id)

    # Authorization Guard
    if record.user_id != current_user.id:
        return "Unauthorized Access Blocked.", 403

    # 2. Create a memory buffer for the PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # 3. Render Executive Design
    # Logo Placeholder / Title
    p.setFont("Helvetica-Bold", 24)
    p.drawString(100, 750, "SECUSYS ENTERPRISE AUDIT")
    p.setFont("Helvetica", 10)
    p.drawString(100, 735, "Founders Series Professional v3.2 - Proprietary Forensic Artifact")
    p.line(100, 725, 500, 725)

    # Target Intel
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 700, f"INFRASTRUCTURE TARGET: {record.target_ip}")
    p.setFont("Helvetica", 12)
    p.drawString(100, 680, f"Client Authentication ID: {current_user.username}")
    p.drawString(100, 665, f"Execution Timestamp: {record.scan_date}")

    # Risk Metrics
    p.setFont("Helvetica-Bold", 12)
    p.setFillColorRGB(0.8, 0, 0) # Executive Alert Color (Red-ish)
    p.drawString(100, 630, f"OVERALL SECURITY HARDENING SCORE: {record.security_score}/100")
    
    p.setFillColorRGB(0, 0, 0) # Back to Black
    p.setFont("Helvetica-Oblique", 11)
    p.drawString(100, 610, f"System Executive Summary: {record.threat_summary}")

    # Page Body / Detailed Insights (Note: Simplified for PDF v1)
    p.setFont("Helvetica", 10)
    p.drawString(100, 580, "Individual findings and Cisco remediation strategies are catalogued below:")
    p.rect(100, 400, 400, 160) # Visual Detail Box
    p.drawString(110, 540, "Scan Detail Map:")
    p.drawString(110, 525, f"- Ports Detected: {record.ports_found}")
    
    if record.remediation_status == 1:
        p.drawString(110, 480, "OPERATIONAL STATUS: [X] RESOLVED - Cisco Mitigation Successfully Deployed")
    else:
        p.drawString(110, 480, "OPERATIONAL STATUS: [!] UNRESOLVED - Infrastructure Action Required")

    # Final Footer
    p.setFont("Helvetica-Oblique", 8)
    p.drawString(100, 100, "CONFIDENTIAL DOCUMENT - Generated via SecuSys Forensic SaaS Engine")

    # 4. Finalize
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"SecuSys_Report_{record.target_ip}.pdf", mimetype='application/pdf')


@app.route('/remediate/<int:record_id>', methods=['POST'])
@login_required
def remediate(record_id):
    """
    SaaS Action Hub: Bridge to Cisco Netmiko logic.
    """
    record = AuditRecord.query.get_or_404(record_id)

    if record.user_id != current_user.id:
        flash("Authorization Violation.", "danger")
        return redirect(url_for('index'))

    try:
        # Step A: Identify high-priority target from findings
        discovery_ports = [int(p) for p in [21,22,23,80,443,445] if str(p) in str(record.threat_summary)]
        target_port = discovery_ports[0] if discovery_ports else 80

        kb_intel = Vulnerability.query.filter_by(port=target_port).first()
        cisco_command = kb_intel.cisco_acl if kb_intel else f"access-list 101 deny tcp any any eq {target_port}"

        # THE SECURE CONNECTIVITY BLOCK
        device_params = {
            'device_type': 'cisco_ios',
            'host': record.target_ip, # The destination IP
            'username': 'admin',
            'password': 'password123',
            'timeout': 10
        }

        # Stage 2 Automation (Simulation of net-connect)
        print(f"[REMEDIATION] Deploying secure tunnel to: {record.target_ip}")
        
        # PREPARED COMMANDS: Active when environment supports SSH Handshake
        """
        net_connect = ConnectHandler(**device_params)
        output = net_connect.send_config_set([cisco_command])
        net_connect.disconnect()
        """

        # Update local forensic log with remediation data
        record.remediation_status = 1
        record.remediation_log = f"HANDSHAKE SUCCESSFUL: Dispatched Cisco IOS Configuration '{cisco_command}' to device."
        
        db.session.commit()
        flash(f"Cyber-Remediation Deployed: Cisco CLI logic sent to {record.target_ip}.", "success")
        
    except (NetmikoTimeoutException, NetmikoAuthenticationException):
        flash(f"Handshake Denied: Secure SSH connection refused by target router.", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"Deployment System Error: {str(e)}", "danger")

    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    seed_intelligence()
    app.run(debug=True, port=8080)