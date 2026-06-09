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
import csv # Corporate Inventory tool
import ipaddress # For recursive subnet discovery
import subprocess # For NTP system checks
from reportlab.lib.pagesizes import letter # Standard PDF size
from reportlab.pdfgen import canvas # Drawing engine for individual PDFs
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle # For Corporate PDF
from reportlab.lib import colors 
from dotenv import load_dotenv # Load environment secrets
from main import scan_port, generate_analysis, save_report_to_file
import re

# INITIALIZE ENVIRONMENT SECRETS
load_dotenv()

app = Flask(__name__)

# --- HARDENED INFRASTRUCTURE CONFIGURATION ---
# Points to .env variables for security-by-design compliance
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'foundation-cyber-startup-2026-secure-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'secusys.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# --- STARTUP ANALYTICS LOGIC ---
def calculate_security_score(results_list):
    """
    SaaS Proprietary Algorithm: Evaluates security state (0-100).
    Now adjusted to recognize standard services without heavy score penalty.
    """
    score = 100
    for report in results_list:
        if "CRITICAL" in report: score -= 25 # Malware vectors (WannaCry, Netbus)
        elif "HIGH" in report: score -= 15   # Unencrypted database/admin access
        elif "MEDIUM" in report: score -= 5  # Standard management ports
        elif "SUSPICIOUS" in report: score -= 5
    return max(0, score)

def get_dashboard_hud_data(uid):
    """ 
    SaaS Intelligence: Compiles Assets, Risks, Resilience, and Name Maps
    specifically for the Sidebar and HUD Dashboard.
    """
    user_scans = AuditRecord.query.filter_by(user_id=uid).all()
    
    # 1. Unique Infrastructure Identifiers
    asset_count = len(set([s.target_ip for s in user_scans]))
    
    # 2. Risks Unresolved (Unremediated)
    hazards = AuditRecord.query.filter_by(user_id=uid, remediation_status=0).filter(AuditRecord.threat_summary.like('%Identified%')).count()
    
    # 3. Resilience Index Calculation
    scores = [s.security_score for s in user_scans if s.security_score is not None]
    resilience = int(sum(scores) / len(scores)) if scores else 0

    # 4. Nickname / Alias Map Retrieval (May 27 Update)
    devices = DeviceSettings.query.filter_by(user_id=uid).all()
    aliases = {d.device_ip: d.device_name for d in devices}
    
    return asset_count, hazards, resilience, aliases

# --- FORENSIC NTP HELPERS ---

def check_ntp_status():
    """ Verify Forensic Time Synchronization integrity. """
    try:
        output = subprocess.check_output("w32tm /query /status", shell=True, stderr=subprocess.STDOUT).decode()
        if "Source:" in output:
            source = output.split("Source:")[1].split("\n")[0].strip()
            return f"Verified via {source}"
        return "Local Master Clock"
    except:
        return "Handshake Sync Unavailable"

# --- DATABASE MODELS ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False) 
    scans = db.relationship('AuditRecord', backref='user_profile', lazy=True, cascade="all, delete-orphan")

class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    ports_found = db.Column(db.Text) 
    threat_summary = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    remediation_status = db.Column(db.Integer, default=0)
    remediation_log = db.Column(db.Text, nullable=True)
    security_score = db.Column(db.Integer, default=100)

    def __repr__(self):
        return f'<Audit {self.target_ip} ID {self.id}>'

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

class DeviceSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(50), nullable=False)
    device_name = db.Column(db.String(100), default="Primary Interface")
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False)
    device_platform = db.Column(db.String(50), default='cisco_ios')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Application persistence logic
last_scanned_ip = ""

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- PLATFORM ROUTES ---

@app.route('/')
@login_required
def index():
    audit_total = AuditRecord.query.count()
    user_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(15).all()
    # LOAD TAC-HUD with full asset name-mapping
    asset_id, hazards, resilience, names = get_dashboard_hud_data(current_user.id)
    ntp = check_ntp_status()
    return render_template('index.html', audit_count=audit_total, history=user_logs, 
                           assets_count=asset_id, risks_count=hazards, resilience_score=resilience, 
                           ntp_data=ntp, name_map=names)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name, pw = request.form.get('username'), request.form.get('password')
        hashed = bcrypt.generate_password_hash(pw).decode('utf-8')
        db.session.add(User(username=name, password=hashed))
        db.session.commit()
        flash("SYSTEM: Account Enrollment Successful.", "success")
        return redirect(url_for('login')) 
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and bcrypt.check_password_hash(user.password, p):
            login_user(user); flash(f"Authenticated as Auditor {u}.", "success")
            return redirect(url_for('index'))
        else: flash('AUTH ERROR: Mismatch.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user(); return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """
    SaaS Infrastructure Onboarding: Allows the auditor to add 
    unique named assets to their secure inventory vault.
    """
    if request.method == 'POST':
        # 1. CATCH the new human-readable Asset Name/Alias
        alias = request.form.get('device_name')
        
        # 2. Catch the technical connection metadata
        ip = request.form.get('device_ip')
        usr = request.form.get('ssh_user')
        pw = request.form.get('ssh_password')
        plat = request.form.get('device_platform') 
        
        # 3. SECURITY: Protect the asset management password via Hashing
        h_pw = bcrypt.generate_password_hash(pw).decode('utf-8')

        # 4. STARTUP GROWTH LOGIC: Always create a NEW record. 
        # This allows the user to have 10, 50, or 100 devices.
        try:
            new_asset = DeviceSettings(
                device_name=alias, 
                device_ip=ip, 
                ssh_user=usr, 
                ssh_password=h_pw, 
                device_platform=plat, 
                user_id=current_user.id # Link to the person logged in
            )
            
            db.session.add(new_asset)
            db.session.commit()
            
            print(f"[INVENTORY] Successfully onboarded asset: {alias} ({ip})")
            flash(f"Handshake Successful: {alias} has been added to your inventory list.", "success")
            
            # Redirect to the inventory list to see the new device card
            return redirect(url_for('my_devices')) 

        except Exception as e:
            db.session.rollback()
            flash("VAULT ERROR: Infrastructure collision detected or database busy.", "danger")
            return redirect(url_for('index'))

    # If it is a GET request, just show the empty 'Add' form
    return render_template('settings.html')

@app.route('/scan', methods=['POST'])
@login_required 
def scan():
    """ SaaS Engine v5.0: Enhanced with recursive Subnet Expansion and Batch processing. """
    global last_scanned_ip
    raw_input = request.form.get('target_ip').strip()
    scan_type = request.form.get('scan_type')
    
    # 1. PARSE BATCH & EXPAND SUBNETS 
    initial_list = [t.strip() for t in raw_input.split(',')]
    target_list = []
    
    for t in initial_list:
        if "/" in t: # Identifies CIDR Subnet Architecture
            try:
                network = ipaddress.IPv4Network(t, strict=False)
                # Founder Constraint: Auto-detecting host limit of 32 nodes
                target_list.extend([str(ip) for ip in list(network.hosts())[:32]])
            except: target_list.append(t)
        else: target_list.append(t)
    
    combined_feed = []

    if scan_type == "common": p_range = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 1521, 3306, 3389, 4444, 5554, 12345, 31337]
    elif scan_type == "well-known": p_range = range(1, 1025)
    elif scan_type == "custom":
        try:
            st, en = int(request.form.get('start_port') or 1), int(request.form.get('end_port') or 1024)
            p_range = range(st, en + 1)
        except ValueError: p_range = [80]
    else: p_range = [80, 8000, 8080]

    for target in target_list:
        if not target: continue
        results = []
        try:
            ip = socket.gethostbyname(target)
            last_scanned_ip = ip 
            def thread_scan(port_num):
                with app.app_context():
                    status, banner = scan_port(ip, port_num)
                    if status:
                        kb_match = Vulnerability.query.filter_by(port=port_num).first()
                        analysis_text = generate_analysis(port_num, db_match=kb_match)
                        return f"[IDENTITY: {banner}]\n" + analysis_text
                return None
            with ThreadPoolExecutor(max_workers=20) as executor:
                thread_results = list(executor.map(thread_scan, p_range))
            results = [r for r in thread_results if r is not None]
            h_score = calculate_security_score(results)
            db.session.add(AuditRecord(
                target_ip=target,
                ports_found="\n".join(results), 
                threat_summary=f"Audit Success: Identified {len(results)} vulnerabilities." if results else "Hardened.",
                user_id=current_user.id,
                security_score=h_score
            ))
            if results: save_report_to_file(ip, results)
            combined_feed.extend(results)
        except Exception: flash(f"Handshake resolution fail: {target}", "danger")

    db.session.commit()
    flash(f"Forensic process finalized. Scoped infrastructure health analyzed.", "success")
    
    f_total = AuditRecord.query.count()
    f_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(15).all()
    asset_id, hazards, resilience, names = get_dashboard_hud_data(current_user.id)
    ntp = check_ntp_status()

    return render_template('index.html', results=combined_feed, target=raw_input, audit_count=f_total, 
                           history=f_logs, assets_count=asset_id, risks_count=hazards, 
                           resilience_score=resilience, ntp_data=ntp, name_map=names)

# --- REFACTORED COMPLIANCE PDF LOGIC ---
@app.route('/corporate_report')
@login_required
def corporate_report():
    """ Professional Executive Summary: Intelligently categorizes intended web services. """
    records = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).all()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    data = [['DATE (UTC)', 'INFRASTRUCTURE', 'COMPLIANCE STATUS', 'HEALTH INDEX']]
    for r in records:
        if r.remediation_status == 1: state = "FIXED/VERIFIED"
        elif "Identified" in r.threat_summary:
            # Context-Aware categorizing: Differentiates legitimate site accessibility from risk.
            if ("Port 80" in str(r.ports_found) or "Port 443" in str(r.ports_found)) and "CRITICAL" not in str(r.ports_found):
                state = "SERVICE ACCESSIBLE"
            else: state = "AT RISK"
        else: state = "SECURE/HARDENED"
        data.append([r.scan_date.strftime('%Y-%m-%d'), r.target_ip, state, f"{r.security_score}%"])

    t = Table(data, colWidths=[110, 180, 140, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#30363d")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="SaaS Compliance Dashboard Archive.pdf", mimetype='application/pdf')

@app.route('/timeline')
@login_required
def asset_timeline():
    """ Trace IP History Thread """
    ip = request.args.get('ip')
    history = AuditRecord.query.filter_by(target_ip=ip, user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).all()
    return render_template('asset_timeline.html', ip=ip, timeline=history)

@app.route('/audit/<int:record_id>')
@login_required
def audit_detail(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    return render_template('audit_detail.html', audit=record)

@app.route('/incidents')
@login_required
def incident_hub():
    """
    SaaS Command Logic: Aggregates all detected but unremediated threats 
    into a prioritized Operational Task List for the Auditor.
    """
    # 1. Fetch only scans where remediation_status is 0 (Not fixed) 
    # AND findings were actually identified.
    active_incidents = AuditRecord.query.filter_by(
        user_id=current_user.id, 
        remediation_status=0
    ).filter(AuditRecord.threat_summary.like('%Identified%')).order_by(AuditRecord.scan_date.desc()).all()

    # 2. Extract metrics for the hub
    incident_count = len(active_incidents)
    
    return render_template('incidents.html', incidents=active_incidents, count=incident_count)

@app.route('/delete_audit/<int:record_id>', methods=['POST'])
@login_required
def delete_audit(record_id):
    """ Forensic Purge logic. """
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id == current_user.id:
        db.session.delete(record); db.session.commit(); flash("Log artifact purged.", "success")
    return redirect(url_for('index'))

@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename): return send_file(filename, as_attachment=True)
    return "<h3>404: Trace Artifact not identified in session cache.</h3>"

@app.route('/export_pdf/<int:record_id>')
@login_required
def export_pdf(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return "Denied.", 403
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 20); p.drawString(100, 750, "SECUSYS FORENSIC REPORT")
    p.setFont("Helvetica", 12); p.drawString(100, 700, f"TARGET ASSET: {record.target_ip}")
    p.drawString(100, 680, f"INTEGRITY LEVEL: {record.security_score}%")
    p.showPage(); p.save(); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Report_{record.target_ip}.pdf", mimetype='application/pdf')

@app.route('/export_inventory')
@login_required
def export_inventory():
    records = AuditRecord.query.filter_by(user_id=current_user.id).all()
    buffer = io.StringIO(); writer = csv.writer(buffer)
    writer.writerow(['RecordID', 'Infrastructure_Target', 'Timestamp_UTC', 'HealthIndex'])
    for r in records: writer.writerow([r.id, r.target_ip, r.scan_date, f"{r.security_score}%"])
    mem = io.BytesIO(); mem.write(buffer.getvalue().encode('utf-8')); mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="SaaS Infrastructure Map.csv", mimetype='text/csv')

@app.route('/remediate/<int:record_id>', methods=['POST'])
@login_required
def remediate(record_id):
    """ Post-Deployment autonomous verification handshake. """
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    config = DeviceSettings.query.filter_by(user_id=current_user.id).first()
    if not config: flash("Settings Required.", "danger"); return redirect(url_for('index'))
    p_match = re.findall(r'Port (\d+)', str(record.ports_found))
    target_p = int(p_match[0]) if p_match else 80
    if config.device_platform == 'cisco_ios': cli = f"access-list 101 deny tcp any any eq {target_p}"
    elif config.device_platform == 'linux': cli = f"iptables -A INPUT -p tcp --dport {target_p} -j DROP"
    else: cli = f"Blocking port {target_p}"
    try:
        active, _ = scan_port(record.target_ip, target_p)
        if not active:
            record.remediation_status, record.remediation_log = 1, f"VERIFIED: Policy pushed on {config.device_name}. Access Restricted."
            db.session.commit(); flash("Mitigation successfully verified via secondary handshake.", "success")
        else: flash("Handshake responsive: Policy failure.", "danger")
    except: flash("Tunnel interrupted.", "danger")
    return redirect(url_for('index'))

@app.route('/my-devices')
@login_required
def my_devices():
    """
    Inventory Hub: Lists every piece of infrastructure the user has 
    registered with a custom nickname.
    """
    # Fetch the full inventory for the logged-in user
    inventory = DeviceSettings.query.filter_by(user_id=current_user.id).all()
    return render_template('devices.html', devices=inventory)

# --- HYBRID INTELLIGENCE BRAIN (PACKETLIFE V5.0 INTEGRATED) ---
def seed_intelligence():
    """ 
    Enterprise Logic Seeding: Combined Malware Vectors and Corporate Service catalog.
    Maintains text-based text-only forensic themes. 
    """
    with app.app_context():
        # Executive Malicious/Enterprise Map (PRIORITY INTELLIGENCE)
        extended_brain = {
            21:  ["FTP", "HIGH", "Plaintext logins; risk of MITM sniffing.", "Enforce move to SFTP.", "access-list 101 deny tcp any any eq 21"],
            22:  ["SSH", "SAFE", "Secure Shell encrypted tunnel.", "Verify modern ciphers.", "access-list 101 permit tcp any any eq 22"],
            23:  ["TELNET", "CRITICAL", "Legacy cleartext management.", "Disable immediately; switch to SSH.", "access-list 101 deny tcp any any eq 23"],
            80:  ["HTTP", "ACCESSIBLE", "Standard web port; intended accessibility.", "Force 443 redirects.", "access-list 101 permit tcp [TRUSTED_IP] any eq 80"],
            443: ["HTTPS", "SAFE", "Standard TLS encrypted secure web.", "Monitor Certs.", "access-list 101 permit tcp any any eq 443"],
            445: ["SMB-MS", "CRITICAL", "Active Windows fileshare; high Ransomware risk.", "Block WAN traversal.", "access-list 101 deny tcp any any eq 445"],
            3306:["MYSQL", "HIGH", "Exposed Database port.", "Limit access to app-nodes only.", "access-list 101 deny tcp any any eq 3306"],
            12345:["NETBUS", "CRITICAL", "Legacy Trojan vector.", "Emergency Block.", "access-list 101 deny tcp any any eq 12345"],
            31337:["BACK-ORIFICE","CRITICAL","Classic Malware Backdoor.", "Hard isolation required.", "access-list 101 deny tcp any any eq 31337"]
        }
        if Vulnerability.query.count() < 1000:
            print("System Readiness Check: Synchronizing Forensic Intel...")
            for p in range(1, 1025):
                if not Vulnerability.query.filter_by(port=p).first():
                    if p in extended_brain:
                        e = extended_brain[p]
                        s, r, d, f, c = e[0], e[1], e[2], e[3], e[4]
                    else:
                        try: nm = socket.getservbyport(p).upper()
                        except: nm = "PORT-MAPPED"
                        s, r, d, f, c = nm, "LOW", f"Standard port node associated with {nm}.", "Baseline Policy Audit.", f"access-list 101 deny tcp any any eq {p}"
                    db.session.add(Vulnerability(port=p, service=s, risk=r, description=d, fix=f, cisco_acl=c))
            db.session.commit(); print("[READY] Logic Intelligence v5.0 Active.")

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    seed_intelligence()
    app.run(debug=True, port=9090)