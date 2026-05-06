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
from reportlab.lib.pagesizes import letter # Standard PDF size
from reportlab.pdfgen import canvas # The drawing engine for PDFs
from dotenv import load_dotenv # Load secrets
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
    Higher threat density reduces the infrastructure index.
    """
    score = 100
    for report in results_list:
        if "CRITICAL" in report: score -= 20
        elif "HIGH" in report: score -= 10
        elif "MEDIUM" in report: score -= 5
        elif "SUSPICIOUS" in report: score -= 5
    return max(0, score)

def get_dashboard_hud(uid):
    """
    Business Intelligence Logic: Calculates Infrastructure Assets, 
    Open Compliance Risks, and the Global Resilience Index.
    """
    user_scans = AuditRecord.query.filter_by(user_id=uid).all()
    
    # 1. Managed Infrastructure Asset Count (Unique IPs)
    unique_assets = len(set([s.target_ip for s in user_scans]))
    
    # 2. Open Compliance Vulnerabilities (Unremediated)
    unresolved_risks = AuditRecord.query.filter_by(user_id=uid, remediation_status=0).filter(AuditRecord.threat_summary.like('%Identified%')).count()
    
    # 3. NEW: Resilience Index (Global Hardening Average)
    all_scores = [s.security_score for s in user_scans if s.security_score is not None]
    resilience = int(sum(all_scores) / len(all_scores)) if all_scores else 0
    
    return unique_assets, unresolved_risks, resilience

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
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False) 
    device_platform = db.Column(db.String(50), default='cisco_ios')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)

# Application Context Tracking
last_scanned_ip = ""

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTE HANDLERS ---

@app.route('/')
@login_required
def index():
    audit_total = AuditRecord.query.count()
    user_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(15).all()
    # FETCH Dynamic SaaS metrics
    assets, risks, resilience = get_dashboard_hud(current_user.id)
    return render_template('index.html', audit_count=audit_total, history=user_logs, assets_count=assets, risks_count=risks, resilience_score=resilience)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name, pw = request.form.get('username'), request.form.get('password')
        hashed = bcrypt.generate_password_hash(pw).decode('utf-8')
        db.session.add(User(username=name, password=hashed))
        db.session.commit()
        flash("SYSTEM: Account Enrollment Successful. Proceed to login.", "success")
        return redirect(url_for('login')) 
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and bcrypt.check_password_hash(user.password, p):
            login_user(user); flash(f"Authenticated as {u}.", "success")
            return redirect(url_for('index'))
        else: flash('AUTH ERROR: Cryptographic mismatch.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    cfg = DeviceSettings.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        ip, usr, pw = request.form.get('device_ip'), request.form.get('ssh_user'), request.form.get('ssh_password')
        plat = request.form.get('device_platform') 
        h_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
        if cfg:
            cfg.device_ip, cfg.ssh_user, cfg.ssh_password, cfg.device_platform = ip, usr, h_pw, plat
        else:
            db.session.add(DeviceSettings(device_ip=ip, ssh_user=usr, ssh_password=h_pw, device_platform=plat, user_id=current_user.id))
        db.session.commit()
        flash(f"Infrastructure Standard Mapped: {plat.upper()}.", "success")
        return redirect(url_for('index'))
    return render_template('settings.html', config=cfg)

@app.route('/scan', methods=['POST'])
@login_required 
def scan():
    global last_scanned_ip
    # NEW STARTUP LOGIC: Batch Target Parsing (Subnet discovery ready)
    raw_input = request.form.get('target_ip').strip()
    target_list = [t.strip() for t in raw_input.split(',')]
    scan_type = request.form.get('scan_type')
    
    combined_feed = [] # Aggregated dashboard view for batch results

    # Determine Port Range
    if scan_type == "common": p_range = [21, 22, 23, 80, 443, 445, 3306, 3389]
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
                    if scan_port(ip, port_num):
                        match = Vulnerability.query.filter_by(port=port_num).first()
                        return generate_analysis(port_num, db_match=match)
                return None
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                thread_results = list(executor.map(thread_scan, p_range))

            results = [r for r in thread_results if r is not None]
            h_score = calculate_security_score(results)
            
            db.session.add(AuditRecord(
                target_ip=target,
                ports_found="\n".join(results), 
                threat_summary=f"Audit Success: Identified {len(results)} vulnerabilities." if results else "State Hardened.",
                user_id=current_user.id,
                security_score=h_score
            ))
            
            if results: save_report_to_file(ip, results)
            combined_feed.extend(results)

        except Exception:
            flash(f"SCAN HANDSHAKE FAILED: Asset {target} resolution error.", "danger")

    db.session.commit()
    flash(f"System Check Complete: Hardening session for {len(target_list)} unique targets.", "success")

    # Refresh Dashboard state variables
    f_total = AuditRecord.query.count()
    f_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(15).all()
    f_assets, f_risks, f_resilience = get_dashboard_hud(current_user.id)

    return render_template('index.html', results=combined_feed, target=raw_input, audit_count=f_total, history=f_logs, assets_count=f_assets, risks_count=f_risks, resilience_score=f_resilience)

@app.route('/audit/<int:record_id>')
@login_required
def audit_detail(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    return render_template('audit_detail.html', audit=record)

@app.route('/delete_audit/<int:record_id>', methods=['POST'])
@login_required
def delete_audit(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    try:
        db.session.delete(record); db.session.commit(); flash("Audit purged from forensic history.", "success")
    except: db.session.rollback(); flash("Platform Exception during purge.", "danger")
    return redirect(url_for('index'))

@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename): return send_file(filename, as_attachment=True)
    return "<h3>No active session report found.</h3>"

@app.route('/export_pdf/<int:record_id>')
@login_required
def export_pdf(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return "403 Forbidden", 403
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(100, 750, "SECUSYS ENTERPRISE FORENSIC RECORD")
    p.line(100, 740, 500, 740)
    p.setFont("Helvetica", 12)
    p.drawString(100, 710, f"INFRASTRUCTURE TARGET: {record.target_ip}")
    p.drawString(100, 680, f"AUTHENTICATED HARDENING: {record.security_score}/100")
    p.showPage(); p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Report_{record.target_ip}.pdf", mimetype='application/pdf')

@app.route('/export_inventory')
@login_required
def export_inventory():
    records = AuditRecord.query.filter_by(user_id=current_user.id).all()
    buffer = io.StringIO(); writer = csv.writer(buffer)
    writer.writerow(['RecordID', 'Infrastructure_Target', 'Timestamp_UTC', 'Integrity_Score'])
    for r in records: writer.writerow([r.id, r.target_ip, r.scan_date, r.security_score])
    mem = io.BytesIO(); mem.write(buffer.getvalue().encode('utf-8')); mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"SecuSys_Portfolio_Inventory.csv", mimetype='text/csv')

@app.route('/remediate/<int:record_id>', methods=['POST'])
@login_required
def remediate(record_id):
    """
    Closed-Loop Remediation Logic with Autonomous Verification Handshake
    """
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    
    config = DeviceSettings.query.filter_by(user_id=current_user.id).first()
    if not config:
        flash("SYSTEM BLOCKED: Device onboarding required in settings vault.", "danger")
        return redirect(url_for('index'))
    
    p_match = re.findall(r'Port (\d+)', str(record.ports_found))
    target_p = int(p_match[0]) if p_match else 80
    
    # Multivendor Policy Generator (Handshake Selection)
    if config.device_platform == 'cisco_ios':
        cli = f"access-list 101 deny tcp any any eq {target_p}"
    elif config.device_platform == 'linux':
        cli = f"iptables -A INPUT -p tcp --dport {target_p} -j DROP"
    else: cli = f"Handshake Default for port {target_p}"

    try:
        handshake_fail = scan_port(record.target_ip, target_p)
        if not handshake_fail:
            record.remediation_status, record.remediation_log = 1, f"VERIFIED: {config.device_platform.upper()} successful block of Port {target_p}."
            db.session.commit(); flash("SYSTEM SUCCESS: Mitigation confirmed by secondary probe.", "success")
        else:
            record.remediation_log = f"PROTOCOL FAILURE: Port {target_p} remains active on {config.device_platform}."
            db.session.commit(); flash("SECUSYS WARNING: Policy Handshake Failure.", "danger")
    except: flash("ERROR: Telemetry tunnel interrupted.", "danger")
    return redirect(url_for('index'))

def seed_intelligence():
    """ Self-Filling Brain migration """
    with app.app_context():
        if Vulnerability.query.count() < 1000:
            print("System Readiness Check: Synchronizing SQL knowledge...")
            for p in range(1, 1025):
                if not Vulnerability.query.filter_by(port=p).first():
                    try: name = socket.getservbyport(p).upper()
                    except: name = "DYNAMIC-PROFILE"
                    db.session.add(Vulnerability(port=p, service=name, risk="LOW", description=f"Handshake at {p}", fix="Manual check suggested", cisco_acl=f"access-list 101 deny tcp any any eq {p}"))
            db.session.commit()

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    seed_intelligence()
    app.run(debug=True, port=9090)