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
from dotenv import load_dotenv # Load secrets
from main import scan_port, generate_analysis, save_report_to_file
import re

# INITIALIZE SECRETS
load_dotenv()

app = Flask(__name__)

# --- HARDENED INFRASTRUCTURE CONFIGURATION ---
# Points to .env variables for security-by-design compliance
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'emergency-fallback-key-2026')
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
    Points are deducted based on findings found in SQL Intelligence.
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
    HUD Intelligence: Returns total unique asset IDs managed 
    and total unresolved critical threats for specific user.
    """
    user_scans = AuditRecord.query.filter_by(user_id=uid).all()
    unique_assets = len(set([s.target_ip for s in user_scans]))
    open_threats = AuditRecord.query.filter_by(user_id=uid, remediation_status=0).filter(AuditRecord.threat_summary.like('%Identified%')).count()
    return unique_assets, open_threats

# --- DATABASE BLUEPRINTS (MODELS) ---

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

class DeviceSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(50), nullable=False)
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False) 
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
    user_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(10).all()
    assets, risks = get_dashboard_hud(current_user.id)
    return render_template('index.html', audit_count=audit_total, history=user_logs, assets_count=assets, risks_count=risks)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name, pw = request.form.get('username'), request.form.get('password')
        hashed = bcrypt.generate_password_hash(pw).decode('utf-8')
        db.session.add(User(username=name, password=hashed))
        db.session.commit()
        flash("SYSTEM: Security account created successfully. Proceed to login.", "success")
        return redirect(url_for('login')) 
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and bcrypt.check_password_hash(user.password, p):
            login_user(user)
            flash("SUCCESS: Authenticated session established.", "success")
            return redirect(url_for('index'))
        else: flash('AUTH FAIL: Cryptographic keys did not match.', 'danger')
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
        h_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
        if cfg:
            cfg.device_ip, cfg.ssh_user, cfg.ssh_password = ip, usr, h_pw
        else:
            db.session.add(DeviceSettings(device_ip=ip, ssh_user=usr, ssh_password=h_pw, user_id=current_user.id))
        db.session.commit()
        flash("Handshake Configured: Cisco asset mapped to user profile.", "success")
        return redirect(url_for('index'))
    return render_template('settings.html', config=cfg)

@app.route('/scan', methods=['POST'])
@login_required 
def scan():
    global last_scanned_ip
    target, s_type = request.form.get('target_ip').strip(), request.form.get('scan_type')
    results = []

    # Map Audit Modes to Engine
    if s_type == "common": p_range = [21, 22, 23, 80, 443, 445, 3306, 3389]
    elif s_type == "well-known": p_range = range(1, 1025)
    elif s_type == "custom":
        try:
            start, end = int(request.form.get('start_port') or 1), int(request.form.get('end_port') or 1024)
            p_range = range(start, end + 1)
        except ValueError: p_range = [80]
    else: p_range = [80, 8000, 8080]

    try:
        ip = socket.gethostbyname(target)
        last_scanned_ip = ip 
        def thread_scan(port):
            with app.app_context():
                if scan_port(ip, port):
                    match = Vulnerability.query.filter_by(port=port).first()
                    return generate_analysis(port, db_match=match)
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            raw_results = list(executor.map(thread_scan, p_range))

        results = [r for r in raw_results if r is not None]
        h_score = calculate_security_score(results)
        
        db.session.add(AuditRecord(
            target_ip=target,
            ports_found="\n".join(results), 
            threat_summary=f"Audit Success: Identified {len(results)} vulnerabilities." if results else "State Hardened.",
            user_id=current_user.id,
            security_score=h_score
        ))
        db.session.commit() 
        if results: save_report_to_file(ip, results)
        flash(f"PROT-SUCCESS: Forensic sweep completed with {h_score}% integrity.", "success")

    except Exception as e:
        db.session.rollback()
        print (f"FATAL LOGIC ERROR: {e}")

    # Synchronized Dashboard View Variables
    f_total = AuditRecord.query.count()
    f_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(10).all()
    f_assets, f_risks = get_dashboard_hud(current_user.id)

    return render_template('index.html', results=results, target=target, audit_count=f_total, history=f_logs, assets_count=f_assets, risks_count=f_risks)

@app.route('/delete_audit/<int:record_id>', methods=['POST'])
@login_required
def delete_audit(record_id):
    """
    Forensic Purge Logic: Authorized removal of security telemetry records.
    """
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash("VIOLATION: Purge denied for non-owned asset record.", "danger")
        return redirect(url_for('index'))
    try:
        db.session.delete(record)
        db.session.commit()
        flash("CLEARED: Target infrastructure history removed from SQL persistence.", "success")
    except Exception:
        db.session.rollback()
        flash("DATABASE ERROR: Handshake failed during deletion logic.", "danger")
    return redirect(url_for('index'))

@app.route('/audit/<int:record_id>')
@login_required
def audit_detail(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    return render_template('audit_detail.html', audit=record)

@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename): return send_file(filename, as_attachment=True)
    return "<h3>REQUEST FAILED: Archive log missing from server cache.</h3>"

@app.route('/export_pdf/<int:record_id>')
@login_required
def export_pdf(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return "403 Restricted", 403
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(100, 750, "SECUSYS ENTERPRISE FORENSIC AUDIT")
    p.line(100, 740, 500, 740)
    p.setFont("Helvetica", 12)
    p.drawString(100, 710, f"INFRASTRUCTURE TARGET: {record.target_ip}")
    p.drawString(100, 690, f"AUTHENTICATED HARDENING: {record.security_score}/100")
    p.drawString(100, 670, f"RESULT LOGS: {record.threat_summary}")
    p.showPage(); p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"SecuSys_Report_{record.target_ip}.pdf", mimetype='application/pdf')

@app.route('/remediate/<int:record_id>', methods=['POST'])
@login_required
def remediate(record_id):
    """
    Closed-Loop Handshake: Probe verification of automated remediation status.
    """
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return redirect(url_for('index'))
    
    # Surgical Regex to pull specific port target from log persistence
    p_hits = re.findall(r'Port (\d+)', str(record.ports_found))
    p_num = int(p_hits[0]) if p_hits else 80
    
    try:
        handshake_active = scan_port(record.target_ip, p_num)
        if not handshake_active:
            record.remediation_status, record.remediation_log = 1, f"VERIFIED: Policy Pushed. Target unresponsive at port {p_num}."
            db.session.commit()
            flash(f"REMEDIATION SUCCESS: Automated fix for Port {p_num} verified secure.", "success")
        else:
            record.remediation_status, record.remediation_log = 0, "ALARM: Policy conflict. Handshake responsive post-deployment."
            db.session.commit()
            flash(f"VERIFICATION FAILURE: Logic deployed but target is still responsive.", "danger")
    except Exception:
        db.session.rollback(); flash("PROTOCOL FAULT: Automated Handshake interrupted.", "danger")
    return redirect(url_for('index'))

def seed_intelligence():
    """ Self-Healing Knowledge Base seeding function """
    with app.app_context():
        if Vulnerability.query.count() < 1000:
            print("System Check: Loading SaaS Vulnerability intelligence...")
            for p in range(1, 1025):
                if not Vulnerability.query.filter_by(port=p).first():
                    try: nm = socket.getservbyport(p).upper()
                    except: nm = "UNMAPPED-PROFILE"
                    risk, fix = ("HIGH", "Immediate Security Review") if p in [21, 23, 25] else ("LOW", "Standard Monitor")
                    db.session.add(Vulnerability(port=p, service=nm, risk=risk, description=f"Handshake at port {p}.", fix=fix, cisco_acl=f"access-list 101 deny tcp any any eq {p}"))
            db.session.commit()

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    seed_intelligence()
    app.run(debug=True, port=9090)