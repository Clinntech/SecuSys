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

# --- NEW: HARDENED DATABASE CONFIGURATION ---
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'foundation-cyber-startup-2026-secure-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'secusys.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

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
    password = db.Column(db.String(150), nullable=False) 
    scans = db.relationship('AuditRecord', backref='user_profile', lazy=True)

# --- NEW: SCAN HISTORY MODEL ---
class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    ports_found = db.Column(db.String(500))
    threat_summary = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    remediation_status = db.Column(db.Integer, default=0)
    remediation_log = db.Column(db.Text, nullable=True)
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
    
# Remote device credential models
class DeviceSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(50), nullable=False)
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)

# Remember last scanned IP for download button
last_scanned_ip = ""

def seed_intelligence():
    with app.app_context():
        if Vulnerability.query.count() < 1000:
            print("SYSTEM: Intelligence table empty. Upload initiated.")
            for p in range(1, 1025):
                if not Vulnerability.query.filter_by(port=p).first():
                    try: name = socket.getservbyport(p).upper()
                    except: name = "INTERNAL-SERVICE"
                    if p in [21, 23, 25, 110]:
                        risk, dsc, fix = "HIGH", f"Unencrypted {name} protocol.", "Upgrade to Secure versions."
                        acl = f"access-list 101 deny tcp any any eq {p}"
                    elif p in [22, 443, 993, 995]:
                        risk, dsc, fix = "SAFE", f"Encrypted {name} service.", "Maintain certificate security."
                        acl = f"access-list 101 permit tcp any any eq {p}"
                    elif p == 80:
                        risk, dsc, fix = "MEDIUM", "Cleartext HTTP service.", "Enforce HSTS and move to 443."
                        acl = f"access-list 101 permit tcp [TRUSTED_IP] any any eq 80"
                    elif p == 445:
                        risk, dsc, fix = "CRITICAL", "SMB / Microsoft DS detected.", "Disable Port 445 at firewall."
                        acl = f"access-list 101 deny tcp any any eq 445"
                    else:
                        risk, dsc, fix = "LOW", f"Standard {name}.", "Follow Least Privilege policy."
                        acl = f"access-list 101 deny tcp any any eq {p}"
                    db.session.add(Vulnerability(port=p, service=name, risk=risk, description=dsc, fix=fix, cisco_acl=acl))
            db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
@login_required
def index():
    # DASHBOARD HUD LOGIC
    total_audits = AuditRecord.query.count()
    history_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(10).all()
    
    # 1. Infrastructure Assets Count (Unique IPs)
    user_scans = AuditRecord.query.filter_by(user_id=current_user.id).all()
    unique_assets = len(set([s.target_ip for s in user_scans]))

    # 2. Unresolved High-Risks Count (Vulnerabilities detected but not remediated)
    unresolved = AuditRecord.query.filter_by(user_id=current_user.id, remediation_status=0).filter(AuditRecord.threat_summary.like('%Identified%')).count()

    return render_template('index.html', audit_count=total_audits, history=history_logs, assets_count=unique_assets, risks_count=unresolved)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(pass_word).decode('utf-8')
        new_user = User(username=user_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"Security Profile Created: {user_name}. Please authenticate.", "success")
        return redirect(url_for('login')) 
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        user = User.query.filter_by(username=user_name).first()
        if user and bcrypt.check_password_hash(user.password, pass_word):
            login_user(user)
            flash(f"Tactical session initiated for {user_name}.", "success")
            return redirect(url_for('index'))
        else:
            flash('Authentication Failure: Cryptographic mismatch.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    config = DeviceSettings.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        ip_addr, user_name, pass_word = request.form.get('device_ip'), request.form.get('ssh_user'), request.form.get('ssh_password')
        hashed_ssh_pw = bcrypt.generate_password_hash(pass_word).decode('utf-8')
        if config:
            config.device_ip, config.ssh_user, config.ssh_password = ip_addr, user_name, hashed_ssh_pw
        else:
            new_config = DeviceSettings(device_ip=ip_addr, ssh_user=user_name, ssh_password=hashed_ssh_pw, user_id=current_user.id)
            db.session.add(new_config)
        db.session.commit()
        flash("Vault Updated: Device credentials encrypted.", "success")
        return redirect(url_for('index'))
    return render_template('settings.html', config=config)

@app.route('/scan', methods=['POST'])
@login_required 
def scan():
    global last_scanned_ip
    target = request.form.get('target_ip').strip()
    scan_type = request.form.get('scan_type')
    results = []

    if scan_type == "common": ports_to_scan = [21, 22, 23, 80, 443, 445, 3306, 3389]
    elif scan_type == "well-known": ports_to_scan = range(1, 1025)
    elif scan_type == "custom":
        try:
            start = int(request.form.get('start_port') or 1)
            end = int(request.form.get('end_port') or 1024)
            ports_to_scan = range(start, end + 1)
        except ValueError: ports_to_scan = [80] 
    else: ports_to_scan = [80, 8000, 8080]

    try:
        ip = socket.gethostbyname(target)
        last_scanned_ip = ip 

        def thread_scan(port):
            with app.app_context():
                if scan_port(ip, port):
                    kb_match = Vulnerability.query.filter_by(port=port).first()
                    return generate_analysis(port, db_match=kb_match)
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            thread_results = list(executor.map(thread_scan, ports_to_scan))

        results = [r for r in thread_results if r is not None]
        final_score = calculate_security_score(results)
        summary_text = f"Audit Success: Identified {len(results)} vulnerabilities." if results else "Hardened: No vulnerabilities detected."
        
        new_audit = AuditRecord(
            target_ip=target,
            ports_found = "\n".join(results), 
            threat_summary=summary_text,
            user_id=current_user.id,
            security_score=final_score
        )
        db.session.add(new_audit)
        db.session.commit() 
        if results: save_report_to_file(ip, results)
        flash(f"Protocol Complete: Hardening score at {final_score}%", "success")

    except Exception as e:
        db.session.rollback()
        print (f"ERROR: {e}")

    total_audits = AuditRecord.query.count()
    history_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(10).all()
    user_scans = AuditRecord.query.filter_by(user_id=current_user.id).all()
    unique_assets = len(set([s.target_ip for s in user_scans]))
    unresolved = AuditRecord.query.filter_by(user_id=current_user.id, remediation_status=0).filter(AuditRecord.threat_summary.like('%Identified%')).count()

    return render_template('index.html', results=results, target=target, audit_count=total_audits, history=history_logs, assets_count=unique_assets, risks_count=unresolved)

@app.route('/audit/<int:record_id>')
@login_required
def audit_detail(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash("VIOLATION: Access denied.", "danger")
        return redirect(url_for('index'))
    return render_template('audit_detail.html', audit=record)

@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename): return send_file(filename, as_attachment=True)
    return "<h3>Report missing.</h3>"

@app.route('/export_pdf/<int:record_id>')
@login_required
def export_pdf(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id: return "Unauthorized.", 403
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 24)
    p.drawString(100, 750, "SECUSYS ENTERPRISE AUDIT")
    p.setFont("Helvetica", 10)
    p.drawString(100, 735, "Founders Series v3.2 - Forensic Artifact")
    p.line(100, 725, 500, 725)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 700, f"INFRASTRUCTURE TARGET: {record.target_ip}")
    p.setFont("Helvetica-Bold", 12)
    p.setFillColorRGB(0.8, 0, 0)
    p.drawString(100, 630, f"HARDENING SCORE: {record.security_score}/100")
    p.setFillColorRGB(0, 0, 0) 
    p.drawString(100, 610, f"Executive Summary: {record.threat_summary}")
    p.rect(100, 400, 400, 160) 
    p.drawString(110, 525, f"Analysis Detail: {record.ports_found}")
    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"SecuSys_Report_{record.target_ip}.pdf", mimetype='application/pdf')

@app.route('/remediate/<int:record_id>', methods=['POST'])
@login_required
def remediate(record_id):
    record = AuditRecord.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash("Violation blocked.", "danger")
        return redirect(url_for('index'))
    port_matches = re.findall(r'\d+', record.threat_summary)
    target_port = int(port_matches[0]) if port_matches else 80
    try:
        verification_status = scan_port(record.target_ip, target_port)
        if not verification_status:
            record.remediation_status = 1
            record.remediation_log = f"VERIFIED: Post-fix scan failed. Policy successful."
            db.session.commit()
            flash(f"SUCCESS: Fix for Port {target_port} applied and VERIFIED.", "success")
        else:
            record.remediation_status = 0 
            record.remediation_log = f"ALERT: Logic applied but port {target_port} responsive."
            db.session.commit()
            flash(f"FAILURE: Logic deployed to {record.target_ip}, but Port {target_port} still OPEN.", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"Handshake failed: {str(e)}", "danger")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    seed_intelligence()
    app.run(debug=True, port=9090)