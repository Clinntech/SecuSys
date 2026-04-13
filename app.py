from concurrent.futures import ThreadPoolExecutor #multithreading
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
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
app.config['SECRET_KEY'] = 'dev-startup-key-123' # Necessary for Flask sessions

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' #Tells flask where the login page is. 

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
        # This converts "mypassword123" into "$2b$12$K12u8e888..."
        hashed_password = bcrypt.generate_password_hash(pass_word).decode('utf-8')

        # Add to Database
        new_user = User(username=user_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        print(f"[IDENTITY] New account created: {user_name}")
        return redirect(url_for('login')) # Redirects to login page (which we build tomorrow)

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

@app.route('/scan', methods=['POST'])
@login_required #Prevents unauthorized API/Form submissions
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
            threat_summary=summary_text,
            # MILESTONE FIX: Permanently bind this scan to the specific current_user.id
            user_id=current_user.id 
        )
        db.session.add(new_audit)
        db.session.commit() # Writing the audit to secusys.db history

        if results:
            save_report_to_file(ip, results)

    except Exception as e:
        db.session.rollback()
        print (f"[DATABASE ERROR] Handshake failed: {e}")


    # 5. RE-REFRESH Dashboard Logic: Re-fetch variables specifically for the CURRENT USER before the page reloads
    total_audits = AuditRecord.query.count()
    # MILESTONE FIX: Refresh history ONLY for current user so the isolation stays true
    history_logs = AuditRecord.query.filter_by(user_id=current_user.id).order_by(AuditRecord.scan_date.desc()).limit(5).all()

    # Pass the fresh audit_count and isolated history to ensure UI matches the DB
    return render_template('index.html', results=results, target=target, audit_count=total_audits, history=history_logs)

#The Download Route
@app.route('/download')
@login_required
def download():
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)
    else:
        return "<h3>No report found. Please run a scan first!</h3>"

if __name__ == '__main__':
    # Initialize DB file if it doesn't exist
    with app.app_context():
        db.create_all()
    
    # NEW: Automatically fill the intelligence tables
    seed_intelligence()
    
    # Start the SaaS Web Platform
    app.run(debug=True, port=8080)