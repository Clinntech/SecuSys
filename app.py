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

    def __rerp__(self):
        return f'<Audit {self.target_ip} on {self.scan_date}>'
    


#remember last scanned IP for download button
last_scanned_ip = ""


@app.route('/')
def index():
    #Shows starting page
    #Fetch the total number of audits from the database
    total_audits = AuditRecord.query.count()
    return render_template('index.html', audit_count = total_audits)

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
            start_str = request.form.get('start_port')
            end_str = request.form.get('end_port')
            
            start = int(start_str) if start_str else 1
            end = int(end_str) if end_str else 1024
            ports_to_scan = range(start, end + 1)
        except ValueError:
            ports_to_scan = [80] # Safe fallback if they type letters instead of numbers

    else: #Default/Test
        ports_to_scan = [80, 8000, 8080]

    try:
        ip = socket.gethostbyname(target)
        last_scanned_ip = ip # Save this globally for the download route

        for port in ports_to_scan:
            #Calls main.py scan_port function
            if scan_port(ip, port): 
                # Calls main.py logic to create the box
                analysis = generate_analysis(port)
                # Adds the box to the results list
                results.append(analysis)
         #Save to Hard Drive, Creates the .txt file in the background
        if results:
            save_report_to_file(ip, results)
    except socket.gaierror:
        return "<h3>Error: Invalid IP or Hostname. Click 'Back' to try again.</h3>"
    
    found_ports_string = ", ".join(map(str, [p for p in results if "SUCCESS" in p]))
    #grab port numbers from the strings

    #we calculate a basic risk score. 
    total_open = len(results)
    final_threat = f"Total Open Ports: {total_open}. Audit status complete."

    #create the actual database record using Auditrecord model
    new_audit = AuditRecord(
        target_ip = target,
        ports_found = str(results), #save analysis as a list text
        threat_summary = final_threat
    )

    #Handshake: save it to file permanently
    try:
        db.session.add(new_audit) #stage data
        db.session.commit() #writes the data to secusys.db
        print(f"[DATABASE] Successfully saved scan for {target}")

    except Exception as e:
        db.session.rollback() #cancels the save if there's an error
        print (f"[DATABASE ERROR] Could not save audit: {e}")    


    return render_template('index.html', results=results, target=target)

#The Download Route
@app.route('/download')
def download():
    global last_scanned_ip
    
    # Calculate what the filename should be
    filename = f"scan_report_{last_scanned_ip.replace('.', '_')}.txt"
    
    # Check if the file actually exists before trying to send it
    if os.path.exists(filename):
        # send_file triggers the browser to download the file to the user's PC
        return send_file(filename, as_attachment=True)
    else:
        return "<h3>No report found. Please run a scan first!</h3>"

if __name__ == '__main__':
    app.run(debug=True, port=8080)
