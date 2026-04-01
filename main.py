# tools 
import socket
import sys
from datetime import datetime

# FOUNDER NOTE: VULNERABILITY_DB has been removed from this code.
# Intelligence now resides in the SQL Database for enterprise scalability.

def print_banner():
    print("-" * 50)
    print("SecuSys: Scan and Fix")
    print(f"Starting Scan at: {datetime.now() .strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

# scanner
def scan_port(ip, port):
    """
    Core Engine: Attempts a TCP handshake.
    Returns True if open, False if closed.
    Use (ip, port) as a single tuple
    """
    try:
        # create socket object (IPv4, TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 1.5 sec timeout for network reliability
        s.settimeout(1.5)
        
        # if connection is successful connect_ex=0
        result = s.connect_ex((ip, port))
        
        s.close() # Always close the connection
        return result == 0
    except Exception as e:
        print(f"Internal error on port {port}: {e}")
        return False

# user interaction fallback
def generate_analysis(port, db_match=None):
    """
    Logic adapted for the Intelligence Shift. 
    It now accepts a db_match (Database Object) for high-speed analysis.
    """
    if db_match:
        # If the Database found a match (Handled in app.py)
        service = db_match.service
        risk = db_match.risk
        desc = db_match.description
        fix = db_match.fix
        acl = db_match.cisco_acl
    else:
        # Zero-Trust Fallback for unmapped ports
        service = "Unknown / Custom Service"
        risk = "SUSPICIOUS (Non-Standard)"
        desc = f"A service is active on Port {port}. This port is not a standard Well-Known port."
        fix = "Immediately verify if this service is required for business. If not, disable it."
        acl = f"access-list 101 deny tcp any any eq {port}"

    # Format the result using the professional SaaS dashboard template
    report = f"\n" + "[+] SCAN SUMMARY"
    report += f"\n[!] SECURITY ANALYSIS: Port {port} ({service})"
    report += f"\n" + "-" * 50
    report += f"\n    RISK LEVEL:  {risk}"
    report += f"\n    THREAT:      {desc}"
    report += f"\n    FIX:         {fix}"
    report += f"\n    CISCO CONFIG: {acl}"

    return report

def save_report_to_file(target, contents):
    """
    Handles creating the .txt file on hard drive.
    """
    filename = f"scan_report_{target.replace('.', '_')}.txt"

    with open(filename, "w") as f:
        f.write("Secusys: Security Audit Report\n")
        f.write("_" * 50 + "\n")
        f.write(f"TARGET: {target}\n")
        f.write(f"DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n\n")

        # This writes all the boxes we saved in our list
        for box in contents:
            f.write(box + "\n")

    print(f"\n[+] SUCCESS: Audit report saved as: {filename}")

# Note: The CLI 'main()' can still function by calling local DB queries if needed.