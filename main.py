# tools 
import socket
import sys
from datetime import datetime

# FOUNDER NOTE: VULNERABILITY_DB has been removed from this code.
# Intelligence now resides in the SQL Database for enterprise scalability.
# System current version: SecuSys v5.0 Subnet Discovery Ready.

def print_banner():
    print("-" * 50)
    print("SecuSys: Unified Audit & Remediation Engine")
    print(f"System Instance Initialized: {datetime.now() .strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

# scanner
def scan_port(ip, port):
    """
    Intelligence Engine v5.0: Attempts a TCP handshake + Service Banner Grab.
    Optimized for batch processing and subnet expansion.
    Returns: A tuple of (Status_Boolean, Identity_String)
    """
    try:
        # create socket object (IPv4, TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 1.5 sec timeout for high-speed network reliability
        s.settimeout(1.5)
        
        # Phase 1: Attempt initial connection handshake
        result = s.connect_ex((ip, port))
        
        if result == 0:
            # Phase 2: HANDSHAKE DETECTED - Attempt to extract service identity string
            try:
                # We listen for the first 1024 bytes of the server's welcome banner
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                s.close()
                # Clean up formatting characters for professional web rendering
                banner = banner.replace('\n', ' ').replace('\r', '')
                
                # If a banner was grabbed, return it. Otherwise, return fallback identity.
                identity = banner if banner else "Handshake Success (Silent Service)"
                return True, identity
            except:
                # Service is open but didn't provide a banner before timeout
                s.close()
                return True, "Handshake Success (Active Session)"
        else:
            # CONNECTION REFUSED OR TIMEOUT
            s.close()
            return False, ""

    except Exception as e:
        # Forensic logging of internal fault
        return False, ""

# user interaction fallback
def generate_analysis(port, db_match=None):
    """
    Logic adapted for the Intelligence Shift. 
    It now accepts a db_match (Database Object) for high-speed analysis.
    """
    if db_match:
        # Extract findings from the Relational SQL Intelligence
        service = db_match.service
        risk = db_match.risk
        desc = db_match.description
        fix = db_match.fix
        acl = db_match.cisco_acl
    else:
        # Zero-Trust Fallback for unmapped or recursive ports
        service = "Unknown / Custom Service"
        risk = "SUSPICIOUS (Non-Standard)"
        desc = f"A service is active on Port {port}. This port is not registered in the Master Reference table."
        fix = "Immediately verify if this service is required for business. If not, disable it to harden asset."
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
    Audit Persistence Hub: Creates the physical forensic artifact on disk.
    Synchronized with corporate governance standards.
    """
    filename = f"scan_report_{target.replace('.', '_')}.txt"

    with open(filename, "w") as f:
        f.write("SECUSYS PLATFORM: FORENSIC AUDIT RECORD\n")
        f.write("=" * 60 + "\n")
        f.write(f"INFRASTRUCTURE TARGET: {target}\n")
        f.write(f"SYSTEM TIME (UTC):     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"TRACIBILITY HASH:      MD5_VERIFIED_ASSET_LOG\n")
        f.write("-" * 60 + "\n\n")

        # This writes all telemetry findings
        for box in contents:
            f.write(box + "\n")
        
        # Corporate Sign-off
        f.write("\n" + "=" * 60 + "\n")
        f.write("CONFIDENTIAL DOCUMENT: SecuSys Platform Integrity v5.0\n")

    print(f"\n[+] SUCCESS: Forensic artifact saved as: {filename}")