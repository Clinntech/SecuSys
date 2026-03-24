# tools 
import socket
import sys
from datetime import datetime

# knowledge base(Database)
VULNERABILITY_DB = {
     20: {
        "service": "FTP-Data",
        "risk": "MEDIUM",
        "desc": "Used for FTP data transfer. Unencrypted.",
        "fix": "Use SFTP or FTPS.",
        "cisco_acl": "access-list 101 deny tcp any any eq 20"
    },

    21: {
        "service" : "FTP",
        "risk" : "HIGH",
        "desc" : "Sends data and passwords in plaintext.",
        "fix" : "Disable and use SFTP(Port 22).",
        "cisco_acl" : "access-list 101 deny tcp any any eq 21"
    },

    22: {
        "service" : "SSH",
        "risk" : "LOW",
        "desc" : "Secure, but can be brute-force if exposed.",
        "fix" : "Use SSH Keys; restrict management IP access.",
        "cisco_acl" : "access-list 101 permit tcp 10.1.1.0 0.0.0.255 any eq 22"
    },

    23: {
        "service" : "Telnet",
        "risk" : "CRITICAL",
        "desc" : "Ancient, unencrypted remote management.",
        "fix" : "IMMEDIATELY switch to SSH",
        "cisco_acl" : "access-list 101 deny tcp any any eq 23"
    },

    25: {
        "service": "SMTP",
        "risk": "MEDIUM",
        "desc": "Simple Mail Transfer. Vulnerable to spoofing and relaying attacks.",
        "fix": "Enforce TLS and authenticate mail relay.",
        "cisco_acl": "access-list 101 permit tcp any any eq 25"
    },

    53: {
        "service": "DNS",
        "risk": "MEDIUM",
        "desc": "Domain Name System. Targets for cache poisoning or amplification DOS.",
        "fix": "Use DNSSEC and limit zone transfers.",
        "cisco_acl": "access-list 101 permit udp any any eq 53"
    },

    67: {
        "service": "DHCP Server",
        "risk": "MEDIUM",
        "desc": "Used to assign IPs. Target for DHCP Starvation attacks.",
        "fix": "Enable 'DHCP Snooping' on Cisco switches.",
        "cisco_acl": "access-list 101 permit udp any any eq 67"
    },

    80: {
        "service" : "HTTP",
        "risk" : "CRITICAL",
        "desc" : "Used to request and load websites from servers.",
        "fix" : "Redirect all incoming HTTP to port 443(HTTPS).",
        "cisco_acl" : "access-list 101 permit tcp [TRUSTED_IP]any any eq 80"
    },

    443: {
        "service": "HTTPS",
        "risk": "INFO",
        "desc": "Encrypted web traffic. Generally secure.",
        "fix": "Monitor certificates and ensure modern TLS versions.",
        "cisco_acl": "access-list 101 permit tcp any any eq 443"
    },
    # --- Remote & Messaging ---
    110: {
        "service": "POP3",
        "risk": "HIGH",
        "desc": "Post Office Protocol. Downloads email without encryption.",
        "fix": "Use Secure POP3 (995) or IMAP with TLS.",
        "cisco_acl": "access-list 101 deny tcp any any eq 110"
    },
    123: {
        "service": "NTP",
        "risk": "LOW",
        "desc": "Network Time Protocol. Used in large scale DDOS attacks.",
        "fix": "Configure NTP authentication and restrict synchronization sources.",
        "cisco_acl": "access-list 101 permit udp any any eq 123"
    },
    143: {
        "service": "IMAP",
        "risk": "MEDIUM",
        "desc": "Email sync. Unencrypted versions are vulnerable.",
        "fix": "Switch to Secure IMAP (993).",
        "cisco_acl": "access-list 101 deny tcp any any eq 143"
    },
    161: {
        "service": "SNMP",
        "risk": "HIGH",
        "desc": "Network monitoring. Default passwords (public/private) often allow hacking of routers.",
        "fix": "Use SNMPv3 for encryption. Change default community strings.",
        "cisco_acl": "access-list 101 deny udp any any eq 161"
    },
    # --- Microsoft & Modern Common Ports ---
    445: {
        "service": "SMB/AD",
        "risk": "CRITICAL",
        "desc": "Microsoft Directory Services. Primary entry for Ransomware (EternalBlue).",
        "fix": "Block Port 445 at the router perimeter. Enforce SMBv3.",
        "cisco_acl": "access-list 101 deny tcp any any eq 445"
    },
    514: {
        "service": "Syslog",
        "risk": "LOW",
        "desc": "Device logs. Can be spoofed to hide attacker tracks.",
        "fix": "Use a secure logging server (SIEM) with encryption.",
        "cisco_acl": "access-list 101 permit udp any any eq 514"
    },
    993: {
        "service": "IMAP Secure",
        "risk": "INFO",
        "desc": "Encrypted email retrieval.",
        "fix": "Preferred over Port 143.",
        "cisco_acl": "access-list 101 permit tcp any any eq 993"
    },
    3306: {
        "service": "MySQL",
        "risk": "HIGH",
        "desc": "Database access. Vulnerable to data theft and SQL injection.",
        "fix": "Allow access only from the Web Server's IP address.",
        "cisco_acl": "access-list 101 permit tcp [DB_IP] [SERVER_IP] eq 3306"
    },
    3389: {
        "service": "RDP",
        "risk": "CRITICAL",
        "desc": "Remote Desktop. Frequent victim of brute-force and credential stuffing.",
        "fix": "Place RDP behind a VPN. Never expose directly to internet.",
        "cisco_acl": "access-list 101 deny tcp any any eq 3389"
    },
    8080: {
        "service": "HTTP Proxy/Dev",
        "risk": "MEDIUM",
        "desc": "Often used for dev environments or hidden backdoors.",
        "fix": "Investigate why this is open; close if not a managed application server.",
        "cisco_acl": "access-list 101 deny tcp any any eq 8080"
    }

}

def print_banner():
    print("-" * 50)
    print("SecuSys: Scan and Fix")
    print(f"Starting Scan at: {datetime.now() .strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

#scanner
def scan_port(ip,port):
    """
    Core Engine: Attempts a TCP handshake.
    Returns True if open, False if closed.
    Use (ip,port) as a single tuple
    """
    try:
        #create socket object(IPv4, TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #1 sec timout
        s.settimeout(1.5)
        
        #if connection is successful connect_ex=0
        result = s.connect_ex((ip,port))
        
        s.close() #to close connection always
        return result == 0
    except Exception as e:
        print(f"Internal error on port {port}: {e}")
        return False
    
    # user interaction

def generate_analysis(port):
    """
    Look up the found port in Our DB. If NOT found, provide a 'Zero-Trust' generic remediation. 
    """
    # 1. Check if port exists on our database
    if port in VULNERABILITY_DB:
        data = VULNERABILITY_DB[port] # Grabs the mini-dictionary for that port

        # 2. Extract info safely using .get(key, default_value)
        
        service = data.get("service", "Unknown Service")
        risk = data.get("risk", "INFO")
        desc = data.get("desc", "No description available.")
        fix = data.get("fix", "No fix recommeded")
        acl = data.get("cisco_acl", "N/A")
    
    else:
        #3. Smartfall back
        # This handles all ports NOT in the dictionary.
        service = "Unknown / Custom Service"
        risk = "SUSPICIOUS (Non-Standard)"
        desc = f"A service is active on Port {port}. This port is not a standard 'Well-Know port."
        fix = "Immediately verify if this service is required for business. If not, disable it to reduce the attack surface."
        acl = f"access-list 101 deny tcp any any eq {port}"

        #4. Format the result using a multi-line f-string

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
   

def main():
    print_banner()

    #1. get and validate user input
    raw_target = input("Enter IP address or hostname you want to scan(e.g 127.0.0.1 or scanme.nmap.org):").strip()

    try: 
        #hostname to ip
        target_ip = socket.gethostbyname(raw_target)
        print(f"[i] Target Resolved: {raw_target} -> {target_ip}")
    except socket.gaierror:
        print(f"[!] Error: Could not resolve '{raw_target}' . Check your internet/DNS.")
        return
    #2. Select Range (Dynamic Selection)
    print("\nSelect Port Range:")
    print("1. Well-Known Ports(1-2024)")
    print("2. Common Web Ports(80,443,8000,8080)")
    print("3. Custom Range")

    choice =input("Choice(1,2, or 3):")

    ports_to_scan = []
    if choice == "1":
        ports_to_scan = range(1,1025)
    elif choice == "2":
        ports_to_scan = [80, 443, 8000, 8080, 8443]
    elif choice == "3":
        start = int(input("Enter Start Port: "))
        end = int(input("Enter End Port: "))
        ports_to_scan = range(start, end + 1)
    else:
        print("[!] Invalid choice. Defaulting to ports 1-100.")
        ports_to_scan = range(1,101)

    report_storage = []

    print(f"\n[i] Scanning {target_ip}...")

    #3. Execution
    print(f"\n[i] Scanning {target_ip}...")
    print("[i] Press Ctrl+C to cancel.")



    open_ports = [] #list to keep track of what we find

    try:
        for port in ports_to_scan:
            #don't print "closed" for every port to keep UI clean
            if scan_port(target_ip,port):

                analysis_report = generate_analysis(port)
                print(analysis_report)

                print(f"[!] SUCCESS: Port {port} is OPEN")
                open_ports.append(port)
                report_storage.append(analysis_report)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit()

    print("\n--- Scan Complete ---")
    if report_storage:
        print(f"DEBUG: I am now calling the save function with {len(report_storage)} items.")
        save_report_to_file(target_ip, report_storage)
    else:
        print("[-] No vulnerabilities found to report. That is why no file was made.")

    #4. Summary
    print("\n" + "-" * 50)
    print(f"SCAN REPORT.")
    print(f"Target: {target_ip}")
    print(f"Status: Scan complete")
    print(f"Open Ports Found: {len(open_ports)}")
    if open_ports:
        print(f"List: {open_ports}")
    else: 
        print("Result: No open ports found in this range.")
    print("-" *50)

if __name__ == "__main__":    
    main()           
