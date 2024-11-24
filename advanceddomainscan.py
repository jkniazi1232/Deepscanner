import socket
import subprocess

# -----------------------------
# 1. Reconnaissance
# -----------------------------

def domain_lookup(domain):
    """Resolve the domain to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"[INFO] Domain '{domain}' resolves to IP: {ip}")
        return ip
    except socket.gaierror as e:
        print(f"[ERROR] Domain lookup failed for '{domain}': {e}")
        return None

def whois_lookup(domain):
    """Perform a WHOIS lookup for the domain."""
    print("\n[INFO] Performing WHOIS Lookup...")
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"[ERROR] WHOIS command failed: {result.stderr}")
    except Exception as e:
        print(f"[ERROR] WHOIS lookup failed: {e}")

def mx_lookup(domain):
    """Retrieve MX records for the domain."""
    print("\n[INFO] Retrieving MX Records...")
    try:
        result = subprocess.run(['nslookup', '-type=MX', domain], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"[ERROR] MX lookup failed: {result.stderr}")
    except Exception as e:
        print(f"[ERROR] MX lookup failed: {e}")

def dns_lookup(domain):
    """Retrieve other DNS records for the domain."""
    print("\n[INFO] Retrieving DNS Records...")
    try:
        result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"[ERROR] DNS lookup failed: {result.stderr}")
    except Exception as e:
        print(f"[ERROR] DNS lookup failed: {e}")

# -----------------------------
# 2. Scanning
# -----------------------------

def port_scan(target_ip, ports=[21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 8080, 3306, 3389]):
    """Scan for open ports on the target IP."""
    open_ports = []
    print("\n[INFO] Starting port scan...")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    print(f"[OPEN] Port {port} is open")
                    open_ports.append(port)
                else:
                    print(f"[CLOSED] Port {port} is closed")
        except Exception as e:
            print(f"[ERROR] Scanning port {port}: {e}")
    return open_ports

# -----------------------------
# 3. Detailed Vulnerability Assessment
# -----------------------------

def vulnerability_check(port):
    """Check for detailed vulnerabilities based on the port."""
    print(f"\n[INFO] Checking vulnerabilities for port {port}...")
    
    # Detailed vulnerability checks for common services
    vulnerabilities = {
        21: """FTP (Port 21):
        - Anonymous login may be allowed.
        - FTP traffic is not encrypted, making it susceptible to MITM attacks.
        - Recommendation: Use SFTP or disable FTP if not needed.""",
        
        22: """SSH (Port 22):
        - Weak passwords or outdated SSH protocols may be used.
        - Brute force attacks are common.
        - Recommendation: Use strong credentials and key-based authentication.""",
        
        23: """Telnet (Port 23):
        - Telnet transmits data in plaintext, exposing credentials.
        - Recommendation: Replace Telnet with SSH.""",
        
        25: """SMTP (Port 25):
        - Open relays may be exploited for spam.
        - Recommendation: Configure SMTP to require authentication.""",
        
        53: """DNS (Port 53):
        - Open DNS resolvers can be abused for DNS amplification attacks.
        - Recommendation: Limit recursion to trusted clients.""",
        
        80: """HTTP (Port 80):
        - Unencrypted traffic is vulnerable to eavesdropping.
        - Recommendation: Use HTTPS.""",
        
        443: """HTTPS (Port 443):
        - Check for outdated or weak SSL/TLS protocols.
        - Recommendation: Enforce strong ciphers and use certificates from trusted CAs.""",
        
        445: """SMB (Port 445):
        - SMB vulnerabilities (e.g., EternalBlue) may exist.
        - Recommendation: Disable SMBv1 and keep SMB patches up-to-date.""",
        
        3306: """MySQL (Port 3306):
        - Open MySQL port can expose the database to unauthorized access.
        - Recommendation: Restrict MySQL to localhost and use strong credentials.""",
        
        3389: """RDP (Port 3389):
        - RDP is a frequent target for brute force and ransomware attacks.
        - Recommendation: Use a VPN or firewall to restrict access."""
    }
    
    # Check if the port is in the known vulnerabilities
    if port in vulnerabilities:
        print(f"[WARNING] {vulnerabilities[port]}")
    else:
        print(f"[INFO] No known vulnerabilities for port {port} in this detailed check.")

# -----------------------------
# Main Execution Flow
# -----------------------------

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")

    # Step 1: Reconnaissance
    target_ip = domain_lookup(target_domain)
    if target_ip:
        whois_lookup(target_domain)
        mx_lookup(target_domain)
        dns_lookup(target_domain)

        # Step 2: Scanning
        open_ports = port_scan(target_ip)

        # Step 3: Vulnerability Assessment
        if open_ports:
            for port in open_ports:
                vulnerability_check(port)
        else:
            print("[INFO] No open ports detected. Skipping vulnerability assessment.")
    else:
        print("[ERROR] Unable to resolve domain. Exiting...")
