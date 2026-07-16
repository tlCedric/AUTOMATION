import xml.etree.ElementTree as ET
import os
import sys
from datetime import datetime

# Comprehensive mapping of ports to types and recommended security tools
PORT_TOOL_MAP = {
    21: {
        "type": "FTP (File Transfer)",
        "tools": ["hydra (Brute-force)", "nmap --script ftp-anon", "ftp"]
    },
    22: {
        "type": "SSH (Secure Shell)",
        "tools": ["hydra (Brute-force)", "ssh-audit", "nmap --script ssh-auth-methods"]
    },
    23: {
        "type": "Telnet",
        "tools": ["hydra (Brute-force)", "nmap --script telnet-brute"]
    },
    25: {
        "type": "SMTP (Mail)",
        "tools": ["smtp-user-enum", "swaks", "nmap --script smtp-enum-users"]
    },
    53: {
        "type": "DNS (Domain Name System)",
        "tools": ["dig axfr", "dnsrecon", "fierce", "gobuster dns"]
    },
    80: {
        "type": "HTTP (Web Server)",
        "tools": ["gobuster dir", "nikto", "feroxbuster", "nmap --script http-vuln-*", "whatweb"]
    },
    88: {
        "type": "Kerberos (Active Directory)",
        "tools": ["kerbrute userenum", "impacket-GetNPUsers", "rubeus"]
    },
    110: {
        "type": "POP3 (Mail)",
        "tools": ["hydra", "nmap --script pop3-capabilities"]
    },
    135: {
        "type": "RPC (Remote Procedure Call)",
        "tools": ["rpcclient", "impacket-rpcdump"]
    },
    139: {
        "type": "NetBIOS (Samba)",
        "tools": ["enum4linux", "nbtscan", "smbclient"]
    },
    389: {
        "type": "LDAP (Lightweight Directory Access Protocol)",
        "tools": ["ldapsearch", "ldapdomaindump", "nmap --script ldap-search"]
    },
    443: {
        "type": "HTTPS (Secure Web Server)",
        "tools": ["gobuster dir", "nikto", "sslscan", "testssl.sh", "feroxbuster"]
    },
    445: {
        "type": "SMB (Server Message Block)",
        "tools": ["smbclient", "smbmap", "enum4linux-ng", "crackmapexec smb", "nmap --script smb-vuln-*"]
    },
    593: {
        "type": "RPC over HTTP",
        "tools": ["rpcclient", "impacket-rpcdump"]
    },
    636: {
        "type": "LDAPS (Secure LDAP)",
        "tools": ["ldapsearch", "ldapdomaindump"]
    },
    1433: {
        "type": "MSSQL (Microsoft SQL Server)",
        "tools": ["crackmapexec mssql", "impacket-mssqlclient", "sqsh", "nmap --script mssql-ntlm-info"]
    },
    2049: {
        "type": "NFS (Network File System)",
        "tools": ["showmount -e", "nmap --script nfs-showmount"]
    },
    3306: {
        "type": "MySQL Database",
        "tools": ["mysql", "hydra", "nmap --script mysql-audit", "crackmapexec mysql"]
    },
    3389: {
        "type": "RDP (Remote Desktop)",
        "tools": ["xfreerdp", "crowbar", "nmap --script rdp-vuln-ms12-020"]
    },
    5985: {
        "type": "WinRM (HTTP Admin)",
        "tools": ["evil-winrm", "crackmapexec winrm"]
    },
    5986: {
        "type": "WinRM (HTTPS Admin)",
        "tools": ["evil-winrm", "crackmapexec winrm"]
    },
    8080: {
        "type": "HTTP Alternate (Web Proxy/Server)",
        "tools": ["gobuster dir", "nikto", "feroxbuster", "nmap --script http-vuln-*"]
    }
}

DEFAULT_SUGGESTION = {
    "type": "Unknown / Uncommon Service",
    "tools": ["nmap -sC -sV (Script Scan)", "nc (Netcat banner grab)", "searchsploit"]
}

def parse_nmap_xml(xml_file):
    """Parses Nmap XML file and extracts host, port, service, and tool data."""
    if not os.path.exists(xml_file):
        print(f"[-] Error: File '{xml_file}' not found.")
        sys.exit(1)
        
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print("[-] Error: Failed to parse XML. Make sure it is a valid Nmap XML file (-oX).")
        sys.exit(1)

    scan_results = {}

    for host in root.findall('host'):
        # Get IP Address
        ip_element = host.find("./address[@addrtype='ipv4']")
        if ip_element is None:
            continue
        ip_address = ip_element.get('addr')
        
        # Get Hostname if available
        hostname_element = host.find("./hostnames/hostname")
        hostname = hostname_element.get('name') if hostname_element is not None else "Unknown Hostname"
        
        scan_results[ip_address] = {
            "hostname": hostname,
            "ports": []
        }
        
        # Parse Ports
        ports = host.findall("./ports/port")
        for port in ports:
            state = port.find('state').get('state')
            if state != 'open':
                continue
                
            port_id = int(port.get('portid'))
            protocol = port.get('protocol')
            
            service_element = port.find('service')
            service_name = service_element.get('name') if service_element is not None else "unknown"
            product = service_element.get('product') if service_element is not None else ""
            version = service_element.get('version') if service_element is not None else ""
            
            version_str = f"{product} {version}".strip() or "No version detected"
            
            # Lookup port configurations
            port_info = PORT_TOOL_MAP.get(port_id, DEFAULT_SUGGESTION)
            
            scan_results[ip_address]["ports"].append({
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "version": version_str,
                "port_type": port_info["type"],
                "tools": port_info["tools"]
            })
            
    return scan_results

def generate_report(results, output_file="nmap_security_report.md"):
    """Generates a structured markdown report from the parsed results."""
    with open(output_file, "w") as f:
        f.write("# Automated Nmap Tool Recommendation Report\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        if not results:
            f.write("### No active hosts or open ports found in the scan file.\n")
            return

        for ip, info in results.items():
            f.write(f"## 🖥️ Target Host: {ip} ({info['hostname']})\n")
            
            if not info["ports"]:
                f.write("*No open ports found on this host.*\n\n")
                continue
                
            f.write("| Port / Protocol | Service Name | Service Type | Detected Version | Recommended Tools |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            
            for p in info["ports"]:
                tools_str = ", ".join([f"`{t}`" for t in p['tools']])
                f.write(f"| **{p['port']}/{p['protocol']}** | {p['service']} | *{p['port_type']}* | {p['version']} | {tools_str} |\n")
            
            f.write("\n### 🚀 Targeted Action Plan\n")
            f.write("Based on the discovered services, prioritize the following commands:\n")
            
            for p in info["ports"]:
                f.write(f"- **Port {p['port']} ({p['service']}):**\n")
                for tool in p['tools']:
                    f.write(f"  - Tool Suggestion: Run analysis using `{tool}`\n")
            f.write("\n---\n\n")
            
    print(f"[+] Detailed report successfully saved to: {os.path.abspath(output_file)}")

def display_summary(results):
    """Prints a quick scannable summary to the terminal terminal."""
    print("\n" + "="*70)
    print(" SCAN SUMMARY & SUGGESTED ATTACK VECTORS")
    print("="*70)
    for ip, info in results.items():
        print(f"\n[IP]: {ip} ({info['hostname']})")
        print("-" * 50)
        for p in info["ports"]:
            print(f"  -> Open Port: {p['port']}/{p['protocol']} | Type: {p['port_type']}")
            print(f"     Suggested Tools: {', '.join(p['tools'])}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_analyzer.py <path_to_nmap_xml_file>")
        print("Example: python nmap_analyzer.py scan.xml")
        sys.exit(1)
        
    xml_input = sys.argv[1]
    parsed_data = parse_nmap_xml(xml_input)
    display_summary(parsed_data)
    generate_report(parsed_data)
