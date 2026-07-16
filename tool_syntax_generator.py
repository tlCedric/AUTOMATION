#!/usr/bin/env python3
"""
Tool Syntax Reference Generator
Generates structured security tool reference documentation in parallel with Nmap analyzer.
Parses tool syntax reference and creates organized report files.
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Tuple
import threading
from pathlib import Path


# Tool categories and syntax data
TOOL_REFERENCE = {
    "FTP (Port 21)": {
        "description": "File Transfer Protocol",
        "tools": {
            "Hydra": {
                "purpose": "Brute Force Attack",
                "commands": [
                    "hydra -l username -P /path/to/wordlist.txt ftp://target_ip",
                    "hydra -L userlist.txt -P passlist.txt ftp://target_ip -t 4"
                ]
            },
            "Nmap": {
                "purpose": "FTP Enumeration",
                "commands": [
                    "nmap --script ftp-anon target_ip",
                    "nmap --script ftp-* target_ip"
                ]
            },
            "FTP Client": {
                "purpose": "Direct Connection",
                "commands": [
                    "ftp target_ip",
                    "ftp> ls",
                    "ftp> get filename"
                ]
            }
        }
    },
    "SSH (Port 22)": {
        "description": "Secure Shell",
        "tools": {
            "Hydra": {
                "purpose": "SSH Brute Force",
                "commands": [
                    "hydra -l admin -P /path/to/wordlist.txt ssh://target_ip",
                    "hydra -L userlist.txt -P passlist.txt ssh://target_ip -t 4"
                ]
            },
            "SSH-Audit": {
                "purpose": "SSH Configuration Analysis",
                "commands": [
                    "ssh-audit target_ip",
                    "ssh-audit -p 2222 target_ip",
                    "ssh-audit --json target_ip"
                ]
            },
            "Nmap": {
                "purpose": "SSH Enumeration",
                "commands": [
                    "nmap --script ssh-auth-methods target_ip",
                    "nmap --script ssh-hostkey target_ip",
                    "nmap --script ssh2-enum-algos target_ip"
                ]
            }
        }
    },
    "DNS (Port 53)": {
        "description": "Domain Name System",
        "tools": {
            "Dig": {
                "purpose": "DNS Zone Transfer",
                "commands": [
                    "dig axfr @target_ip domain.com",
                    "dig @target_ip ns domain.com",
                    "dig @target_ip any domain.com"
                ]
            },
            "DNSRecon": {
                "purpose": "DNS Reconnaissance",
                "commands": [
                    "dnsrecon -d domain.com -n target_ip",
                    "dnsrecon -d domain.com -t axfr",
                    "dnsrecon -d domain.com -t brute"
                ]
            },
            "Fierce": {
                "purpose": "DNS Subdomain Enumeration",
                "commands": [
                    "fierce --domain domain.com --dns-servers target_ip",
                    "fierce --domain domain.com --dnsserver target_ip --wordlist wordlist.txt"
                ]
            }
        }
    },
    "HTTP (Port 80)": {
        "description": "Web Server",
        "tools": {
            "Gobuster": {
                "purpose": "Directory/Content Enumeration",
                "commands": [
                    "gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt",
                    "gobuster dir -u http://target_ip -w wordlist.txt -x .php,.html",
                    "gobuster dir -u http://target_ip -w wordlist.txt -t 50"
                ]
            },
            "Nikto": {
                "purpose": "Web Server Vulnerability Scanner",
                "commands": [
                    "nikto -h http://target_ip",
                    "nikto -h target_ip -p 80",
                    "nikto -h http://target_ip -Tuning 1 -o report.html"
                ]
            },
            "Feroxbuster": {
                "purpose": "Web Content Discovery",
                "commands": [
                    "feroxbuster -u http://target_ip -w wordlist.txt",
                    "feroxbuster -u http://target_ip -w wordlist.txt -x php,html,txt"
                ]
            }
        }
    },
    "HTTPS (Port 443)": {
        "description": "Secure Web Server",
        "tools": {
            "SSLScan": {
                "purpose": "SSL/TLS Configuration Analysis",
                "commands": [
                    "sslscan target_ip:443",
                    "sslscan --no-failed target_ip"
                ]
            },
            "TestSSL.sh": {
                "purpose": "Comprehensive SSL Testing",
                "commands": [
                    "./testssl.sh target_ip",
                    "./testssl.sh -e all target_ip",
                    "./testssl.sh --json target_ip"
                ]
            }
        }
    },
    "SMB (Port 445)": {
        "description": "Server Message Block",
        "tools": {
            "SMBClient": {
                "purpose": "SMB Share Access",
                "commands": [
                    "smbclient -L //target_ip -U username%password",
                    "smbclient //target_ip/share -U username%password"
                ]
            },
            "SMBMap": {
                "purpose": "SMB Share Enumeration",
                "commands": [
                    "smbmap -H target_ip",
                    "smbmap -H target_ip -u username -p password -d domain"
                ]
            },
            "CrackMapExec": {
                "purpose": "SMB Testing and Exploitation",
                "commands": [
                    "crackmapexec smb target_ip",
                    "crackmapexec smb target_ip -u username -p password"
                ]
            }
        }
    },
    "LDAP (Port 389)": {
        "description": "Lightweight Directory Access Protocol",
        "tools": {
            "LDAPSearch": {
                "purpose": "LDAP Directory Search",
                "commands": [
                    "ldapsearch -h target_ip -x -s base namingcontexts",
                    "ldapsearch -h target_ip -x -b \"dc=domain,dc=com\" \"(objectClass=*)\""
                ]
            },
            "LDAPDomainDump": {
                "purpose": "Domain Information Extraction",
                "commands": [
                    "ldapdomaindump -u domain\\\\username -p password ldap://target_ip",
                    "ldapdomaindump --no-kerberos ldap://target_ip"
                ]
            }
        }
    },
    "MySQL (Port 3306)": {
        "description": "MySQL Database Server",
        "tools": {
            "MySQL Client": {
                "purpose": "Direct Database Connection",
                "commands": [
                    "mysql -h target_ip -u username -p password",
                    "mysql -h target_ip -u root -e \"SELECT version();\""
                ]
            },
            "Hydra": {
                "purpose": "MySQL Brute Force",
                "commands": [
                    "hydra -l root -P /path/to/wordlist.txt mysql://target_ip"
                ]
            }
        }
    },
    "MSSQL (Port 1433)": {
        "description": "Microsoft SQL Server",
        "tools": {
            "CrackMapExec": {
                "purpose": "MSSQL Testing",
                "commands": [
                    "crackmapexec mssql target_ip -u username -p password"
                ]
            },
            "Impacket": {
                "purpose": "MSSQL Client",
                "commands": [
                    "impacket-mssqlclient username:password@target_ip",
                    "impacket-mssqlclient -windows-auth domain/username:password@target_ip"
                ]
            }
        }
    },
    "RDP (Port 3389)": {
        "description": "Remote Desktop Protocol",
        "tools": {
            "xfreerdp": {
                "purpose": "RDP Client",
                "commands": [
                    "xfreerdp /v:target_ip /u:username /p:password",
                    "xfreerdp /v:target_ip /u:domain\\\\username /p:password"
                ]
            },
            "Crowbar": {
                "purpose": "RDP Brute Force",
                "commands": [
                    "crowbar -b rdp -s target_ip/32 -u username -C passlist.txt"
                ]
            }
        }
    }
}

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/wfuzz/common.txt",
    "SecLists: /Discovery/Web-Content/common.txt",
    "SecLists: /Discovery/DNS/subdomains-top1million-5000.txt"
]

BEST_PRACTICES = [
    "Always obtain proper authorization before testing",
    "Use -t flag to control thread count for performance",
    "Add delays between requests using -w flag in hydra",
    "Save all results to file with -o flag for documentation",
    "Test with common default credentials first (admin/admin, root/password)",
    "Respect target resources and avoid DoS attacks",
    "Document all findings with timestamps and methodology",
    "Keep tools and wordlists updated regularly"
]


def generate_markdown_report(output_file: str = "tool_syntax_reference_report.md") -> str:
    """
    Generate a comprehensive markdown report from tool reference data.
    
    Args:
        output_file: Path to save the markdown report
        
    Returns:
        Path to generated report file
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("# Security Tools Syntax Reference Report\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        # Table of Contents
        f.write("## Table of Contents\n")
        for port_service in TOOL_REFERENCE.keys():
            anchor = port_service.lower().replace(" ", "-").replace("(", "").replace(")", "")
            f.write(f"- [{port_service}](#{anchor})\n")
        f.write("- [Common Wordlists](#wordlists)\n")
        f.write("- [Best Practices](#best-practices)\n\n")
        
        # Tool Sections
        for port_service, service_data in TOOL_REFERENCE.items():
            anchor = port_service.lower().replace(" ", "-").replace("(", "").replace(")", "")
            f.write(f"## {port_service}\n\n")
            f.write(f"**Description:** {service_data['description']}\n\n")
            
            for tool_name, tool_data in service_data['tools'].items():
                f.write(f"### {tool_name}\n")
                f.write(f"**Purpose:** {tool_data['purpose']}\n\n")
                f.write("**Commands:**\n```bash\n")
                for cmd in tool_data['commands']:
                    f.write(f"{cmd}\n")
                f.write("```\n\n")
        
        # Wordlists Section
        f.write("## Common Wordlists\n\n")
        f.write("### Kali Linux Default Locations\n```\n")
        for wordlist in WORDLISTS[:4]:
            f.write(f"{wordlist}\n")
        f.write("```\n\n")
        f.write("### SecLists Repository\n```bash\n")
        f.write("git clone https://github.com/danielmiessler/SecLists.git\n")
        f.write("```\n")
        for wordlist in WORDLISTS[4:]:
            f.write(f"- {wordlist}\n")
        f.write("\n")
        
        # Best Practices
        f.write("## Best Practices\n\n")
        for i, practice in enumerate(BEST_PRACTICES, 1):
            f.write(f"{i}. {practice}\n")
        f.write("\n")
        
        # Footer
        f.write("---\n")
        f.write("*For detailed examples and advanced usage, refer to individual tool documentation.*\n")
    
    return output_file


def generate_json_report(output_file: str = "tool_syntax_reference_report.json") -> str:
    """
    Generate a structured JSON report of all tools and syntax.
    
    Args:
        output_file: Path to save the JSON report
        
    Returns:
        Path to generated report file
    """
    report_data = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "version": "1.0",
            "description": "Security Tools Syntax Reference"
        },
        "tools": TOOL_REFERENCE,
        "wordlists": WORDLISTS,
        "best_practices": BEST_PRACTICES
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)
    
    return output_file


def generate_csv_report(output_file: str = "tool_syntax_reference_report.csv") -> str:
    """
    Generate a CSV report for spreadsheet analysis.
    
    Args:
        output_file: Path to save the CSV report
        
    Returns:
        Path to generated report file
    """
    import csv
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow(["Service", "Description", "Tool Name", "Purpose", "Command"])
        
        # Data rows
        for port_service, service_data in TOOL_REFERENCE.items():
            for tool_name, tool_data in service_data['tools'].items():
                for cmd in tool_data['commands']:
                    writer.writerow([
                        port_service,
                        service_data['description'],
                        tool_name,
                        tool_data['purpose'],
                        cmd
                    ])
    
    return output_file


def generate_html_report(output_file: str = "tool_syntax_reference_report.html") -> str:
    """
    Generate an HTML report with styling for browser viewing.
    
    Args:
        output_file: Path to save the HTML report
        
    Returns:
        Path to generated report file
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Tools Syntax Reference</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                padding: 40px;
            }
            h1 {
                color: #667eea;
                border-bottom: 3px solid #764ba2;
                padding-bottom: 10px;
            }
            h2 {
                color: #764ba2;
                margin-top: 30px;
                margin-bottom: 15px;
            }
            h3 {
                color: #555;
                margin-left: 20px;
            }
            .service-section {
                background: #f8f9fa;
                padding: 15px;
                border-left: 4px solid #667eea;
                margin: 20px 0;
                border-radius: 5px;
            }
            .tool-subsection {
                background: white;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
            }
            code {
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
            }
            pre {
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                font-family: 'Courier New', monospace;
            }
            .meta {
                color: #666;
                font-size: 0.9em;
                font-style: italic;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            th {
                background: #667eea;
                color: white;
            }
            tr:nth-child(even) {
                background: #f9f9f9;
            }
            .tips {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Security Tools Syntax Reference</h1>
            <p class="meta">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    """
    
    # Add tool sections
    for port_service, service_data in TOOL_REFERENCE.items():
        html_content += f"""
            <div class="service-section">
                <h2>{port_service}</h2>
                <p><strong>Description:</strong> {service_data['description']}</p>
        """
        
        for tool_name, tool_data in service_data['tools'].items():
            html_content += f"""
                <div class="tool-subsection">
                    <h3>{tool_name}</h3>
                    <p><strong>Purpose:</strong> {tool_data['purpose']}</p>
                    <p><strong>Commands:</strong></p>
                    <pre>"""
            for cmd in tool_data['commands']:
                html_content += f"{cmd}\n"
            html_content += """</pre>
                </div>
            """
        
        html_content += """</div>"""
    
    # Add best practices
    html_content += """
            <h2>📋 Best Practices</h2>
            <div class="tips">
                <ul>
    """
    for practice in BEST_PRACTICES:
        html_content += f"<li>{practice}</li>\n"
    
    html_content += """
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file


def run_tool_generator(report_formats: List[str] = None) -> Dict[str, str]:
    """
    Generate tool reference reports in specified formats.
    
    Args:
        report_formats: List of formats to generate ('markdown', 'json', 'csv', 'html')
                       Defaults to all formats if None
    
    Returns:
        Dictionary mapping format names to generated file paths
    """
    if report_formats is None:
        report_formats = ['markdown', 'json', 'csv', 'html']
    
    results = {}
    generators = {
        'markdown': generate_markdown_report,
        'json': generate_json_report,
        'csv': generate_csv_report,
        'html': generate_html_report
    }
    
    for fmt in report_formats:
        if fmt.lower() in generators:
            try:
                output_path = generators[fmt.lower()]()
                results[fmt.lower()] = output_path
                print(f"[+] Generated {fmt.upper()} report: {os.path.abspath(output_path)}")
            except Exception as e:
                print(f"[-] Error generating {fmt.upper()} report: {e}")
                results[fmt.lower()] = None
    
    return results


if __name__ == "__main__":
    import sys
    
    print("[*] Tool Syntax Reference Generator")
    print("[*] Generating security tool reference reports...")
    print()
    
    # Parse command line arguments
    formats = ['markdown', 'json', 'csv', 'html']
    if len(sys.argv) > 1:
        formats = [fmt.lower() for fmt in sys.argv[1:] if fmt.lower() in ['markdown', 'json', 'csv', 'html']]
    
    # Generate reports
    results = run_tool_generator(formats if formats else ['markdown', 'json', 'csv', 'html'])
    
    print()
    print("="*70)
    print("REPORT GENERATION SUMMARY")
    print("="*70)
    for fmt, path in results.items():
        status = "✓" if path else "✗"
        print(f"{status} {fmt.upper():10} -> {path if path else 'Failed'}")
    print("="*70)
