# AUTOMATION - Penetration Testing Security Tools

Complete automation suite for penetration testers to analyze Nmap scans and generate comprehensive security tool recommendations.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Script Descriptions](#script-descriptions)
- [Workflow: Complete Penetration Testing Pipeline](#workflow-complete-penetration-testing-pipeline)
- [Installation & Setup](#installation--setup)
- [Usage Examples](#usage-examples)
- [Output Files](#output-files)
- [Best Practices](#best-practices)

---

## 🎯 Overview

This repository contains Python scripts designed to automate security testing workflows:

1. **Nmap_analyzer.py** - Parses Nmap XML output and recommends tools for the scanned target
2. **concurrent_security_analyzer.py** - Orchestrates the Nmap analyzer for efficient automation

These scripts work together to transform raw Nmap scan results into actionable security tool recommendations for a single target.

---

## 📦 Prerequisites

- Python 3.7+
- Nmap (for generating XML scan output)
- The following tools installed (recommended for security testing):
  - hydra
  - nmap with scripts
  - ssh-audit
  - gobuster
  - nikto
  - feroxbuster
  - sslscan
  - testssl.sh
  - smbclient
  - smbmap
  - crackmapexec
  - ldapsearch
  - mysql
  - And others (see port recommendations)

---

## 📄 Script Descriptions

### 1. **Nmap_analyzer.py**
Analyzes Nmap XML scan results and recommends security tools for the discovered target.

**What it does:**
- Parses Nmap XML output files (-oX format)
- Extracts IP addresses, hostnames, ports, services, and versions from the scanned target
- Maps ports to security testing tools
- Generates a markdown report with recommendations
- Displays a terminal summary of findings
- Focuses on the first scanned target only

**Key Features:**
- Supports 25+ common ports (FTP, SSH, DNS, HTTP, HTTPS, SMB, LDAP, MySQL, MSSQL, RDP, etc.)
- Provides tool-specific recommendations for each port
- Extracts service version information
- Generates a structured markdown report
- Single target report (no multi-target output)

**Output:**
- `nmap_security_report.md` - Detailed markdown report with tool recommendations for the target

---

### 2. **concurrent_security_analyzer.py**
Master orchestrator that manages Nmap analyzer for efficient automation.

**What it does:**
- Manages execution of Nmap analyzer
- Creates organized output directory structure
- Tracks execution time and generates summary reports
- Handles errors gracefully with detailed logging
- Focuses on single target analysis

**Key Features:**
- Runs Nmap analyzer
- Creates organized output directory structure
- Generates execution summary with timing information
- Saves analysis metadata to JSON
- Returns proper exit codes for shell scripting

**Output:**
- Complete security analysis in `./security_reports/` (customizable)
- `analysis_summary.json` - Execution metadata and file locations

---

## 🚀 Workflow: Complete Penetration Testing Pipeline

### Step-by-Step Process

```
1. Perform Nmap Scan
   └─> nmap -oX scan.xml target.com

2. Run Security Analyzer
   └─> python concurrent_security_analyzer.py scan.xml
       │
       └─── Nmap Analyzer
            └─> Parse XML
            └─> Extract target ports/services
            └─> Generate tool recommendations
            └─> Create nmap_security_report.md

3. Review Report
   └─> Markdown report for quick reference
   └─> Tool recommendations per port

4. Execute Recommended Tools
   └─> Copy commands from generated recommendations
   └─> Follow best practices guidelines
   └─> Document findings
```

---

## 💾 Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/tlCedric/AUTOMATION.git
cd AUTOMATION
```

### 2. Verify Python Installation
```bash
python3 --version  # Should be 3.7+
```

### 3. Install Nmap (if not already installed)
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Other systems: https://nmap.org/download
```

### 4. Install Optional Security Tools
```bash
# Common pentest tools
sudo apt-get install hydra nikto gobuster smbclient

# For more tools, refer to your distribution's package manager
```

---

## 🎮 Usage Examples

### Option A: Quick Start (All-in-One)

After performing an Nmap scan:

```bash
# 1. Generate Nmap XML output
nmap -oX scan.xml -sV -p- target.example.com

# 2. Run the complete automation
python3 concurrent_security_analyzer.py scan.xml

# 3. Check your reports
ls -la security_reports/
```

**Output:**
- `security_reports/nmap_security_report.md` - Tool recommendations for the target
- `security_reports/analysis_summary.json` - Execution metadata

---

### Option B: Custom Output Directory

```bash
python3 concurrent_security_analyzer.py scan.xml ./my_reports
```

---

### Option C: Individual Script Usage

#### Run Only Nmap Analyzer
```bash
python3 Nmap_analyzer.py scan.xml

# Output: nmap_security_report.md (in current directory)
```

---

## 📊 Output Files

### Generated by Nmap Analyzer
| File | Format | Purpose |
|------|--------|---------|
| `nmap_security_report.md` | Markdown | Port-to-tool mapping with detailed recommendations for the target |

### Generated by Concurrent Analyzer
| File | Format | Purpose |
|------|--------|---------|
| `analysis_summary.json` | JSON | Execution timing, file paths, error log |

---

## 📋 Supported Services & Ports

The scripts provide tool recommendations for the following services:

| Port | Service | Example Tools |
|------|---------|---------------|
| 21 | FTP | hydra, nmap, ftp client |
| 22 | SSH | hydra, ssh-audit, nmap |
| 23 | Telnet | hydra, nmap |
| 25 | SMTP | smtp-user-enum, swaks, nmap |
| 53 | DNS | dig, dnsrecon, fierce, gobuster |
| 80 | HTTP | gobuster, nikto, feroxbuster, whatweb |
| 88 | Kerberos | kerbrute, impacket, rubeus |
| 110 | POP3 | hydra, nmap |
| 135 | RPC | rpcclient, impacket |
| 139 | NetBIOS | enum4linux, nbtscan, smbclient |
| 389 | LDAP | ldapsearch, ldapdomaindump, nmap |
| 443 | HTTPS | gobuster, nikto, sslscan, testssl.sh |
| 445 | SMB | smbclient, smbmap, enum4linux, crackmapexec |
| 593 | RPC/HTTP | rpcclient, impacket |
| 636 | LDAPS | ldapsearch, ldapdomaindump |
| 1433 | MSSQL | crackmapexec, impacket, sqsh |
| 2049 | NFS | showmount, nmap |
| 3306 | MySQL | mysql, hydra, crackmapexec |
| 3389 | RDP | xfreerdp, crowbar, nmap |
| 5985 | WinRM (HTTP) | evil-winrm, crackmapexec |
| 5986 | WinRM (HTTPS) | evil-winrm, crackmapexec |
| 8080 | HTTP Alt | gobuster, nikto, feroxbuster |

---

## ⚡ Workflow Example (Real Scenario)

```bash
# Step 1: Scan target
nmap -oX targets/company.xml -sV -sC -p- company.example.com

# Step 2: Run full automation
python3 concurrent_security_analyzer.py targets/company.xml ./company_audit

# Step 3: Review findings (takes ~2-5 seconds)
cat company_audit/nmap_security_report.md

# Step 4: Execute recommended tests
# Example from report: SMB on port 445 found
# From tool recommendations, run:
crackmapexec smb company.example.com

# Step 5: Document findings
```

---

## 🔒 Best Practices

### Before Running Tools

1. ✅ **Obtain Authorization** - Always get written permission before security testing
2. ✅ **Scope Documentation** - Know exactly which systems/IPs you're authorized to test
3. ✅ **Network Considerations** - Inform network teams of testing timeline
4. ✅ **Backup Data** - Never test on production without proper procedures

### While Using Generated Recommendations

1. ✅ **Start Conservative** - Begin with non-destructive reconnaissance tools
2. ✅ **Use Thread Control** - Use `-t` flag to control parallel connections
3. ✅ **Add Delays** - Avoid detection with `-w` flag in brute-force tools
4. ✅ **Log Everything** - Save all results with `-o` flag for documentation
5. ✅ **Test Default Credentials** - Always try common credentials first
6. ✅ **Document Methodology** - Keep detailed notes with timestamps

### After Testing

1. ✅ **Compile Findings** - Organize results by severity and service
2. ✅ **Validate Results** - Confirm findings with multiple tools when possible
3. ✅ **Generate Reports** - Create professional documentation with remediation steps
4. ✅ **Keep Tools Updated** - Regularly update Nmap, tool databases, and wordlists

---

## 🐛 Troubleshooting

### Issue: "File not found" error
```
Solution: Ensure Nmap XML file exists and provide correct path:
python3 concurrent_security_analyzer.py /full/path/to/scan.xml
```

### Issue: Module import errors
```
Solution: Run from repository root directory:
cd /path/to/AUTOMATION
python3 concurrent_security_analyzer.py scan.xml
```

### Issue: No tools found for ports
```
Solution: These are likely uncommon services. The scripts will still identify them.
Use: nmap -sC -sV -p<port> target to get more service details
```

### Issue: Reports saved in wrong location
```
Solution: Specify output directory explicitly:
python3 concurrent_security_analyzer.py scan.xml ./desired_output_path
```

---

## 📚 Additional Resources

- **Nmap Documentation**: https://nmap.org/book/
- **SecLists Repository**: https://github.com/danielmiessler/SecLists
- **HackTricks**: https://book.hacktricks.xyz/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

---

## 📝 Example Report Preview

### Nmap Analyzer Output (nmap_security_report.md)
```
## 🖥️ Target Host: 192.168.1.100 (webserver.local)

| Port / Protocol | Service Name | Service Type | Detected Version | Recommended Tools |
| :--- | :--- | :--- | :--- | :--- |
| **22/tcp** | ssh | *SSH (Secure Shell)* | OpenSSH 7.4 | `hydra (Brute-force)`, `ssh-audit`, `nmap --script ssh-auth-methods` |
| **80/tcp** | http | *HTTP (Web Server)* | Apache 2.4.6 | `gobuster dir`, `nikto`, `feroxbuster` |
| **445/tcp** | netbios-ssn | *SMB (Server Message Block)* | Samba 4.7 | `smbclient`, `smbmap`, `crackmapexec smb` |

### 🚀 Targeted Action Plan
Based on the discovered services, prioritize the following commands:
- **Port 22 (ssh):** Run analysis using `hydra (Brute-force)`, etc.
```

---

## 🤝 Contributing

Found an issue or want to improve the scripts? Feel free to submit pull requests or open issues.

---

## 📄 License

This project is open source and available under the MIT License.

---

## ⚠️ Disclaimer

These tools are designed for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing. The author is not responsible for misuse.

---

**Last Updated**: July 2026  
**Repository**: https://github.com/tlCedric/AUTOMATION
