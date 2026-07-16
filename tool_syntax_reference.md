# Security Tools Syntax Reference Guide

This document provides command syntax and usage examples for all security tools referenced in the Nmap analyzer.

---

## FTP (Port 21)

### Hydra - Brute Force Attack
```bash
hydra -l username -P /path/to/wordlist.txt ftp://target_ip
hydra -L userlist.txt -P passlist.txt ftp://target_ip -t 4
```

### Nmap FTP Enumeration Scripts
```bash
nmap --script ftp-anon target_ip
nmap --script ftp-* target_ip
```

### FTP Client
```bash
ftp target_ip
ftp> ls
ftp> get filename
ftp> quit
```

---

## SSH (Port 22)

### Hydra - SSH Brute Force
```bash
hydra -l admin -P /path/to/wordlist.txt ssh://target_ip
hydra -L userlist.txt -P passlist.txt ssh://target_ip -t 4
```

### SSH-Audit
```bash
ssh-audit target_ip
ssh-audit -p 2222 target_ip
ssh-audit --json target_ip
```

### Nmap SSH Scripts
```bash
nmap --script ssh-auth-methods target_ip
nmap --script ssh-hostkey target_ip
nmap --script ssh2-enum-algos target_ip
```

### Manual SSH Connection
```bash
ssh username@target_ip
ssh -p 2222 username@target_ip
ssh -v username@target_ip  # Verbose mode
```

---

## Telnet (Port 23)

### Hydra - Telnet Brute Force
```bash
hydra -l admin -P /path/to/wordlist.txt telnet://target_ip
```

### Nmap Telnet Scripts
```bash
nmap --script telnet-brute target_ip
nmap --script telnet-encryption target_ip
```

### Telnet Client
```bash
telnet target_ip 23
telnet target_ip
```

---

## SMTP (Port 25)

### SMTP User Enumeration
```bash
smtp-user-enum -M VRFY -U userlist.txt -t target_ip
smtp-user-enum -M EXPN -U userlist.txt -t target_ip
```

### SWAKS - SMTP Mail Testing
```bash
swaks --to recipient@domain.com --from attacker@domain.com --header "Subject: Test" --body "Test message" --server target_ip
swaks -t admin@target.com --server target_ip --auth LOGIN -au user -ap password
```

### Nmap SMTP Scripts
```bash
nmap --script smtp-enum-users target_ip
nmap --script smtp-commands target_ip
nmap --script smtp-open-relay target_ip
```

---

## DNS (Port 53)

### Dig - DNS Zone Transfer
```bash
dig axfr @target_ip domain.com
dig @target_ip ns domain.com
dig @target_ip any domain.com
```

### DNSRecon
```bash
dnsrecon -d domain.com -n target_ip
dnsrecon -d domain.com -t axfr
dnsrecon -d domain.com -t brute
```

### Fierce - DNS Enumeration
```bash
fierce --domain domain.com --dns-servers target_ip
fierce --domain domain.com --dnsserver target_ip --wordlist wordlist.txt
```

### Gobuster DNS Enumeration
```bash
gobuster dns -d domain.com -w wordlist.txt
gobuster dns -d domain.com -w wordlist.txt -r target_ip
```

---

## HTTP (Port 80)

### Gobuster - Directory Enumeration
```bash
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target_ip -w wordlist.txt -x .php,.html
gobuster dir -u http://target_ip -w wordlist.txt -t 50
```

### Nikto - Web Server Scanner
```bash
nikto -h http://target_ip
nikto -h target_ip -p 80
nikto -h http://target_ip -Tuning 1 -o report.html
```

### Feroxbuster - Web Content Discovery
```bash
feroxbuster -u http://target_ip -w wordlist.txt
feroxbuster -u http://target_ip -w wordlist.txt -x php,html,txt
feroxbuster -u http://target_ip --scan-limit 6
```

### Nmap HTTP Vulnerability Scripts
```bash
nmap --script http-vuln-* target_ip
nmap --script http-title target_ip
nmap --script http-methods target_ip
```

### WhatWeb - Web Technology Identification
```bash
whatweb target_ip
whatweb http://target_ip
whatweb -v target_ip  # Verbose
```

---

## Kerberos (Port 88)

### Kerbrute - User Enumeration
```bash
kerbrute userenum --dc target_ip -d domain.com userlist.txt
kerbrute passwordspray --dc target_ip -d domain.com userlist.txt password.txt
```

### Impacket - Get NTLM Hash
```bash
impacket-GetNPUsers -dc-ip target_ip domain.com/username
impacket-GetNPUsers -dc-ip target_ip domain.com/ -usersfile userlist.txt
```

### Rubeus - Kerberos Tool (Windows)
```bash
Rubeus.exe asreproast /domain:domain.com /dc:target_ip
Rubeus.exe kerberoast /domain:domain.com /dc:target_ip
```

---

## POP3 (Port 110)

### Hydra - POP3 Brute Force
```bash
hydra -l username -P /path/to/wordlist.txt pop3://target_ip
hydra -L userlist.txt -P passlist.txt pop3://target_ip
```

### Nmap POP3 Scripts
```bash
nmap --script pop3-capabilities target_ip
nmap --script pop3-brute target_ip
```

---

## RPC (Port 135)

### RPCClient
```bash
rpcclient -U "domain\\username%password" target_ip
rpcclient -U "domain\\username" -W domain target_ip
rpcclient $> enumdomusers
rpcclient $> queryuser rid
```

### Impacket - RPC Dump
```bash
impacket-rpcdump target_ip
impacket-rpcdump target_ip | grep -i interface
```

---

## NetBIOS (Port 139)

### Enum4Linux - SMB/NetBIOS Enumeration
```bash
enum4linux -a target_ip
enum4linux -u username -p password -a target_ip
enum4linux -r target_ip  # RID cycling
```

### NBTScan
```bash
nbtscan target_ip
nbtscan -r target_ip
nbtscan -v target_ip
```

### SMBClient
```bash
smbclient -L //target_ip -U username%password
smbclient //target_ip/share -U username
smbclient //target_ip/share -U username -p password
```

---

## LDAP (Port 389)

### LDAPSearch
```bash
ldapsearch -h target_ip -x -s base namingcontexts
ldapsearch -h target_ip -x -b "dc=domain,dc=com" -D "cn=admin,dc=domain,dc=com" -w password
ldapsearch -h target_ip -x -b "dc=domain,dc=com" "(objectClass=*)"
```

### LDAPDomainDump
```bash
ldapdomaindump -u domain\\username -p password ldap://target_ip
ldapdomaindump --no-kerberos ldap://target_ip
```

### Nmap LDAP Scripts
```bash
nmap --script ldap-search target_ip
nmap --script ldap-rootdse target_ip
```

---

## HTTPS (Port 443)

### Gobuster - HTTPS Directory Enumeration
```bash
gobuster dir -u https://target_ip -w wordlist.txt -k
gobuster dir -u https://target_ip -w wordlist.txt -k -x .php,.html
```

### Nikto - HTTPS Scanning
```bash
nikto -h https://target_ip -ssl
nikto -h target_ip -p 443
```

### SSLScan - SSL/TLS Configuration
```bash
sslscan target_ip:443
sslscan --no-failed target_ip
```

### TestSSL.sh - Comprehensive SSL Testing
```bash
./testssl.sh target_ip
./testssl.sh -e all target_ip
./testssl.sh --json target_ip
```

### Feroxbuster - HTTPS Content Discovery
```bash
feroxbuster -u https://target_ip -w wordlist.txt -k
feroxbuster -u https://target_ip -w wordlist.txt -k -x php,html
```

---

## SMB (Port 445)

### SMBClient - SMB Share Access
```bash
smbclient -L //target_ip -U username%password
smbclient //target_ip/share -U username%password
smbclient //target_ip/share -U username
```

### SMBMap - SMB Share Mapping
```bash
smbmap -H target_ip
smbmap -H target_ip -u username -p password
smbmap -H target_ip -u username -p password -d domain
```

### Enum4Linux-ng - Enhanced Enumeration
```bash
enum4linux-ng target_ip
enum4linux-ng -A target_ip
enum4linux-ng -u username -p password target_ip
```

### CrackMapExec - SMB Testing
```bash
crackmapexec smb target_ip
crackmapexec smb target_ip -u username -p password
crackmapexec smb target_ip -u username -p password --local-auth
```

### Nmap SMB Scripts
```bash
nmap --script smb-vuln-* target_ip
nmap --script smb-os-discovery target_ip
nmap --script smb-enum-shares target_ip
```

---

## RPC over HTTP (Port 593)

### RPCClient
```bash
rpcclient -U "domain\\username%password" -I target_ip
```

### Impacket - RPC Dump
```bash
impacket-rpcdump target_ip -I
```

---

## LDAPS (Port 636)

### LDAPSearch - Secure LDAP
```bash
ldapsearch -H ldaps://target_ip -x -b "dc=domain,dc=com"
ldapsearch -H ldaps://target_ip -x -D "cn=admin,dc=domain,dc=com" -w password
```

### LDAPDomainDump - LDAPS
```bash
ldapdomaindump -u domain\\username -p password ldaps://target_ip
```

---

## MSSQL (Port 1433)

### CrackMapExec - MSSQL
```bash
crackmapexec mssql target_ip
crackmapexec mssql target_ip -u username -p password
crackmapexec mssql target_ip -u username -p password -x "SELECT @@version"
```

### Impacket - MSSQL Client
```bash
impacket-mssqlclient username:password@target_ip
impacket-mssqlclient -windows-auth domain/username:password@target_ip
```

### SQSH - SQL Shell
```bash
sqsh -S target_ip -U username -P password
sqsh -S target_ip -U domain\\username -P password
```

### Nmap MSSQL Scripts
```bash
nmap --script mssql-ntlm-info target_ip
nmap --script mssql-info target_ip
```

---

## NFS (Port 2049)

### Showmount - NFS Export Enumeration
```bash
showmount -e target_ip
showmount -a target_ip
```

### Nmap NFS Scripts
```bash
nmap --script nfs-showmount target_ip
nmap --script nfs-ls target_ip
```

### Mounting NFS Shares
```bash
mkdir /mnt/nfs
mount -t nfs target_ip:/export /mnt/nfs
mount -t nfs -o nolock target_ip:/export /mnt/nfs
```

---

## MySQL (Port 3306)

### MySQL Client
```bash
mysql -h target_ip -u username -p password
mysql -h target_ip -u root -e "SELECT version();"
```

### Hydra - MySQL Brute Force
```bash
hydra -l root -P /path/to/wordlist.txt mysql://target_ip
hydra -L userlist.txt -P passlist.txt mysql://target_ip
```

### Nmap MySQL Scripts
```bash
nmap --script mysql-audit target_ip
nmap --script mysql-databases target_ip
nmap --script mysql-users target_ip
```

### CrackMapExec - MySQL
```bash
crackmapexec mysql target_ip -u username -p password
crackmapexec mysql target_ip -u root -p '' --query "SELECT VERSION()"
```

---

## RDP (Port 3389)

### xfreerdp - RDP Client
```bash
xfreerdp /v:target_ip /u:username /p:password
xfreerdp /v:target_ip /u:domain\\username /p:password
xfreerdp /v:target_ip /u:username /p:password /cert-ignore
```

### Crowbar - RDP Brute Force
```bash
crowbar -b rdp -s target_ip/32 -u username -C passlist.txt
crowbar -b rdp -s target_ip -u admin -C wordlist.txt -n 1
```

### Nmap RDP Scripts
```bash
nmap --script rdp-vuln-ms12-020 target_ip
nmap --script rdp-enum-encryption target_ip
```

---

## WinRM (Port 5985 / 5986)

### Evil-WinRM - Windows Remote Management
```bash
evil-winrm -i target_ip -u username -p password
evil-winrm -i target_ip -u domain\\username -p password
evil-winrm -i target_ip -u username -p password -s /path/to/scripts
```

### CrackMapExec - WinRM
```bash
crackmapexec winrm target_ip
crackmapexec winrm target_ip -u username -p password
crackmapexec winrm target_ip -u username -p password -x "powershell command"
```

---

## HTTP Alternate (Port 8080)

### Gobuster - Port 8080 Enumeration
```bash
gobuster dir -u http://target_ip:8080 -w wordlist.txt
gobuster dir -u http://target_ip:8080 -w wordlist.txt -x .php,.html,.jsp
```

### Nikto - Port 8080 Scanning
```bash
nikto -h http://target_ip:8080
nikto -h target_ip -p 8080
```

### Feroxbuster - Port 8080
```bash
feroxbuster -u http://target_ip:8080 -w wordlist.txt
feroxbuster -u http://target_ip:8080 -w wordlist.txt -x php,html,jsp
```

### Nmap HTTP Vulnerability Scripts
```bash
nmap --script http-vuln-* target_ip -p 8080
nmap --script http-title target_ip -p 8080
```

---

## Generic Tools

### Nmap Comprehensive Scanning
```bash
nmap -sC -sV target_ip
nmap -A target_ip
nmap -sS -sV -sC target_ip
```

### Netcat - Banner Grabbing
```bash
nc -v target_ip 21
nc -v target_ip 80
echo "" | nc -v target_ip 25
```

### SearchSploit - Exploit Search
```bash
searchsploit "service_name"
searchsploit "service_name" version
searchsploit -x service_name/exploit.py
```

---

## Common Wordlists

### Kali Linux Default Wordlists
```bash
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/wfuzz/common.txt
```

### SecLists Repository
```bash
git clone https://github.com/danielmiessler/SecLists.git
# Web content
/SecLists/Discovery/Web-Content/common.txt
# DNS
/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Tips & Best Practices

1. **Timing**: Use `-t` flag to control thread count
2. **Stealth**: Add delays between requests using `-w` in hydra
3. **Output**: Always save results to file with `-o` flag
4. **Authentication**: Test with common credentials first (admin/admin, root/password)
5. **Rate Limiting**: Respect target resources and avoid DoS
6. **Legal**: Always have authorization before testing

