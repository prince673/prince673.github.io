---
title: "HackTheBox Cap — The Fundamentals Behind the Box"
date: 2024-06-05 15:00:00 +0530
categories: [CTF, HackTheBox]
tags: [idor, pcap, linux-capabilities, cap-setuid, web-security, privilege-escalation, learning]
author: YourHandle
---

Cap is classified as an "Easy" box on HackTheBox, but don't let that fool you. It packages three of the most real-world-relevant security concepts into a single clean attack chain. Understanding *why* each step works — not just *how* to execute it — is what separates a script-kiddie from a security professional. This post breaks down the three core weaknesses that make Cap tick.

---

## 1. Insecure Direct Object Reference (IDOR)

Everything begins with a deceptively simple observation: the URL `/download/2` has a number in it. That number is called a **direct object reference** — it's the application's way of pointing to a specific resource, in this case a packet capture file. The word "insecure" comes from what happens when you change that number. The server hands you someone else's file without ever asking whether you're allowed to have it.

Think of it like a coat check at a restaurant. You're given ticket number 42. But what if you handed back ticket number 1 instead, and the attendant just gave you whatever coat was hanging there — no questions asked? That's IDOR. The system trusts the identifier you present without verifying ownership.

In Cap, changing `/download/2` to `/download/0` exposed Nathan's packet capture — a file you had absolutely no business accessing. The fix is straightforward in principle: the server should always check that the logged-in user actually *owns* the resource they're requesting before serving it. This is called **authorization**, and it's distinct from *authentication* (proving who you are). You were authenticated as yourself — but the server never performed the authorization step of asking "does this person own resource 0?"

IDOR consistently appears in real-world bug bounty programs and penetration tests because it's easy to overlook during development. Developers focus on building features, and it's tempting to assume that users "won't think to change the number." They will. Always.

---

## 2. Credential Harvesting from Packet Captures

Once you have the PCAP file, the next weakness isn't technical at all — it's a protocol choice made decades ago. **FTP (File Transfer Protocol)** was designed in an era when the internet was a small, trusted academic network. It transmits everything, including usernames and passwords, in plain readable text. No encryption, no protection.

A packet capture is essentially a recording of raw network traffic — every byte that traveled across the wire during that session. When Nathan logged into the FTP server, his credentials were broadcast in cleartext, and the capture faithfully recorded every word. Opening the file in Wireshark and finding `USER nathan` followed by `PASS <password>` is not a sophisticated attack. It's just reading.

The deeper lesson here is actually twofold. First, **cleartext protocols are a liability** regardless of how "internal" or "trusted" a network feels. FTP should be replaced with SFTP or FTPS wherever credentials are involved. HTTP should be HTTPS. The moment traffic is encrypted, a captured PCAP becomes useless to an attacker — they'd see scrambled bytes instead of passwords.

Second, and more subtly, **logs and captures themselves are sensitive data**. The web dashboard on Cap was storing these snapshots and making them accessible via a predictable URL. Even if the FTP traffic had been encrypted, storing network captures and exposing them through an IDOR vulnerability is a serious design flaw. Protect your forensic data as carefully as you protect the systems it monitors.

---

## 3. Linux Capabilities Misconfiguration (`cap_setuid`)

The final piece of the puzzle involves a Linux security feature that, when misconfigured, becomes the exact thing it was designed to prevent. To understand it, a little background helps.

Traditionally, Linux has a binary privilege model: you're either a regular user, or you're root. Many programs need *one specific* root-like power — a web server needs to bind to port 80, for example — but granting them full root to achieve that one thing is overkill and dangerous. **Linux capabilities** were introduced to solve this. They let you carve root's powers into fine-grained pieces and assign only the necessary slice to a binary.

`cap_setuid` is one such capability. It grants a process the ability to **change its own user ID** to any user on the system, including root (UID 0). When this capability is assigned to Python 3.8, it means any user who can run that Python binary can write a few lines of code to switch to root and spawn a shell:

```bash
/usr/bin/python3.8 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

What makes this particularly dangerous is that Python is an *interpreter* — a general-purpose tool that executes arbitrary code. Giving `cap_setuid` to something like `/usr/bin/ping` is less risky because ping does one specific thing. Giving it to Python is essentially saying "anyone can write a root shell." The `-p` flag in the shell command tells it to preserve the effective UID (root) rather than dropping back to the real UID of the invoking user.

The lesson here is to **audit your binaries with elevated capabilities** regularly. The command `getcap -r / 2>/dev/null` will show you every binary on the system that has capabilities assigned. Each one is a potential privilege escalation path if it can be coerced into running attacker-controlled logic. Interpreters, scripting languages, and package managers are especially high-risk candidates.
a
---

## The Full Attack Chain

What makes Cap elegant as a learning exercise is how cleanly the three vulnerabilities chain together. Each step unlocks the next:

**IDOR** gave access to a PCAP that wasn't ours → the **cleartext PCAP** revealed Nathan's FTP credentials → those credentials provided an **initial foothold** via SSH → **`cap_setuid` on Python** turned that user-level foothold into full root access.

No single step is complicated in isolation. But together they form a complete compromise, and each mirrors a mistake that appears regularly in real production environments. That's precisely why mastering these fundamentals — not just memorizing the commands — is what makes you genuinely better at security.

---

*The best way to learn defense is to understand offense. The more clearly you can see how these chains form, the more instinctively you'll spot them when building or auditing systems of your own.*