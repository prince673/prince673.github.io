---
title: "HackTheBox Abducted — The Fundamentals Behind the Box"
date: 2026-06-11 15:00:00 +0530
categories: [CTF, HackTheBox]
tags: [cve-2026-4480, samba, symlinks, systemd, polkit, web-security, privilege-escalation, learning]
author: Prince_kumar
---

Abducted is classified as a "Medium" difficulty box on HackTheBox, and it packages an exceptional, multi-staged exploit chain. From RPC manipulation to Polkit delegation and Samba symlink bypasses, the box requires a deep understanding of standard system services and access controls. 

This post breaks down the core fundamental mechanisms that make each step of the Abducted challenge possible.

---

## 1. SMB Enumeration & Guest Printer Shares
SMB enumeration is one of the most critical steps when targeting Windows or Linux-based file servers. By executing:

```bash
smbclient -L //IP -N
```

We enumerate available shares. Printer shares (such as `HP-Reception`) are often configured to be guest-accessible so that anyone in the office can submit print jobs. However, a guest-accessible print queue is also an RPC endpoint. This means unauthenticated remote users can issue print commands, transforming a simple printer share into a major remote attack surface.

---

## 2. Command Injection via Unsanitized Input (CVE-2026-4480)
The root cause of CVE-2026-4480 lies within Samba's print subsystem. When a user submits a print job, Samba processes the document using its defined print command. In vulnerable versions, Samba substitutes the user-controlled job name (`%J`) directly into a shell command without escaping:

- **Sanitization Bypass**: The target's sanitization routine only replaces single quotes (`'`) with underscores (`_`).
- **Command Shell Metacharacters**: Because it only filters single quotes, other shell metacharacters such as `|`, `;`, `&`, `$()`, and backticks (`` ` ``) are fully processed by the underlying shell execution.
- **Protocol Restriction**: The attack cannot be carried out via the standard `smbclient` utility, because legacy RAP (Remote Access Protocol) sanitizes metacharacters before they reach the spooler. Instead, we must use the modern `spoolss` RPC interface to send our payload unmodified.

---

## 3. RPC Protocol Manipulation (The `spoolss` Pipe)
By interacting directly with the `spoolss` RPC pipe using Python's Samba bindings (`samba.dcerpc.spoolss`), we can programmatically trigger the print command injection. The exploit flow follows a distinct sequence of RPC events:

1. **`OpenPrinter`**: Establishes a handle to the vulnerable printer share.
2. **`StartDocPrinter`**: Registers a new print job where the `document_name` is set to our shell payload (e.g., `|sh`).
3. **`WritePrinter`**: Sends the spool file content containing the raw shell commands we wish to run.
4. **`EndDocPrinter`**: Closes the document, prompting Samba to run the configured print command with our unsanitized `%J` variable, executing the contents of our spool file.

---

## 4. Blind Command Execution & Process Detachment
When a command is executed via Samba's print command shell injection, there is no backchannel to receive stdout or stderr. The execution is entirely blind.

To verify execution and obtain access, we must:
- Use out-of-band communication channels (like ICMP pings or reverse TCP connections).
- Detach the payload execution path using `setsid bash -c '...' &`. If we don't detach the command, the parent process hangs waiting for the shell to close, which halts the RPC spooler and prevents the connection from returning cleanly.

---

## 5. Reversible Password Obscurity (Rclone Configs)
Many utilities obscure passwords in configuration files to prevent them from being read by casual observers. However, obscuring is not encrypting. 

- Rclone configuration files store passwords encoded with a custom base64-like algorithm. 
- Using `rclone reveal` immediately restores the credentials back to cleartext. 
- Storing passwords in configuration files without using a cryptographically backed keystore means any local read access leads to complete credential exposure.

---

## 6. Samba `force user` & Insecure Symlink Abuse (Wide Links)
Samba provides several features to bridge Linux filesystems and Windows networking:

- **`force user`**: Forces all operations on a share to run as a specific local account (e.g., `marcus`), regardless of who authenticated.
- **`wide links = yes`**: Instructs Samba to follow symlinks that lead outside the root directory of the share.
- **`unix extensions = no`**: Disables UNIX-specific protocol extensions, which is a prerequisite for allowing insecure wide links.

**The Exploit Mechanism**: If a user has write permissions on the share, they can create a local symbolic link pointing to a protected target folder (like `/home/marcus`). When Samba follows the symlink, `force user = marcus` ensures that any files created through the share are owned by `marcus` and written with his permissions. We use this to write our own public key into `/home/marcus/.ssh/authorized_keys`.

---

## 7. Systemd Drop-in Service Overrides
Systemd allows administrators to modify service behaviors without altering the main service file. By placing `.conf` files in a drop-in directory:

```bash
/etc/systemd/system/<service>.service.d/
```

These configurations are merged into the service's runtime configuration. If this directory is writable by a non-root group (such as `operators`), we can inject an `ExecStartPre` parameter. Since the main service (`smbd.service`) runs as `root`, any commands declared in our `ExecStartPre` drop-in will also execute as `root`.

---

## 8. Polkit (PolicyKit) Permission Delegation
Polkit acts as an authorization manager on Linux, determining whether a user is allowed to perform administrative tasks (like restarting services) without entering a password.

- **`pkcheck`**: Checks if the current process is authorized to perform specific actions.
- **`org.freedesktop.systemd1.reload-daemon`**: Allows non-root users to reload the systemd configuration.
- **Conditional Restart Rules**: Polkit can be configured to allow specific groups to restart specific services (like `smbd`) without credentials.

By combining the ability to reload systemd daemon files and restart the service via Polkit with the group-writable drop-in directory, we gain arbitrary root code execution when the service restarts.

---

## 9. Setuid Binary Execution & Privilege Preservation
When copying a binary (like `bash`) to run with root privileges, we set the Set User ID (SUID) bit:

```bash
chmod 4755 /tmp/binary
```

When executing an SUID shell, `bash` will drop privileges by default if it detects that the real UID does not match the effective UID (root). To prevent this behavior, we must execute `bash` with the privilege-preservation flag:

```bash
/tmp/binary -p
```

This instructs the shell to retain its effective UID (root), granting us a root terminal.

---

## The Full Attack Chain

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

## Summary Table

| Phase | Fundamental Technique | Key Vulnerability |
|-------|----------------------|-------------------|
| **Foothold** | RPC-based printing spooler manipulation | Unsanitized job name (`%J`) command execution |
| **Pivot** | Reversible config decryption | Cleartext password obscuring and reuse |
| **Lateral Move** | Samba symlink traversal & user forcing | Insecure wide link traversal with `force user` |
| **Root Escalation** | Systemd drop-in override & Polkit authorization | Writable system config folder + delegated service administration |
