# Host Forensics Case Study: Detection of Credential Harvesting Attempts via Syscall Auditing

**Date:** May 20, 2026  
**Host Environment:** Kali Linux Rolling Sandbox VM (Debian-based Kernel)  
**Triage Tooling:** Linux Kernel Audit Framework (`auditd`)  
**Threat Category:** Insider Threat / Credential Harvesting (TA0006 - Access)  

---

## 1. Executive Summary
A high-priority defensive alert triggered on the host environment tracking unauthorized system interactions with protected credential stores. An unprivileged session identity (`uid=1000`) attempted to open the local password shadow hashes file database (`/etc/shadow`). The kernel immediately restricted the execution path, returning a permission deficit validation, which was subsequently extracted via targeted system call recording pipelines.

## 2. Forensic Telemetry Analysis (Raw SIEM Breakout)

The system call intercept cleanly isolated the event parameters across multiple event block contexts:

```log
type=SYSCALL msg=audit(1779301152.124:52): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7ffe6deb42d3 a2=0 a3=0 items=1 ppid=1499 pid=7216 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="cat" exe="/usr/bin/cat" subj=unconfined key="password_access"ARCH=x86_64 SYSCALL=openat AUID="kali" UID="kali" GID="kali"
type=PATH msg=audit(1779301152.124:52): item=0 name="/etc/shadow" inode=523418 dev=fe:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL OUID="root" OGID="shadow"
