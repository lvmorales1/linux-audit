# linux-audit

A simple bash script that checks basic security settings on a Linux machine. I made it to practice Linux hardening and to have a quick way to spot common misconfigurations.

It doesn't change anything on the system, it only reads and reports.

## What it checks

- **Users** - accounts with UID 0, empty passwords, users with a login shell, sudo/wheel members
- **File permissions** - `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, sticky bit on `/tmp`, world-writable files, unusual SUID binaries
- **Updates** - pending updates for apt, dnf and pacman (plus AUR helpers like yay/paru), and if a reboot is needed
- **Services** - running and failed services, services that are usually unnecessary, open TCP ports
- **Firewall** - checks if ufw, firewalld, nftables or iptables is active
- **SSH** - root login, password auth, empty passwords and port

## Usage

```bash
git clone https://github.com/<your-user>/linux-audit.git
cd linux-audit
chmod +x audit.sh
sudo ./audit.sh
```

It works without root, but some checks (like `/etc/shadow` and the full sshd config) are skipped.

Save the report to a file:

```bash
sudo ./audit.sh -o reports/audit.log
```

## Example output

```
=== Users ===
  [OK] Only root has UID 0
  [OK] No users with empty passwords
  [INFO] Users with a login shell: root,user

=== File permissions ===
  [OK] /etc/passwd permissions are fine (644)
  [OK] /etc/shadow permissions are fine (600)
  [WARN] Unusual SUID binary: /usr/bin/nvidia-modprobe

=== SSH ===
  [WARN] Password authentication is enabled, prefer key-based auth

=== Summary ===
  Failures: 0
  Warnings: 2
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Warnings found |
| 2 | Failures found |

This makes it easy to use in cron jobs or CI.

## Tested on

- Arch Linux
- Debian 13