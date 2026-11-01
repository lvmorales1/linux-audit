#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNINGS=0

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
bad()  { echo -e "  ${RED}[FAIL]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

section() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
}

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Not running as root, some checks may be incomplete.${NC}"
fi

echo "Linux Security Audit"
echo "Host: $(cat /etc/hostname 2>/dev/null || uname -n)"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"

check_users() {
    section "Users"

    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    for u in $root_users; do
        if [ "$u" != "root" ]; then
            bad "User '$u' has UID 0"
        fi
    done
    [ "$root_users" = "root" ] && ok "Only root has UID 0"

    if [ -r /etc/shadow ]; then
        empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
        if [ -n "$empty" ]; then
            for u in $empty; do
                bad "User '$u' has an empty password"
            done
        else
            ok "No users with empty passwords"
        fi
    else
        info "Can't read /etc/shadow, skipping password check"
    fi

    login_users=$(awk -F: '$7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
    info "Users with a login shell: $(echo $login_users | tr ' ' ',')"

    for group in sudo wheel; do
        members=$(getent group "$group" | cut -d: -f4)
        if [ -n "$members" ]; then
            info "Members of $group: $members"
        fi
    done
}

check_permissions() {
    section "File permissions"

    for f in /etc/passwd /etc/group; do
        perms=$(stat -c %a "$f")
        if [ $((8#$perms & 8#022)) -ne 0 ]; then
            bad "$f is writable by group/others ($perms)"
        else
            ok "$f permissions are fine ($perms)"
        fi
    done

    for f in /etc/shadow /etc/gshadow /etc/sudoers; do
        [ -e "$f" ] || continue
        perms=$(stat -c %a "$f")
        if [ $((8#$perms & 8#007)) -ne 0 ]; then
            bad "$f is accessible by others ($perms)"
        else
            ok "$f permissions are fine ($perms)"
        fi
    done

    if [ -d /tmp ] && [ ! -k /tmp ]; then
        bad "/tmp doesn't have the sticky bit set"
    else
        ok "/tmp has the sticky bit set"
    fi

    ww=$(find /etc /usr /bin /sbin -xdev -type f -perm -0002 2>/dev/null)
    if [ -n "$ww" ]; then
        while read -r f; do
            bad "World-writable file: $f"
        done <<< "$ww"
    else
        ok "No world-writable files in system directories"
    fi

    known_suid="sudo su passwd chsh chfn newgrp gpasswd mount umount ping pkexec unix_chkpwd fusermount fusermount3 ssh-keysign Xorg.wrap dbus-daemon-launch-helper polkit-agent-helper-1 chage expiry newuidmap newgidmap sg chrome-sandbox"

    suid_files=$(find / -xdev -type f -perm -4000 2>/dev/null)
    info "Found $(echo "$suid_files" | grep -c .) SUID binaries"
    while read -r f; do
        [ -z "$f" ] && continue
        name=$(basename "$f")
        if ! echo " $known_suid " | grep -q " $name "; then
            warn "Unusual SUID binary: $f"
        fi
    done <<< "$suid_files"
}

check_users
check_permissions
