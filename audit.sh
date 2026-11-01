#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNINGS=0
FAILS=0
OUTPUT=""

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
bad()  { echo -e "  ${RED}[FAIL]${NC} $1"; FAILS=$((FAILS + 1)); }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

section() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
}

usage() {
    echo "Usage: $0 [-o file] [-h]"
    echo "  -o file   save the report to a file"
    echo "  -h        show this help"
}

while getopts "o:h" opt; do
    case $opt in
        o) OUTPUT="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [ -n "$OUTPUT" ]; then
    mkdir -p "$(dirname "$OUTPUT")"
    exec > >(tee >(sed -r 's/\x1b\[[0-9;]*m//g' > "$OUTPUT")) 2>&1
fi

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

check_updates() {
    section "Updates"

    if command -v apt >/dev/null; then
        updates=$(apt list --upgradable 2>/dev/null | grep -v "^Listing")
        security=$(echo "$updates" | grep -ci security)
    elif command -v dnf >/dev/null; then
        updates=$(dnf check-update -q 2>/dev/null | grep -v "^$")
        security=$(dnf updateinfo list --security -q 2>/dev/null | grep -c .)
    elif command -v pacman >/dev/null; then
        if command -v checkupdates >/dev/null; then
            updates=$(checkupdates 2>/dev/null)
        else
            updates=$(pacman -Qu 2>/dev/null)
        fi
        for helper in yay paru pikaur trizen; do
            if command -v "$helper" >/dev/null; then
                aur=$($helper -Qua 2>/dev/null | grep -c .)
                if [ "$aur" -gt 0 ]; then
                    warn "$aur AUR packages can be updated ($helper)"
                else
                    ok "AUR packages are up to date ($helper)"
                fi
                break
            fi
        done
    else
        info "Unsupported package manager, skipping"
        return
    fi

    count=$(echo "$updates" | grep -c .)
    if [ "$count" -gt 0 ]; then
        warn "$count packages can be updated"
    else
        ok "System is up to date"
    fi

    if [ -n "$security" ] && [ "$security" -gt 0 ]; then
        bad "$security security updates pending"
    fi

    if [ -f /var/run/reboot-required ]; then
        warn "A reboot is required to apply updates"
    elif [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
        warn "Running kernel differs from installed one, reboot needed"
    fi
}

check_services() {
    section "Services"

    if ! command -v systemctl >/dev/null; then
        info "systemd not found, skipping"
        return
    fi

    running=$(systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}')
    info "$(echo "$running" | grep -c .) services running"

    risky="telnet rsh rlogin rexec vsftpd proftpd tftp xinetd avahi-daemon cups rpcbind nfs-server smb snmpd"
    for svc in $risky; do
        if echo "$running" | grep -q "^$svc\.service"; then
            warn "Potentially unnecessary service running: $svc"
        fi
    done

    failed=$(systemctl list-units --type=service --state=failed --no-legend --plain | awk '{print $1}')
    for svc in $failed; do
        warn "Failed service: $svc"
    done

    if command -v ss >/dev/null; then
        while read -r addr; do
            case "$addr" in
                127.*|\[::1\]*) ;;
                0.0.0.0:*|\[::\]:*|\*:*) warn "TCP port open on all interfaces: $addr" ;;
                *) info "TCP port listening: $addr" ;;
            esac
        done < <(ss -tlnH | awk '{print $4}' | sort -u)
    fi
}

check_firewall() {
    section "Firewall"

    for fw in ufw firewalld nftables iptables; do
        if systemctl is-active --quiet "$fw" 2>/dev/null; then
            ok "Firewall active: $fw"
            return
        fi
    done

    bad "No active firewall found (ufw, firewalld, nftables, iptables)"
}

check_ssh() {
    section "SSH"

    if [ ! -f /etc/ssh/sshd_config ]; then
        info "sshd not installed, skipping"
        return
    fi

    if ! systemctl is-active --quiet sshd 2>/dev/null && ! systemctl is-active --quiet ssh 2>/dev/null; then
        info "SSH server is not running"
    fi

    if [ "$EUID" -eq 0 ] && command -v sshd >/dev/null; then
        config=$(sshd -T 2>/dev/null)
    else
        config=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v "^\s*#" | tr 'A-Z' 'a-z')
    fi

    root_login=$(echo "$config" | awk '$1 == "permitrootlogin" {print $2; exit}')
    case "$root_login" in
        yes) bad "PermitRootLogin is enabled" ;;
        no) ok "Root login is disabled" ;;
        *) warn "PermitRootLogin is '${root_login:-default}', consider setting it to no" ;;
    esac

    pass_auth=$(echo "$config" | awk '$1 == "passwordauthentication" {print $2; exit}')
    if [ "$pass_auth" = "no" ]; then
        ok "Password authentication is disabled"
    else
        warn "Password authentication is enabled, prefer key-based auth"
    fi

    empty=$(echo "$config" | awk '$1 == "permitemptypasswords" {print $2; exit}')
    [ "$empty" = "yes" ] && bad "PermitEmptyPasswords is enabled"

    port=$(echo "$config" | awk '$1 == "port" {print $2; exit}')
    info "SSH port: ${port:-22}"
}

check_users
check_permissions
check_updates
check_services
check_firewall
check_ssh

section "Summary"
echo -e "  ${RED}Failures: $FAILS${NC}"
echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}"
[ -n "$OUTPUT" ] && echo "  Report saved to $OUTPUT"

[ "$FAILS" -gt 0 ] && exit 2
[ "$WARNINGS" -gt 0 ] && exit 1
exit 0
