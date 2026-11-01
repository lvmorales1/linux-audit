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

check_users
