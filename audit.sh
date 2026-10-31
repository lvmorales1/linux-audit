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
