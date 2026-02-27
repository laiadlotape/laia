#!/usr/bin/env bash
# Verify security configuration files exist and are valid
LAIA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Required security files
required=(
    "config/security/harden.sh"
    "config/security/ufw-rules.sh"
    "config/security/fail2ban-laia.conf"
    "config/security/sysctl-hardening.conf"
    "config/security/apparmor/ollama"
    "config/security/apparmor/openclaw"
)

for f in "${required[@]}"; do
    [[ -f "$LAIA_ROOT/$f" ]] || { echo "Missing: $f"; exit 1; }
done

# sysctl config must have at least 5 settings
SYSCTL_COUNT=$(grep -v '^#' "$LAIA_ROOT/config/security/sysctl-hardening.conf" | grep '=' | wc -l)
[[ $SYSCTL_COUNT -ge 5 ]] || exit 1

# harden.sh must be valid bash
bash -n "$LAIA_ROOT/config/security/harden.sh" || exit 1
bash -n "$LAIA_ROOT/config/security/ufw-rules.sh" || exit 1
