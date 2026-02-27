#!/usr/bin/env bash
# LAIA Security Hardening Script
# Applies all security configurations to the current system
#
# Based on:
#   - Arch Linux Security Wiki
#   - Madaidan's Linux Hardening Guide
#   - Debian Security Management documentation
#   - CIS Benchmarks for Linux
#
# Run as root: sudo bash harden.sh
# WARNING: Some settings may affect system usability. Review before applying.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="/var/log/laia-security.log"

# Color output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "[$(date '+%H:%M:%S')] ${GREEN}$*${NC}" | tee -a "$LOG"; }
warn() { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}[WARN]${NC} $*" | tee -a "$LOG"; }
err()  { echo -e "[$(date '+%H:%M:%S')] ${RED}[ERROR]${NC} $*" | tee -a "$LOG"; }

# Verify running as root
if [[ "$EUID" -ne 0 ]]; then
    err "This script must be run as root (sudo bash harden.sh)"
    exit 1
fi

# Verify this is Debian/Ubuntu
if ! command -v apt-get &>/dev/null; then
    err "This script is designed for Debian/Ubuntu systems with apt-get."
    exit 1
fi

log "=== LAIA Security Hardening ==="
log "Script dir: $SCRIPT_DIR"
log "Log file: $LOG"
log "This will apply hardened security settings to this system."
log "Some changes require reboot to take full effect."
echo ""

# -----------------------------------------------------------------------
# 1. Kernel parameters (sysctl)
# -----------------------------------------------------------------------
log "1/10 — Applying kernel hardening (sysctl)..."

if [[ -f "$SCRIPT_DIR/sysctl-hardening.conf" ]]; then
    cp "$SCRIPT_DIR/sysctl-hardening.conf" /etc/sysctl.d/99-laia-hardening.conf
    chmod 644 /etc/sysctl.d/99-laia-hardening.conf
    # Apply now — some params may not work on this kernel version, that's OK
    sysctl --system 2>/dev/null | grep -E "(laia|error)" | head -20 || true
    log "  Sysctl config deployed to /etc/sysctl.d/99-laia-hardening.conf"
else
    err "  sysctl-hardening.conf not found in $SCRIPT_DIR — skipping"
fi

# -----------------------------------------------------------------------
# 2. UFW Firewall
# -----------------------------------------------------------------------
log "2/10 — Configuring UFW firewall..."

apt-get install -y -qq ufw
if [[ -f "$SCRIPT_DIR/ufw-rules.sh" ]]; then
    bash "$SCRIPT_DIR/ufw-rules.sh"
else
    warn "  ufw-rules.sh not found — configuring basic UFW defaults"
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit ssh comment "SSH with rate limiting"
    ufw logging medium
    ufw --force enable
fi
log "  UFW firewall configured"

# -----------------------------------------------------------------------
# 3. fail2ban
# -----------------------------------------------------------------------
log "3/10 — Installing and configuring fail2ban..."

apt-get install -y -qq fail2ban

if [[ -f "$SCRIPT_DIR/fail2ban-laia.conf" ]]; then
    cp "$SCRIPT_DIR/fail2ban-laia.conf" /etc/fail2ban/jail.d/laia.conf
    chmod 644 /etc/fail2ban/jail.d/laia.conf
fi

# Create log directory for OpenClaw (fail2ban needs it to exist)
mkdir -p /var/log/openclaw
chown root:adm /var/log/openclaw
chmod 750 /var/log/openclaw

systemctl enable fail2ban
systemctl restart fail2ban
log "  fail2ban configured and running"

# -----------------------------------------------------------------------
# 4. AppArmor
# -----------------------------------------------------------------------
log "4/10 — Enabling AppArmor..."

apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra

# Ensure AppArmor is enabled at boot (kernel param)
if ! grep -q "apparmor=1" /etc/default/grub 2>/dev/null; then
    warn "  AppArmor boot parameters may not be set in GRUB — check /etc/default/grub"
    warn "  Add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX if not present"
fi

systemctl enable apparmor
systemctl start apparmor || warn "AppArmor already running"

# Put all standard profiles in enforce mode (best effort — some may not apply)
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# Install LAIA-specific profiles
if [[ -d "$SCRIPT_DIR/apparmor" ]]; then
    for profile in "$SCRIPT_DIR/apparmor/"*; do
        profile_name="$(basename "$profile")"
        dest="/etc/apparmor.d/$profile_name"
        cp "$profile" "$dest"
        chmod 644 "$dest"
        # Parse and load the profile
        apparmor_parser -r "$dest" 2>/dev/null && \
            aa-enforce "$dest" 2>/dev/null && \
            log "  Enforced AppArmor profile: $profile_name" || \
            warn "  Could not enforce $profile_name (binary may not exist yet — will apply when installed)"
    done
fi
log "  AppArmor configured"

# -----------------------------------------------------------------------
# 5. SSH hardening
# -----------------------------------------------------------------------
log "5/10 — Hardening SSH..."

mkdir -p /etc/ssh/sshd_config.d
SSHD_CONFIG="/etc/ssh/sshd_config.d/99-laia-hardening.conf"
cat > "$SSHD_CONFIG" << 'SSHEOF'
# LAIA SSH Hardening
# Applied by laia/config/security/harden.sh

# Never allow root to log in directly via SSH
# Root should only be accessible via su/sudo from a normal user account
PermitRootLogin no

# Allow both password and key-based authentication
# Consider setting PasswordAuthentication no once SSH keys are configured
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Limit login attempts — fail2ban handles banning, but this adds a backstop
MaxAuthTries 3

# Short grace period reduces exposure to connection-state exhaustion
LoginGraceTime 30

# Disable X11 forwarding — not needed and expands attack surface
X11Forwarding no

# Disable agent and TCP forwarding — reduces pivoting risk
AllowAgentForwarding no
AllowTcpForwarding no

# Never allow empty passwords
PermitEmptyPasswords no

# Disable older challenge-response auth (keep PAM only)
KbdInteractiveAuthentication no

# Use PAM for authentication
UsePAM yes

# Log last login info (useful for detecting unauthorized access)
PrintLastLog yes

# Use only strong ciphers and MACs
# (Remove old/weak algorithms)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
SSHEOF

chmod 644 "$SSHD_CONFIG"

# Test the config before restarting
if sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || warn "Could not restart SSH daemon"
    log "  SSH hardening applied"
else
    warn "  SSH config test failed — not restarting SSH (check $SSHD_CONFIG)"
fi

# -----------------------------------------------------------------------
# 6. Automatic security updates
# -----------------------------------------------------------------------
log "6/10 — Enabling automatic security updates..."

apt-get install -y -qq unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/50unattended-upgrades-laia << 'UEOF'
// LAIA Automatic Security Updates Configuration
// Only applies security updates automatically — other updates require manual review

Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Automatically fix interrupted dpkg runs
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Remove unused dependency packages after upgrade
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove unused automatically installed kernel-related packages
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Do NOT reboot automatically — user decides when to reboot
Unattended-Upgrade::Automatic-Reboot "false";

// Notify if a reboot is required
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Email on errors (requires sendmail)
// Unattended-Upgrade::Mail "admin@localhost";
// Unattended-Upgrade::MailOnlyOnError "true";

// Verbose logging
Unattended-Upgrade::Verbose "false";

// Enable dpkg output logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
UEOF

# Enable the periodic run
cat > /etc/apt/apt.conf.d/20auto-upgrades-laia << 'AEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AEOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
log "  Automatic security updates enabled"

# -----------------------------------------------------------------------
# 7. Disable unnecessary services
# -----------------------------------------------------------------------
log "7/10 — Disabling unnecessary services..."

# These services expand attack surface without being needed on most systems:
# - avahi-daemon: mDNS/zeroconf, can be used for network discovery
# - cups: printing daemon (disable if no printer needed)
# - bluetooth: disable if no Bluetooth devices used
declare -a SERVICES_TO_DISABLE=("avahi-daemon" "cups" "bluetooth")

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        systemctl disable "$svc" 2>/dev/null && \
            systemctl stop "$svc" 2>/dev/null && \
            log "  Disabled and stopped: $svc" || \
            warn "  Could not disable $svc"
    else
        log "  Already disabled: $svc"
    fi
done

# -----------------------------------------------------------------------
# 8. Restrict /proc (hidepid)
# -----------------------------------------------------------------------
log "8/10 — Restricting /proc visibility..."

# hidepid=2 hides other users' processes from /proc.
# Without this, any user can see what commands all other users are running,
# potentially leaking sensitive info from command-line arguments.

# Ensure proc group exists
groupadd -f proc

# Add users who should see all processes (e.g., monitoring tools) to the proc group
# usermod -aG proc prometheus  # example

if ! grep -q "hidepid" /etc/fstab; then
    echo "proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab
    # Try to apply now; if it fails, it'll apply after reboot
    mount -o remount,hidepid=2,gid=proc /proc 2>/dev/null && \
        log "  /proc remounted with hidepid=2" || \
        warn "  Cannot remount /proc now — hidepid=2 will apply after reboot"
else
    log "  /proc hidepid already configured in /etc/fstab"
fi

# -----------------------------------------------------------------------
# 9. Core dump restriction
# -----------------------------------------------------------------------
log "9/10 — Restricting core dumps..."

# Core dumps can contain passwords, keys, and other sensitive data from memory.
# For a hardened system, we want to disable them entirely.

# Via limits.conf
cat > /etc/security/limits.d/99-laia-nodumps.conf << 'LIMEOF'
# LAIA: Disable core dumps for all users
# Core dumps can expose sensitive memory contents (passwords, keys, tokens)
* soft core 0
* hard core 0
LIMEOF

# Via systemd (if applicable)
if [[ -d /etc/systemd ]]; then
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/laia.conf << 'COREOF'
[Coredump]
# Disable core dump storage
Storage=none
ProcessSizeMax=0
COREOF
fi

log "  Core dumps restricted"

# -----------------------------------------------------------------------
# 10. Password quality requirements
# -----------------------------------------------------------------------
log "10/10 — Setting password quality requirements..."

apt-get install -y -qq libpam-pwquality

cat > /etc/security/pwquality.conf << 'PWEOF'
# LAIA Password Quality Requirements
# Based on NIST SP 800-63B and CIS Benchmark recommendations
#
# Note: Modern guidance (NIST 2024) recommends length over complexity.
# These settings balance traditional complexity with minimum length.

# Minimum password length: 12 characters
# Longer passwords are exponentially harder to brute force
minlen = 12

# Require at least 1 digit
dcredit = -1

# Require at least 1 uppercase letter
ucredit = -1

# Require at least 1 lowercase letter
lcredit = -1

# Require at least 1 special character
ocredit = -1

# Require at least 3 character classes (upper, lower, digit, special)
minclass = 3

# Max 3 consecutive identical characters (prevents "aaaa" patterns)
maxrepeat = 3

# Require at least 8 characters to be different from old password
difok = 8

# Also enforce these requirements for root
enforce_for_root
PWEOF

log "  Password quality requirements configured"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
log "================================================================"
log "=== LAIA Security Hardening Complete ==="
log ""
log "Applied:"
log "  ✅ Kernel hardening (sysctl) → /etc/sysctl.d/99-laia-hardening.conf"
log "  ✅ UFW firewall (deny all in, SSH rate-limited)"
log "  ✅ fail2ban (SSH brute-force protection)"
log "  ✅ AppArmor (mandatory access control)"
log "  ✅ SSH hardening (no root login, strong ciphers)"
log "  ✅ Automatic security updates"
log "  ✅ Unnecessary services disabled"
log "  ✅ /proc restricted (hidepid=2)"
log "  ✅ Core dumps disabled"
log "  ✅ Password quality requirements"
log ""
warn "⚠️  REBOOT RECOMMENDED to apply all kernel and sysctl changes"
log "📊 Run 'sudo lynis audit system' for a security audit score (target: 80+)"
log "📋 Full log: $LOG"
log "================================================================"
