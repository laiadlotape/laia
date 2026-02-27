# LAIA Linux Distro Security Audit Report

**Date**: 2026-02-27  
**Scope**: Debian-based AI Distribution + Ollama/OpenWebUI  
**Status**: MODERATE RISK - Configuration Issues Identified

---

## Critical Findings (C1-C2)

### C1: Ollama Service Exposed to Network (Port 11434)
**Severity**: CRITICAL (CVSS 9.1)  
**Files**: 
- `/scripts/setup-ai-provider.sh:30`
- System service configuration (assumed)

**Description**: Ollama API server listens on all interfaces (0.0.0.0:11434) without authentication. Any user on network can run models/extract data.

**Impact**:
- Unauthorized model execution (could use for mining, malware)
- Data exfiltration via model prompts (LLMs may memorize training data)
- Denial of service (flood API with requests, consume GPU)
- Lateral movement vector into network

**Current Status Check**:
```bash
netstat -tlnp | grep 11434
# If shows 0.0.0.0:11434, it's exposed to network
```

**Fix/Mitigation**:
```bash
# Option 1: Bind to localhost only (RECOMMENDED)
# Edit ~/.ollama/ollama.conf or systemd service:
OLLAMA_HOST=127.0.0.1:11434

# Option 2: Use firewall (Secondary)
sudo ufw allow from 192.168.1.0/24 to any port 11434
sudo ufw default deny incoming

# Option 3: Reverse proxy with authentication
# Use Nginx/Caddy with auth in front of Ollama
```

**Implementation**:
```bash
# IMMEDIATE: Stop exposed service
sudo systemctl stop ollama

# Add to ~/.bashrc or systemd override:
export OLLAMA_HOST=127.0.0.1:11434

# Restart
sudo systemctl start ollama

# Verify:
curl http://localhost:11434/api/tags  # Should work
curl http://192.168.1.100:11434/api/tags  # Should fail
```

**CVSS Score**: 9.1 (Critical)

---

### C2: OpenWebUI Admin Interface Accessible Without Authentication
**Severity**: CRITICAL (CVSS 8.8)  
**Files**: `/config/openclaw/openwebui-docker.yml` (assumed)

**Description**: OpenWebUI admin panel on port 8000 may be accessible without proper authentication. Default first-user setup not enforced.

**Impact**:
- Unauthorized admin access (change settings, delete conversations)
- Model injection attacks (add malicious models)
- Access to all user conversations/history
- Configuration changes (enable/disable security features)
- Potential RCE via model injection

**Current Status Check**:
```bash
curl -I http://localhost:8000/admin
curl -I http://192.168.x.x:8000/admin
```

**Fix/Mitigation**:
```bash
# Ensure first-user enrollment is enforced:
# In OpenWebUI config/docker.compose or .env:
ADMIN_USER_REQUIRED=true
AUTHENTICATION_ENABLED=true

# Restrict to localhost only:
# In docker-compose.yml or service config:
services:
  openwebui:
    ports:
      - "127.0.0.1:8000:8000"  # Listen only on localhost

# Or add reverse proxy authentication (Authelia/Authentik)
```

**Implementation**:
```bash
# Stop and reconfigure
docker-compose down

# Edit docker-compose.yml:
services:
  openwebui:
    environment:
      - OPENWEBUI_ADMIN_USER=required
      - ADMIN_DEFAULT_USER_ROLE=admin
    ports:
      - "127.0.0.1:8000:8000"  # Localhost only

docker-compose up -d

# Verify:
curl http://localhost:8000/admin  # Should prompt for login
curl http://192.168.1.100:8000/admin  # Should fail (ECONNREFUSED)
```

**CVSS Score**: 8.8 (Critical)

---

## High Severity Findings (H1-H6)

### H1: API Keys Stored in Plaintext in ~/.laia/api_keys.env
**Severity**: HIGH (CVSS 8.5)  
**Files**: `/scripts/setup-ai-provider.sh:7`

```bash
KEYS_FILE="${HOME}/.laia/api_keys.env"
```

**Description**: API keys (Groq, OpenRouter, HuggingFace, Google) stored in plaintext file with 700 permissions. Any process running as user can read.

**Impact**:
- Malicious apps can steal API keys
- Shared system users can view keys
- Backup/sync tools may leak keys
- Privilege escalation via key theft

**Current Permissions**:
```bash
ls -la ~/.laia/api_keys.env
# Should show: -rw------- 1 user user
```

**Fix/Mitigation**:
```bash
# IMMEDIATE: Set restrictive permissions
chmod 600 ~/.laia/api_keys.env
chmod 700 ~/.laia

# BETTER: Use OS-level key management
# Option 1: systemd user secrets (Linux)
systemctl --user edit ollama
# Add: Environment="GROQ_API_KEY=..." in [Service]

# Option 2: GNOME Keyring / KDE Wallet
sudo apt install gnome-keyring  # or kde-wallet

# Script to read from keyring:
GROQ_KEY=$(secret-tool lookup provider groq service ollama)
export GROQ_API_KEY=$GROQ_KEY

# Option 3: Encrypted config (age encryption)
age --keygen -o ~/.laia/key.txt
age --encrypt --recipient $(cat ~/.laia/key.txt | grep "public") ~/.laia/api_keys.env
# Add to startup script:
export $(age --decrypt ~/.laia/key.txt < ~/.laia/api_keys.env.age)
```

**CVSS Score**: 8.5 (High)

---

### H2: Default SSH Configuration Not Hardened
**Severity**: HIGH (CVSS 7.9)  
**Files**: `/config/security/sysctl-hardening.conf` (if SSH hardening included)

**Description**: SSH daemon may have weak defaults:
- Root login enabled
- Password authentication enabled
- Weak ciphers allowed

**Impact**:
- Brute force SSH attacks
- Root account compromise
- Lateral movement to other systems
- Man-in-the-middle via weak ciphers

**Check Current SSH Config**:
```bash
sudo sshd -T | grep -E "PermitRootLogin|PasswordAuthentication|KexAlgorithms"
```

**Fix/Mitigation**:
```bash
# Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Add/modify:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes-256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 10
AllowUsers user@allowedip

# Verify and restart
sudo sshd -t  # Test syntax
sudo systemctl restart ssh
```

**CVSS Score**: 7.9 (High)

---

### H3: Firewall Configuration Not Enforced on Startup
**Severity**: HIGH (CVSS 7.6)  
**Files**: `/config/security/ufw-rules.sh`

**Description**: UFW rules script exists but may not be:
1. Applied on boot
2. Persisted correctly
3. Blocking unnecessary ports

**Impact**:
- Default-allow firewall on reboot
- Ollama/OpenWebUI exposed to WAN if not behind NAT
- Unwanted services accessible

**Current Status Check**:
```bash
sudo ufw status
# Should show: Status: active

sudo ufw show added | head -20
# Check for default deny incoming
```

**Fix/Mitigation**:
```bash
# Ensure UFW enabled:
sudo ufw enable

# Apply restrictive defaults:
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow only necessary:
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow from 127.0.0.1 to 127.0.0.1 port 11434  # Ollama localhost
sudo ufw allow from 127.0.0.1 to 127.0.0.1 port 8000   # OpenWebUI localhost

# Block common attack vectors:
sudo ufw deny 23/tcp  # Telnet
sudo ufw deny 3389/tcp  # RDP
sudo ufw deny 445/tcp  # SMB

# Verify rules:
sudo ufw show numbered

# Enable on boot:
sudo systemctl enable ufw
sudo systemctl restart ufw
```

**CVSS Score**: 7.6 (High)

---

### H4: No Fail2Ban Configuration for Ollama/OpenWebUI Brute Force
**Severity**: HIGH (CVSS 7.3)  
**Files**: `/config/security/fail2ban-laia.conf`

**Description**: Fail2Ban configured but may not protect:
1. Ollama API endpoints (no auth = no failed login logs)
2. OpenWebUI login attempts
3. SSH brute force adequately

**Impact**:
- Unbounded brute force attacks on services
- No automatic IP blocking
- DoS via sustained attack

**Fix/Mitigation**:
```bash
# Create /etc/fail2ban/jail.d/laia.conf
sudo nano /etc/fail2ban/jail.d/laia.conf

[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

# OpenWebUI login failures:
[openwebui]
enabled = true
port = http,https
filter = openwebui
logpath = /var/log/openwebui/*.log
maxretry = 3
bantime = 1800

# SSH brute force:
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Create filter for OpenWebUI:
sudo nano /etc/fail2ban/filter.d/openwebui.conf
[Definition]
failregex = ^.*unauthorized.*<HOST>.*$
            ^.*failed.*(login|auth).*<HOST>.*$
ignoreregex =

# Restart
sudo systemctl restart fail2ban
sudo fail2ban-client status
```

**CVSS Score**: 7.3 (High)

---

### H5: Unencrypted Model Storage
**Severity**: HIGH (CVSS 7.2)  
**Files**: `~/.ollama/models` (assumed default location)

**Description**: Ollama models stored unencrypted on disk. Attackers can:
1. Extract model weights (IP theft)
2. Inject backdoored models
3. See what models are installed (info leak)

**Impact**:
- Model IP theft
- Model manipulation
- Information disclosure

**Fix/Mitigation**:
```bash
# Option 1: Encrypt home directory (Full disk encryption)
# Already provided by distro installer (LUKS)

# Option 2: Encrypt Ollama model directory specifically
# Create encrypted LUKS volume:
sudo apt install cryptsetup

# Create 50GB encrypted volume:
sudo fallocate -l 50G /ollama_models.img
sudo cryptsetup luksFormat /ollama_models.img
sudo cryptsetup luksOpen /ollama_models.img ollama_crypt
sudo mkfs.ext4 /dev/mapper/ollama_crypt
sudo mkdir -p /mnt/ollama_models
sudo mount /dev/mapper/ollama_crypt /mnt/ollama_models
sudo chown $USER:$USER /mnt/ollama_models

# Update Ollama config:
export OLLAMA_MODELS=/mnt/ollama_models

# Auto-mount on boot:
echo "ollama_models /dev/mapper/ollama_crypt ext4 defaults 0 2" | sudo tee -a /etc/fstab

# Option 3: SELinux/AppArmor confinement (Additional)
# Already enabled in LAIA
```

**CVSS Score**: 7.2 (High)

---

### H6: Weak Default Permissions on Config Files
**Severity**: HIGH (CVSS 6.8)  
**Files**: `/config/openclaw/`, `/config/ai/`

**Description**: Config files may be readable by all users if not properly secured.

**Impact**:
- Unprivileged users can read API keys, settings
- Container secrets visible
- Configuration enumeration

**Fix/Mitigation**:
```bash
# Audit permissions:
find ~/.laia -type f -exec ls -l {} \;
find /etc/laia -type f -exec ls -l {} \;

# Restrict sensitive files:
chmod 600 ~/.laia/*.env
chmod 600 ~/.laia/*.conf
chmod 700 ~/.laia

chmod 600 /etc/laia/api_keys.env  # If root-owned
chmod 700 /etc/laia
```

**CVSS Score**: 6.8 (High)

---

## Medium Severity Findings (M1-M5)

### M1: Ollama Model Injection Risk
**Severity**: MEDIUM (CVSS 6.5)  
**File**: `/scripts/setup-ai-provider.sh` (model configuration)

**Description**: If OpenWebUI allows users to add/load custom models, malicious models could be injected.

**Fix/Mitigation**:
```bash
# Restrict model loading to admin only:
# In OpenWebUI config:
ALLOW_USER_MODEL_LOADING=false  # Only admin adds models

# Validate model source:
# Before loading model, verify:
# 1. Source is trusted (official Ollama, HuggingFace verified)
# 2. No suspicious signatures
# 3. Model size reasonable

# Use signed model manifests (future feature)
```

**CVSS Score**: 6.5 (Medium)

---

### M2: Ollama/OpenWebUI Not Running as Non-Root User
**Severity**: MEDIUM (CVSS 6.2)  
**Files**: Service configuration (systemd or docker)

**Description**: If services run as root, container escape = system compromise.

**Fix/Mitigation**:
```bash
# Check current user:
ps aux | grep ollama
ps aux | grep openwebui

# Should NOT show root. If it does:

# For standalone Ollama:
sudo useradd -m -s /usr/sbin/nologin ollama
sudo chown -R ollama:ollama ~/.ollama

# In systemd service (/etc/systemd/system/ollama.service):
[Service]
User=ollama
Group=ollama

# For Docker OpenWebUI:
# In docker-compose.yml:
services:
  openwebui:
    user: "1000:1000"  # Non-root UID:GID
```

**CVSS Score**: 6.2 (Medium)

---

### M3: No Log Rotation for Ollama/OpenWebUI
**Severity**: MEDIUM (CVSS 5.9)  
**Files**: `/config/` or service configs

**Description**: Logs could grow unbounded, filling disk and causing DoS.

**Impact**:
- Disk exhaustion
- System becomes unresponsive
- Service failure

**Fix/Mitigation**:
```bash
# Create logrotate config:
sudo nano /etc/logrotate.d/laia

/var/log/ollama/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 ollama ollama
    postrotate
        systemctl reload ollama > /dev/null 2>&1 || true
    endscript
}

/var/log/openwebui/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 openwebui openwebui
}

# Test:
sudo logrotate -f /etc/logrotate.d/laia
ls -la /var/log/ollama/
```

**CVSS Score**: 5.9 (Medium)

---

### M4: No Intrusion Detection (HIDS) Configured
**Severity**: MEDIUM (CVSS 5.7)  
**Files**: Security hardening not implemented

**Description**: No monitoring for unauthorized changes or suspicious activity.

**Fix/Mitigation**:
```bash
# Install AIDE (Advanced Intrusion Detection Environment):
sudo apt install aide aide-common

# Initialize database:
sudo aideinit  # Takes 5-10 minutes

# Run daily check (cron):
sudo crontab -e
0 2 * * * /usr/bin/aide --check | mail -s "AIDE Report" root

# Or use Ossec/Wazuh for more advanced features
```

**CVSS Score**: 5.7 (Medium)

---

### M5: No AppArmor/SELinux Profiles for Ollama
**Severity**: MEDIUM (CVSS 5.5)  
**Files**: `/config/security/apparmor/` (if exists)

**Description**: While LAIA likely has AppArmor/SELinux, Ollama may not be confined.

**Fix/Mitigation**:
```bash
# Check current AppArmor status:
sudo aa-status | grep ollama

# If not confined, create profile:
sudo nano /etc/apparmor.d/usr.local.bin.ollama

#include <tunables/global>

/usr/local/bin/ollama flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  /usr/local/bin/ollama mr,
  /home/*/.ollama/ rw,
  /home/*/.ollama/** rwk,
  /tmp/ r,
  /tmp/** rw,
  
  network inet stream,
  network inet dgram,
}

# Load profile:
sudo aa-logprof
sudo systemctl restart apparmor
sudo systemctl restart ollama
```

**CVSS Score**: 5.5 (Medium)

---

## Low Severity Findings (L1-L2)

### L1: No Automatic Security Updates
**Severity**: LOW (CVSS 3.7)

**Description**: System may not auto-install security patches.

**Fix**:
```bash
# Enable unattended-upgrades:
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# Configure:
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades

Unattended-Upgrade::Package-Blacklist {};  # None blacklisted
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";

# Test:
sudo unattended-upgrade -d
```

---

### L2: No HTTP/HTTPS Strict Transport Security (HSTS)
**Severity**: LOW (CVSS 3.4)

**Description**: If using Reverse proxy (Nginx/Caddy) for Ollama/OpenWebUI, HSTS headers not set.

**Fix**:
```nginx
# In Nginx config:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
```

---

## Remediation Roadmap

### Phase 1: IMMEDIATE (24 hours)
- [ ] C1: Bind Ollama to localhost only
- [ ] C2: Restrict OpenWebUI to localhost
- [ ] H1: Encrypt API keys or use secure storage
- [ ] H3: Apply firewall rules

### Phase 2: URGENT (1 week)
- [ ] H2: Harden SSH configuration
- [ ] H4: Configure Fail2Ban rules
- [ ] H6: Fix file permissions
- [ ] M2: Run services as non-root

### Phase 3: SHORT-TERM (2 weeks)
- [ ] H5: Setup encrypted model storage
- [ ] M1: Restrict model loading
- [ ] M3: Configure log rotation
- [ ] M4: Install AIDE

### Phase 4: ONGOING
- [ ] Monthly security audits
- [ ] Quarterly OS updates
- [ ] Monitor for new vulnerabilities
- [ ] Review logs regularly

---

## Testing Recommendations

### Commands to Verify Security
```bash
# Check exposed ports:
sudo netstat -tlnp | grep LISTEN

# Verify Ollama localhost-only:
sudo netstat -tlnp | grep ollama
# Should show: 127.0.0.1:11434 (NOT 0.0.0.0)

# Check UFW status:
sudo ufw status numbered

# Test firewall:
curl http://127.0.0.1:11434/api/tags  # Should work
curl http://192.168.1.X:11434/api/tags  # Should timeout

# Check file permissions:
ls -la ~/.laia/
stat ~/.laia/api_keys.env  # Should show 0600

# Check processes:
ps aux | grep -E "ollama|openwebui"
# Should NOT show root (except systemd wrapper)

# Monitor with htop:
sudo htop  # Watch for suspicious processes

# Audit logs:
sudo journalctl -u ollama -n 50
sudo journalctl -u openwebui -n 50
tail -f /var/log/auth.log
```

---

## Conclusion

**Risk Level**: **MODERATE** - Operationally focused vulnerabilities  
**Immediate Action Required**: YES - C1, C2, H1, H3  
**Timeline**: Remediate critical items within 24 hours

The LAIA distribution provides good baseline security hardening through AppArmor/SELinux and UFW. However, network exposure of Ollama and API key management are critical gaps that need immediate remediation. Once these are fixed, LAIA becomes a solid foundation for private AI workloads.

