# LAIA Security Guide

## Philosophy

LAIA defaults are maximally restrictive. Every feature that could be a security risk
is disabled by default. You can enable things through the GUI with clear risk explanations.

The core principles:

1. **Default-deny** — block everything, explicitly allow only what's needed
2. **Least privilege** — each component gets the minimum access required to function
3. **Defense in depth** — multiple independent layers; if one fails, others remain
4. **Transparency** — every setting explains the security trade-off before you change it

---

## What's Hardened by Default

### Kernel (sysctl)
*File: `config/security/sysctl-hardening.conf`*

| Setting | What it does | Why it matters |
|---------|-------------|----------------|
| `kernel.randomize_va_space=2` | Full ASLR | Randomizes memory layout, defeating many exploits |
| `kernel.kptr_restrict=2` | Hide kernel pointers | Prevents kernel pointer leaks useful for exploit crafting |
| `kernel.dmesg_restrict=1` | Restrict kernel log | Hides sensitive info from the kernel ring buffer |
| `kernel.kexec_load_disabled=1` | Disable kexec | Prevents loading a malicious kernel at runtime |
| `kernel.yama.ptrace_scope=1` | Restrict ptrace | Prevents process injection between unrelated processes |
| `kernel.unprivileged_bpf_disabled=1` | Restrict eBPF | eBPF is a major kernel exploit vector |
| `fs.protected_symlinks=1` | Symlink protection | Blocks TOCTOU attacks via /tmp symlinks |
| `fs.protected_hardlinks=1` | Hardlink protection | Prevents hardlink attacks on setuid binaries |
| `fs.suid_dumpable=0` | No SUID core dumps | Setuid core dumps can leak privileged memory |
| `net.ipv4.tcp_syncookies=1` | SYN cookies | Protects against SYN flood DoS attacks |
| `net.ipv4.conf.all.accept_redirects=0` | No ICMP redirects | Prevents man-in-the-middle via ICMP redirect injection |
| `net.ipv4.conf.all.rp_filter=1` | Reverse path filter | Prevents IP spoofing attacks |
| `net.ipv4.tcp_timestamps=0` | No TCP timestamps | Prevents OS fingerprinting via uptime measurement |

### Firewall (UFW)
*File: `config/security/ufw-rules.sh`*

- All incoming connections **blocked by default**
- SSH allowed with **rate limiting** (blocks brute force — 6 connections/30s triggers ban)
- Ollama API (port 11434) — **localhost only** (no auth = must never be exposed)
- OpenWebUI (port 3000) — **localhost only**
- OpenClaw gateway (port 3101) — **localhost only**
- Medium logging enabled → `/var/log/ufw.log`
- Outgoing connections **allowed** (for web browsing, updates, API calls)

### fail2ban
*File: `config/security/fail2ban-laia.conf`*

| Jail | Trigger | Ban Duration |
|------|---------|-------------|
| `sshd` | 3 failed SSH logins | 24 hours |
| `sshd-ddos` | 6 rapid SSH connections | 1 hour |
| `openclaw` | 5 failed auth attempts | 1 hour |
| `pam-generic` | 3 PAM failures | 1 hour |

### AppArmor
*Files: `config/security/apparmor/`*

AppArmor uses **mandatory access control** — programs can only access what their
profile explicitly allows, even if the process is compromised.

**Ollama profile** restricts access to:
- ✅ Allow: Own model storage (`~/.ollama/`, `/usr/share/ollama/`)
- ✅ Allow: GPU devices (`/dev/dri/`, `/dev/nvidia*`)
- ✅ Allow: System hardware info (`/proc/meminfo`, `/sys/class/drm/`)
- ❌ Deny: Shadow/sudoers files
- ❌ Deny: All SSH keys
- ❌ Deny: Other users' home directories
- ❌ Deny: Execute from `/tmp`

**OpenClaw profile** restricts access to:
- ✅ Allow: `~/.openclaw/` (config and workspace)
- ✅ Allow: Network (API calls)
- ❌ Deny: `~/.ssh/`, `~/.gnupg/`
- ❌ Deny: Browser profiles (Chrome, Firefox, Brave)
- ❌ Deny: `~/Documents`, `~/Downloads`, `~/Desktop`
- ❌ Deny: `/proc/*/mem` (memory reading)
- ❌ Deny: Execute from `/tmp` or `/var/tmp`
- ❌ Deny: Write to `/etc`, `/usr`, `/bin`

### SSH
*Applied by `harden.sh`*

- Root login disabled (`PermitRootLogin no`)
- Maximum 3 auth attempts per connection
- X11, agent, and TCP forwarding disabled
- Empty passwords forbidden
- Strong ciphers only (ChaCha20-Poly1305, AES-256-GCM)
- Strong MACs only (HMAC-SHA2-512-ETM, HMAC-SHA2-256-ETM)

### OpenClaw Restricted Mode
*File: `config/openclaw/openclaw-restricted.json`*

| Setting | Value | Meaning |
|---------|-------|---------|
| `security.bind` | `127.0.0.1` | Only accessible from localhost |
| `exec.ask` | `always` | Permission required for every command |
| `exec.elevated` | `false` | Cannot run as root |
| `exec.security` | `allowlist` | Only allowed command patterns can run |
| `browser.blockChrome` | `true` | Cannot attach to your real Chrome profile |
| `features.nodes` | `false` | Device pairing disabled |
| `features.camera` | `false` | Camera access disabled |
| `features.location` | `false` | Location access disabled |
| `rateLimit.requestsPerMinute` | `20` | Throttled API usage |

---

## Configuring Security

Use the GUI — run `laia-config` from the terminal or Applications menu.

Every setting change shows a full explanation of the risk before applying.
Dangerous changes (like enabling root access) require explicit confirmation.

### Manual Configuration

If you prefer the terminal, edit `~/.openclaw/openclaw.json` directly, or:

```bash
# Apply default restricted config
bash config/openclaw/setup-restricted.sh

# Apply full system hardening (run as root)
sudo bash config/security/harden.sh
```

---

## Running a Security Audit

Install and run [lynis](https://cisofy.com/lynis/) for a comprehensive audit:

```bash
sudo apt-get install lynis
sudo lynis audit system
```

A score above **70** is acceptable. LAIA targets **80+**.

Common findings and fixes:
- **Low ASLR score**: Check `sysctl kernel.randomize_va_space` (should be `2`)
- **SSH warnings**: Run `harden.sh` to apply SSH hardening
- **AppArmor disabled**: `sudo systemctl enable --now apparmor`
- **Automatic updates off**: `sudo systemctl enable --now unattended-upgrades`

---

## Security Incident Response

If you suspect compromise:

1. **Isolate**: `sudo ufw default deny outgoing` (blocks all outbound)
2. **Check connections**: `ss -tulnp` and `netstat -an`
3. **Check processes**: `ps aux`, `htop`
4. **Check auth log**: `sudo tail -100 /var/log/auth.log`
5. **Check fail2ban**: `sudo fail2ban-client status`
6. **Check AppArmor denials**: `sudo dmesg | grep apparmor`
7. **Restore from backup** if needed

---

## Threat Model

LAIA is designed to protect against:

- ✅ **Remote attackers** — firewall blocks all inbound, fail2ban blocks brute force
- ✅ **AI model compromise** — AppArmor limits what Ollama can do even if exploited
- ✅ **AI assistant overreach** — OpenClaw restricted mode limits tool capabilities
- ✅ **Local privilege escalation** — kernel hardening, ptrace restrictions
- ✅ **Data exfiltration via AI** — AppArmor blocks document/key access from AI processes

LAIA does **not** fully protect against:
- ⚠️ **Physical access** — use full disk encryption (LUKS) for that
- ⚠️ **Malicious OS/firmware** — use Secure Boot + verified boot
- ⚠️ **Zero-day kernel exploits** — keep kernel updated

---

## Reporting Security Issues

Found a security vulnerability in LAIA?

1. **Do not** open a public GitHub issue
2. Email the project maintainers (see contact in README)
3. Include: description, reproduction steps, potential impact
4. Allow 90 days for a fix before public disclosure

We take security seriously and will respond within 48 hours.
