#!/usr/bin/env bash
# LAIA Firewall Configuration
# Policy: deny all incoming, allow all outgoing, exceptions below
#
# Based on principle of least privilege:
# - Block everything by default
# - Explicitly allow only what is needed
# - Rate-limit SSH to block brute force
# - Restrict local services to loopback only
#
set -e

echo "Configuring LAIA firewall..."

# Reset to clean state
ufw --force reset

# Default policies
ufw default deny incoming    # Block all inbound connections by default
ufw default allow outgoing   # Allow all outbound (web browsing, updates, etc.)
ufw default deny forward     # Block forwarding (we're not a router)

# Allow SSH with rate limiting — blocks brute force attacks.
# UFW rate limiting: deny connections if an IP makes 6+ connections in 30 seconds.
ufw limit ssh comment "SSH with rate limiting (anti-brute-force)"

# NOTE: UFW automatically handles stateful connection tracking via iptables.
# Established/related connections are always allowed so existing sessions
# are not interrupted by the deny-incoming default policy.

# -----------------------------------------------------------------------
# LOCAL-ONLY SERVICES (loopback only — never expose to network)
# -----------------------------------------------------------------------

# Ollama API — should NEVER be exposed to the network.
# The Ollama API has no authentication by default; anyone who can reach it
# can make arbitrary model inference requests and read/write model data.
ufw allow from 127.0.0.1 to any port 11434 comment "Ollama API - local only"

# OpenWebUI — web interface for Ollama.
# Same concern: no auth by default, local only.
ufw allow from 127.0.0.1 to any port 3000 comment "OpenWebUI - local only"

# OpenClaw gateway — AI assistant bridge.
# Must not be exposed to the network. Contains session tokens and tools.
ufw allow from 127.0.0.1 to any port 3101 comment "OpenClaw gateway - local only"

# -----------------------------------------------------------------------
# OPTIONAL RULES (uncomment as needed)
# -----------------------------------------------------------------------

# Local network printing (CUPS)
# Only uncomment if you have a network printer on your LAN.
# ufw allow from 192.168.0.0/16 to any port 631 comment "CUPS printing - LAN only"

# Local Samba file sharing
# ufw allow from 192.168.0.0/16 to any port 445 comment "Samba - LAN only"
# ufw allow from 192.168.0.0/16 to any port 139 comment "Samba NetBIOS - LAN only"

# mDNS (for .local hostnames and service discovery)
# ufw allow from 224.0.0.251 to any port 5353 comment "mDNS"

# -----------------------------------------------------------------------
# LOGGING AND ENABLE
# -----------------------------------------------------------------------

# Enable medium logging — captures blocked packets without flooding disk.
# Logs appear in /var/log/ufw.log
ufw logging medium

# Enable firewall (--force skips the interactive "are you sure?" prompt)
ufw --force enable

echo "✅ Firewall configured successfully"
echo ""
echo "Current rules:"
ufw status verbose
