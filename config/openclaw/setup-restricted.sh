#!/usr/bin/env bash
# Set up OpenClaw in LAIA restricted mode
#
# This script applies the LAIA-hardened OpenClaw configuration.
# It backs up any existing config before overwriting.
#
# Usage: bash setup-restricted.sh
# No root required — operates on ~/.openclaw/
set -e

OPENCLAW_CONFIG="$HOME/.openclaw/openclaw.json"
RESTRICTED_CONFIG="$(cd "$(dirname "$0")" && pwd)/openclaw-restricted.json"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"

echo "=== LAIA: OpenClaw Restricted Mode Setup ==="
echo ""

# Check if OpenClaw is installed
if ! command -v openclaw &>/dev/null; then
    echo "⚠️  OpenClaw not found in PATH."
    echo "   Install it with: npm install -g openclaw"
    echo "   Then run this script again."
    echo ""
    echo "   Copying restricted config to ~/.openclaw/ anyway for when you install..."
fi

# Create config directory if it doesn't exist
mkdir -p "$HOME/.openclaw"

# Back up existing config
if [[ -f "$OPENCLAW_CONFIG" ]]; then
    BACKUP="${OPENCLAW_CONFIG}.bak-${TIMESTAMP}"
    echo "⚠️  Backing up existing config:"
    echo "   $OPENCLAW_CONFIG → $BACKUP"
    cp "$OPENCLAW_CONFIG" "$BACKUP"
    echo ""
fi

# Apply restricted config
if [[ ! -f "$RESTRICTED_CONFIG" ]]; then
    echo "❌ Restricted config not found: $RESTRICTED_CONFIG"
    echo "   Run from the config/openclaw/ directory."
    exit 1
fi

cp "$RESTRICTED_CONFIG" "$OPENCLAW_CONFIG"
echo "✅ OpenClaw configured in LAIA restricted mode"
echo ""
echo "Settings applied:"
echo "  🔒 bind: 127.0.0.1 (localhost only)"
echo "  🔒 exec.ask: always (permission required for all commands)"
echo "  🔒 elevated: false (cannot run as root)"
echo "  🔒 browser: openclaw profile only (Chrome blocked)"
echo "  🔒 features: nodes, camera, location disabled"
echo "  🔒 notifications: none"
echo ""
echo "To adjust these settings safely, use the LAIA Configurator GUI:"
echo "   laia-config"
echo ""
echo "Current config: $OPENCLAW_CONFIG"

# Verify the config is valid JSON
if command -v python3 &>/dev/null; then
    if python3 -c "import json; json.load(open('$OPENCLAW_CONFIG'))" 2>/dev/null; then
        echo "✅ Config is valid JSON"
    else
        echo "⚠️  Config JSON validation failed — check the file"
    fi
fi

echo ""
echo "Restart OpenClaw to apply: openclaw restart"
