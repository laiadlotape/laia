#!/usr/bin/env bash
# Install LAIA Configurator GUI
# Run as root: sudo bash install.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/usr/local/lib/laia/gui/laia-configurator"

echo "=== Installing LAIA Security Configurator ==="
echo ""

# Verify root
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ This script must be run as root: sudo bash install.sh"
    exit 1
fi

# Install GTK3 Python bindings and libnotify
echo "Installing Python GTK3 dependencies..."
apt-get install -y -qq \
    python3-gi \
    python3-gi-cairo \
    gir1.2-gtk-3.0 \
    gir1.2-notify-0.7 \
    gir1.2-glib-2.0

echo "✅ Dependencies installed"

# Copy files to install location
echo "Installing LAIA Configurator to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/main.py" "$INSTALL_DIR/main.py"
chmod 755 "$INSTALL_DIR/main.py"

# Create desktop entry for application menu
cat > /usr/share/applications/laia-config.desktop << 'EOF'
[Desktop Entry]
Name=LAIA Security Configurator
GenericName=Security Configurator
Comment=Configure LAIA AI assistant security settings safely
Exec=python3 /usr/local/lib/laia/gui/laia-configurator/main.py
Icon=preferences-system-privacy
Terminal=false
Type=Application
Categories=Settings;Security;System;
StartupNotify=true
Keywords=security;privacy;ai;openclaw;laia;firewall;
EOF

echo "✅ Desktop entry created"

# Create command-line launcher
cat > /usr/local/bin/laia-config << 'EOF'
#!/usr/bin/env bash
# LAIA Security Configurator launcher
exec python3 /usr/local/lib/laia/gui/laia-configurator/main.py "$@"
EOF
chmod 755 /usr/local/bin/laia-config

echo "✅ Launcher created: /usr/local/bin/laia-config"
echo ""
echo "=== Installation Complete ==="
echo ""
echo "Launch from:"
echo "  • Terminal:          laia-config"
echo "  • Applications menu: LAIA Security Configurator"
echo "  • Direct:            python3 $INSTALL_DIR/main.py"
echo ""
echo "First-time setup:"
echo "  1. Open LAIA Security Configurator"
echo "  2. Review settings in the 'OpenClaw' tab"
echo "  3. Check 'System' tab — ensure AppArmor and fail2ban are active"
echo "  4. Run the security audit to see your score"
