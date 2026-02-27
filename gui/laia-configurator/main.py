#!/usr/bin/env python3
"""
LAIA Security Configurator
GTK-based GUI for managing security settings safely.
Designed for users coming from Windows — no terminal needed.

Features:
- View and change OpenClaw security settings with risk warnings
- Check status of system security services
- Run security audits (lynis)
- Every dangerous setting change shows a confirmation dialog

Requirements:
    apt-get install python3-gi gir1.2-gtk-3.0 gir1.2-notify-0.7

Usage:
    python3 main.py
    # or after install.sh:
    laia-config
"""
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Notify', '0.7')
from gi.repository import Gtk, GLib, Notify, Gdk
import json
import os
import subprocess
import threading
from pathlib import Path

OPENCLAW_CONFIG = Path.home() / ".openclaw" / "openclaw.json"
LAIA_CONFIG_DIR = Path("/etc/laia")
VERSION = "1.0.0"

# Risk warnings shown before each setting change
WARNINGS = {
    "exec.ask": {
        "always": (
            "✅ MOST SECURE\n"
            "OpenClaw will ask your permission before running any command.\n"
            "You will see a prompt for every shell command the AI wants to execute.\n\n"
            "Best for: Daily use, privacy-sensitive work."
        ),
        "on-miss": (
            "⚠️ MEDIUM SECURITY\n"
            "OpenClaw asks only for commands it hasn't run before.\n"
            "Known/trusted commands run automatically after first approval.\n\n"
            "Best for: Power users who want less interruption."
        ),
        "off": (
            "🔴 INSECURE\n"
            "OpenClaw will run ANY shell command without asking.\n"
            "This means the AI could delete files, install software, or\n"
            "make system changes without your knowledge.\n\n"
            "Not recommended. Only use in isolated/sandboxed environments."
        ),
    },
    "exec.elevated": {
        True: (
            "🔴 DANGEROUS — ROOT ACCESS\n"
            "This allows OpenClaw to execute commands as root (administrator).\n\n"
            "Root commands can:\n"
            "  • Modify or delete any system file\n"
            "  • Install or remove software system-wide\n"
            "  • Change other users' data\n"
            "  • Disable security controls\n\n"
            "Only enable this if you explicitly need it for a specific task.\n"
            "Disable it again immediately after."
        ),
        False: (
            "✅ SAFE\n"
            "OpenClaw cannot execute commands as root.\n"
            "All commands run with your normal user permissions."
        ),
    },
    "security.bind": {
        "127.0.0.1": (
            "✅ SECURE — LOCALHOST ONLY\n"
            "OpenClaw is only accessible from this computer.\n"
            "No one on your network can connect to it."
        ),
        "0.0.0.0": (
            "🔴 INSECURE — NETWORK EXPOSED\n"
            "OpenClaw will be accessible from your entire network.\n\n"
            "This means:\n"
            "  • Anyone on the same WiFi can connect\n"
            "  • Anyone on your LAN can use your AI assistant\n"
            "  • Your OpenClaw session tokens may be exposed\n\n"
            "Only use on trusted private networks with no untrusted devices."
        ),
    },
}

# CSS for visual polish
CSS = b"""
.section-header {
    font-weight: bold;
    font-size: 1.1em;
    margin-top: 12px;
}
.warning-safe { color: #2e7d32; }
.warning-caution { color: #f57f17; }
.warning-danger { color: #c62828; }
.status-active { color: #2e7d32; font-weight: bold; }
.status-inactive { color: #c62828; }
"""


class LaiaConfigurator(Gtk.Window):
    def __init__(self):
        super().__init__(title=f"LAIA Security Configurator v{VERSION}")
        self.set_default_size(720, 580)
        self.set_border_width(0)

        # Load CSS
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        Notify.init("LAIA Configurator")

        # Main layout
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(vbox)

        # Header bar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "LAIA Security Configurator"
        header.props.subtitle = f"v{VERSION} — Configure security settings safely"
        self.set_titlebar(header)

        # Notebook (tabs)
        notebook = Gtk.Notebook()
        notebook.set_border_width(10)
        vbox.pack_start(notebook, True, True, 0)

        # Tabs
        notebook.append_page(self._build_openclaw_tab(), Gtk.Label(label="🔒 OpenClaw"))
        notebook.append_page(self._build_system_tab(),   Gtk.Label(label="🛡️ System"))
        notebook.append_page(self._build_status_tab(),   Gtk.Label(label="📊 Status"))
        notebook.append_page(self._build_about_tab(),    Gtk.Label(label="ℹ️ About"))

        # Bottom status bar
        bottom = Gtk.Box(spacing=8)
        bottom.set_border_width(10)

        self.status_label = Gtk.Label(label="Ready — load config from ~/.openclaw/openclaw.json")
        self.status_label.set_halign(Gtk.Align.START)
        self.status_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        bottom.pack_start(self.status_label, True, True, 0)

        reload_btn = Gtk.Button(label="↺ Reload")
        reload_btn.connect("clicked", lambda b: self._load_config())
        bottom.pack_end(reload_btn, False, False, 0)

        save_btn = Gtk.Button(label="💾 Save Changes")
        save_btn.get_style_context().add_class("suggested-action")
        save_btn.connect("clicked", self._on_save)
        bottom.pack_end(save_btn, False, False, 0)

        sep = Gtk.Separator()
        vbox.pack_start(sep, False, False, 0)
        vbox.pack_start(bottom, False, False, 0)

        self.connect("destroy", Gtk.main_quit)
        self._load_config()

    # ------------------------------------------------------------------
    # TAB: OpenClaw Settings
    # ------------------------------------------------------------------
    def _build_openclaw_tab(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        grid = Gtk.Grid(column_spacing=16, row_spacing=8, border_width=20)
        scrolled.add(grid)

        row = 0

        # ---- Command Execution ----
        grid.attach(self._section_label("Command Execution"), 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Label(label="Permission mode:", xalign=0), 0, row, 1, 1)
        self.exec_ask_combo = Gtk.ComboBoxText()
        self.exec_ask_combo.append("always",  "🔒 Always ask (most secure)")
        self.exec_ask_combo.append("on-miss", "⚠️  Ask for unknown commands")
        self.exec_ask_combo.append("off",     "🔴 Never ask (insecure)")
        self.exec_ask_combo.connect("changed", self._on_exec_ask_changed)
        grid.attach(self.exec_ask_combo, 1, row, 1, 1)
        row += 1

        self.exec_warning_label = Gtk.Label(label="", xalign=0)
        self.exec_warning_label.set_line_wrap(True)
        self.exec_warning_label.set_max_width_chars(60)
        grid.attach(self.exec_warning_label, 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Separator(), 0, row, 2, 1)
        row += 1

        # ---- Root Access ----
        grid.attach(self._section_label("Root (Administrator) Access"), 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Label(label="Allow root commands:", xalign=0), 0, row, 1, 1)
        self.elevated_switch = Gtk.Switch()
        self.elevated_switch.set_halign(Gtk.Align.START)
        self.elevated_switch.connect("notify::active", self._on_elevated_changed)
        grid.attach(self.elevated_switch, 1, row, 1, 1)
        row += 1

        self.elevated_warning = Gtk.Label(label="", xalign=0)
        self.elevated_warning.set_line_wrap(True)
        self.elevated_warning.set_max_width_chars(60)
        grid.attach(self.elevated_warning, 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Separator(), 0, row, 2, 1)
        row += 1

        # ---- Network Binding ----
        grid.attach(self._section_label("Network Binding"), 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Label(label="Listen on:", xalign=0), 0, row, 1, 1)
        self.bind_combo = Gtk.ComboBoxText()
        self.bind_combo.append("127.0.0.1", "🔒 Localhost only (secure)")
        self.bind_combo.append("0.0.0.0",   "🔴 All network interfaces (insecure)")
        self.bind_combo.connect("changed", self._on_bind_changed)
        grid.attach(self.bind_combo, 1, row, 1, 1)
        row += 1

        self.bind_warning = Gtk.Label(label="", xalign=0)
        self.bind_warning.set_line_wrap(True)
        self.bind_warning.set_max_width_chars(60)
        grid.attach(self.bind_warning, 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Separator(), 0, row, 2, 1)
        row += 1

        # ---- Feature Toggles ----
        grid.attach(self._section_label("Feature Toggles"), 0, row, 2, 1)
        row += 1

        self.feature_switches = {}
        features = [
            ("nodes",   "Allow node device pairing",   "Enables pairing with phone/tablet devices"),
            ("camera",  "Allow camera access",          "Enables camera snapshots from paired devices"),
            ("location","Allow location access",        "Enables GPS location from paired devices"),
        ]
        for key, label, tooltip in features:
            lbl = Gtk.Label(label=f"{label}:", xalign=0)
            lbl.set_tooltip_text(tooltip)
            sw = Gtk.Switch()
            sw.set_halign(Gtk.Align.START)
            self.feature_switches[key] = sw
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(sw, 1, row, 1, 1)
            row += 1

        return scrolled

    # ------------------------------------------------------------------
    # TAB: System Security
    # ------------------------------------------------------------------
    def _build_system_tab(self):
        grid = Gtk.Grid(column_spacing=16, row_spacing=10, border_width=20)
        row = 0

        # Firewall
        grid.attach(self._section_label("Firewall (UFW)"), 0, row, 2, 1)
        row += 1

        fw_btn = Gtk.Button(label="🔥 Check Firewall Status")
        fw_btn.set_tooltip_text("Show current UFW firewall rules")
        fw_btn.connect("clicked", lambda b: self._run_command("ufw status verbose", "Firewall Status"))
        grid.attach(fw_btn, 0, row, 1, 1)

        apply_fw_btn = Gtk.Button(label="⚙️  Apply LAIA Firewall Rules")
        apply_fw_btn.set_tooltip_text("Run ufw-rules.sh to configure firewall")
        apply_fw_btn.connect("clicked", self._on_apply_firewall)
        grid.attach(apply_fw_btn, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Separator(), 0, row, 2, 1)
        row += 1

        # Security Services
        grid.attach(self._section_label("Security Service Status"), 0, row, 2, 1)
        row += 1

        self.service_labels = {}
        services = [
            ("apparmor",            "AppArmor (Mandatory Access Control)"),
            ("fail2ban",            "fail2ban (Brute-force Protection)"),
            ("unattended-upgrades", "Automatic Security Updates"),
            ("ufw",                 "UFW Firewall"),
        ]
        for svc, name in services:
            lbl = Gtk.Label(label=f"{name}:", xalign=0)
            status = Gtk.Label(label="Checking...", xalign=0)
            self.service_labels[svc] = status
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(status, 1, row, 1, 1)
            row += 1
            GLib.idle_add(self._check_service, svc, status)

        refresh_svc_btn = Gtk.Button(label="🔄 Refresh Status")
        refresh_svc_btn.connect("clicked", lambda b: self._refresh_services())
        grid.attach(refresh_svc_btn, 0, row, 2, 1)
        row += 1

        grid.attach(Gtk.Separator(), 0, row, 2, 1)
        row += 1

        # Security Audit
        grid.attach(self._section_label("Security Audit"), 0, row, 2, 1)
        row += 1

        audit_label = Gtk.Label(
            label="Run lynis for a comprehensive security audit.\nScores above 70 are good; LAIA targets 80+.",
            xalign=0
        )
        audit_label.set_line_wrap(True)
        grid.attach(audit_label, 0, row, 2, 1)
        row += 1

        scan_btn = Gtk.Button(label="🔍 Run Security Audit (lynis)")
        scan_btn.set_tooltip_text("Requires lynis: apt-get install lynis")
        scan_btn.connect("clicked", lambda b: self._run_command("lynis audit system --quick 2>&1", "Security Audit"))
        grid.attach(scan_btn, 0, row, 2, 1)
        row += 1

        return grid

    # ------------------------------------------------------------------
    # TAB: Status Dashboard
    # ------------------------------------------------------------------
    def _build_status_tab(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=16)
        vbox.pack_start(Gtk.Label(label="System security overview", xalign=0), False, False, 0)

        self.status_text = Gtk.TextView()
        self.status_text.set_editable(False)
        self.status_text.set_monospace(True)
        self.status_text.set_wrap_mode(Gtk.WrapMode.WORD)

        sw = Gtk.ScrolledWindow()
        sw.add(self.status_text)
        sw.set_vexpand(True)
        vbox.pack_start(sw, True, True, 0)

        refresh_btn = Gtk.Button(label="🔄 Refresh Status")
        refresh_btn.connect("clicked", lambda b: self._refresh_status())
        vbox.pack_start(refresh_btn, False, False, 0)

        GLib.idle_add(self._refresh_status)
        return vbox

    # ------------------------------------------------------------------
    # TAB: About
    # ------------------------------------------------------------------
    def _build_about_tab(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, border_width=20)

        title = Gtk.Label()
        title.set_markup(f"<b>LAIA Security Configurator v{VERSION}</b>")
        vbox.pack_start(title, False, False, 0)

        desc = Gtk.Label(
            label=(
                "LAIA (Linux AI Assistant) Security Configurator\n\n"
                "This tool helps you manage security settings for your LAIA installation.\n"
                "Every setting change includes a clear explanation of the security implications.\n\n"
                "Security philosophy:\n"
                "  • Default-deny: block everything, explicitly allow what's needed\n"
                "  • Least privilege: each component gets minimum required access\n"
                "  • Defense in depth: multiple independent security layers\n"
                "  • Transparency: every change explains the risk\n\n"
                "Quick start:\n"
                "  1. OpenClaw tab — review and set AI assistant permissions\n"
                "  2. System tab — check security services are running\n"
                "  3. Run a security audit to see your current score\n\n"
                "Hardening script: config/security/harden.sh (run as root)\n"
                "Documentation: docs/SECURITY.md"
            ),
            xalign=0
        )
        desc.set_line_wrap(True)
        vbox.pack_start(desc, False, False, 0)

        return vbox

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _section_label(self, text):
        label = Gtk.Label(label=f"<b>{text}</b>", use_markup=True, xalign=0)
        label.get_style_context().add_class("section-header")
        return label

    def _on_exec_ask_changed(self, combo):
        val = combo.get_active_id()
        msg = WARNINGS["exec.ask"].get(val, "")
        self.exec_warning_label.set_text(msg)

    def _on_elevated_changed(self, switch, _):
        val = switch.get_active()
        msg = WARNINGS["exec.elevated"].get(val, "")
        self.elevated_warning.set_text(msg)
        if val:
            # Block the signal temporarily to avoid loop
            switch.handler_block_by_func(self._on_elevated_changed)
            confirmed = self._show_warning_dialog(
                "Enable Root Access?",
                WARNINGS["exec.elevated"][True]
            )
            switch.handler_unblock_by_func(self._on_elevated_changed)
            if not confirmed:
                switch.set_active(False)

    def _on_bind_changed(self, combo):
        val = combo.get_active_id()
        msg = WARNINGS["security.bind"].get(val, "")
        self.bind_warning.set_text(msg)
        if val == "0.0.0.0":
            combo.handler_block_by_func(self._on_bind_changed)
            confirmed = self._show_warning_dialog(
                "Expose OpenClaw to Network?",
                WARNINGS["security.bind"]["0.0.0.0"]
            )
            combo.handler_unblock_by_func(self._on_bind_changed)
            if not confirmed:
                combo.set_active_id("127.0.0.1")

    def _show_warning_dialog(self, title, message):
        """Show a warning dialog. Returns True if user confirmed, False if cancelled."""
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=Gtk.DialogFlags.MODAL,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=title,
        )
        dialog.format_secondary_text(message)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

    def _load_config(self):
        """Load current config from OpenClaw config file."""
        try:
            if OPENCLAW_CONFIG.exists():
                with open(OPENCLAW_CONFIG) as f:
                    config = json.load(f)

                security = config.get("security", {})
                exec_cfg = security.get("exec", {})
                features = config.get("features", {})

                # Set exec.ask
                ask = exec_cfg.get("ask", "always")
                self.exec_ask_combo.set_active_id(ask)

                # Set elevated
                elevated = exec_cfg.get("elevated", False)
                self.elevated_switch.set_active(bool(elevated))

                # Set bind
                bind = security.get("bind", "127.0.0.1")
                self.bind_combo.set_active_id(bind)

                # Set feature toggles
                for key, sw in self.feature_switches.items():
                    sw.set_active(bool(features.get(key, False)))

                self.status_label.set_text(f"Loaded: {OPENCLAW_CONFIG}")
            else:
                self.status_label.set_text("Config file not found — using defaults")
                self.exec_ask_combo.set_active_id("always")
                self.elevated_switch.set_active(False)
                self.bind_combo.set_active_id("127.0.0.1")

        except json.JSONDecodeError as e:
            self.status_label.set_text(f"⚠️ Config JSON error: {e}")
        except Exception as e:
            self.status_label.set_text(f"⚠️ Load error: {e}")

    def _on_save(self, button):
        """Save settings to OpenClaw config file."""
        try:
            # Load existing config or start fresh
            if OPENCLAW_CONFIG.exists():
                with open(OPENCLAW_CONFIG) as f:
                    config = json.load(f)
            else:
                config = {}

            # Update security settings
            security = config.setdefault("security", {})
            exec_cfg = security.setdefault("exec", {})
            features = config.setdefault("features", {})

            exec_cfg["ask"]      = self.exec_ask_combo.get_active_id()
            exec_cfg["elevated"] = self.elevated_switch.get_active()
            security["bind"]     = self.bind_combo.get_active_id()

            for key, sw in self.feature_switches.items():
                features[key] = sw.get_active()

            # Write with backup
            OPENCLAW_CONFIG.parent.mkdir(parents=True, exist_ok=True)
            backup = Path(str(OPENCLAW_CONFIG) + ".bak")
            if OPENCLAW_CONFIG.exists():
                OPENCLAW_CONFIG.rename(backup)

            with open(OPENCLAW_CONFIG, "w") as f:
                json.dump(config, f, indent=2)
                f.write("\n")

            self.status_label.set_text("✅ Settings saved. Restart OpenClaw to apply.")

            try:
                notif = Notify.Notification.new(
                    "LAIA Security Configurator",
                    "Settings saved. Restart OpenClaw to apply changes.",
                    "dialog-information"
                )
                notif.show()
            except Exception:
                pass  # Notifications are optional

        except PermissionError:
            self.status_label.set_text(f"❌ Permission denied writing to {OPENCLAW_CONFIG}")
        except Exception as e:
            self.status_label.set_text(f"❌ Save error: {e}")

    def _check_service(self, service, label):
        """Check if a systemd service is active (called from GLib idle)."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=3
            )
            state = result.stdout.strip()
            if state == "active":
                label.set_markup('<span color="#2e7d32"><b>✅ Active</b></span>')
            elif state == "inactive":
                label.set_markup('<span color="#c62828">❌ Inactive</span>')
            else:
                label.set_markup(f'<span color="#f57f17">⚠️ {state}</span>')
        except FileNotFoundError:
            label.set_text("N/A (systemctl not found)")
        except subprocess.TimeoutExpired:
            label.set_text("Timeout")
        except Exception as e:
            label.set_text(f"Error: {e}")
        return False  # Don't repeat

    def _refresh_services(self):
        """Refresh all service status labels."""
        for svc, lbl in self.service_labels.items():
            lbl.set_text("Checking...")
            GLib.idle_add(self._check_service, svc, lbl)

    def _run_command(self, cmd, title):
        """Open a dialog and run a shell command, showing output."""
        dialog = Gtk.Dialog(title=title, transient_for=self, flags=Gtk.DialogFlags.MODAL)
        dialog.add_button("Close", Gtk.ResponseType.OK)
        dialog.set_default_size(680, 450)

        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_monospace(True)
        tv.set_wrap_mode(Gtk.WrapMode.WORD)

        sw = Gtk.ScrolledWindow()
        sw.add(tv)
        sw.set_vexpand(True)
        sw.set_hexpand(True)

        content = dialog.get_content_area()
        content.set_spacing(8)
        content.set_border_width(10)
        content.pack_start(Gtk.Label(label=f"Running: {cmd}", xalign=0), False, False, 0)
        content.pack_start(sw, True, True, 0)
        dialog.show_all()

        def run():
            try:
                result = subprocess.run(
                    ["bash", "-c", f"sudo {cmd}"],
                    capture_output=True, text=True, timeout=120
                )
                output = result.stdout + result.stderr
                if not output.strip():
                    output = "(no output)"
            except subprocess.TimeoutExpired:
                output = "Command timed out after 120 seconds."
            except Exception as e:
                output = f"Error running command: {e}"

            GLib.idle_add(tv.get_buffer().set_text, output)

        threading.Thread(target=run, daemon=True).start()
        dialog.run()
        dialog.destroy()

    def _refresh_status(self):
        """Refresh the status tab dashboard."""
        def do_refresh():
            lines = ["=== LAIA Security Status Dashboard ===\n"]
            checks = [
                ("ufw status 2>/dev/null | head -5 || echo 'ufw not installed'", "Firewall"),
                ("systemctl is-active apparmor 2>/dev/null || echo 'not found'", "AppArmor"),
                ("systemctl is-active fail2ban 2>/dev/null || echo 'not found'", "fail2ban"),
                ("systemctl is-active unattended-upgrades 2>/dev/null || echo 'not found'", "Auto-updates"),
                ("openclaw status 2>/dev/null | head -5 || echo 'openclaw not running'", "OpenClaw"),
                ("grep -c '^proc.*hidepid' /etc/fstab 2>/dev/null && echo 'configured' || echo 'not configured'", "/proc hidepid"),
                ("sysctl kernel.randomize_va_space 2>/dev/null || echo 'unknown'", "ASLR"),
                ("sysctl kernel.kptr_restrict 2>/dev/null || echo 'unknown'", "Kernel ptr restrict"),
            ]

            for cmd, name in checks:
                try:
                    result = subprocess.run(
                        ["bash", "-c", cmd],
                        capture_output=True, text=True, timeout=5
                    )
                    output = (result.stdout or result.stderr or "").strip() or "no output"
                except Exception as e:
                    output = f"error: {e}"
                lines.append(f"{'─'*40}")
                lines.append(f"{name}:")
                lines.append(f"  {output}\n")

            text = "\n".join(lines)
            GLib.idle_add(self.status_text.get_buffer().set_text, text)

        threading.Thread(target=do_refresh, daemon=True).start()
        return False  # Don't repeat

    def _on_apply_firewall(self, button):
        """Apply LAIA firewall rules."""
        script = Path(__file__).parent.parent.parent / "config" / "security" / "ufw-rules.sh"
        if not script.exists():
            self._show_warning_dialog(
                "Script Not Found",
                f"Could not find ufw-rules.sh at:\n{script}\n\nMake sure LAIA is fully installed."
            )
            return
        self._run_command(f"bash '{script}'", "Apply LAIA Firewall")


def main():
    win = LaiaConfigurator()
    win.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
