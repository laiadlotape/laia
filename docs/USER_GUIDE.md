# LAIA User Guide

## First Steps After Install

### 1. Launch the Setup Wizard
After installing LAIA, the setup wizard launches automatically.
You can always re-run it: **Applications → LAIA → Setup Wizard**

### 2. Open the AI Interface
Go to **http://localhost:3000** in your browser.
You'll see OpenWebUI — a ChatGPT-like interface that runs locally.

### 3. Configure Security Settings
Run the LAIA Configurator: **Applications → LAIA → Security Configurator**
Or from terminal: `laia-config`

---

## Using AI Models

### Chat with AI
1. Open **http://localhost:3000**
2. Select a model from the dropdown
3. Start chatting — everything stays on your computer

### Install More Models
```bash
ollama pull mistral:7b        # 7B general model (~4GB)
ollama pull gemma2:9b         # Better quality (~5GB)
ollama pull qwen2.5-coder:7b  # For coding tasks
```

### List Installed Models
```bash
ollama list
```

---

## Security

### Change OpenClaw Settings
```
laia-config → OpenClaw tab
```
Every change shows a risk explanation before applying.

### Check Firewall Status
```bash
sudo ufw status verbose
```

### View Security Audit
```bash
sudo lynis audit system
```
Score above 70 = good. LAIA targets 80+.

---

## Troubleshooting

### AI not working?
```bash
systemctl status ollama
sudo systemctl restart ollama
```

### OpenWebUI not loading?
```bash
systemctl status laia-openwebui
sudo systemctl restart laia-openwebui
```
Then try: http://localhost:3000

### Can't connect via SSH?
```bash
sudo ufw status       # check firewall
sudo systemctl status sshd
```

### Full system logs
```bash
journalctl -b -p err  # errors since boot
```
