# Chael SIEM — Agent Deployment Guide

## How It Works (Simple Explanation)

Your Chael SIEM has two parts:
1. **The SIEM Server** — The PC running Docker with all the services (this is your current machine)
2. **The Agent** — A small Python script installed on any PC you want to monitor

The agent collects logs (Windows events, Linux syslog, etc.) and sends them to the SIEM server over HTTP. The SIEM stores them in OpenSearch and shows them in the dashboard.

```
[Agent PC] --sends logs--> [SIEM Server PC:8001] --stores--> [OpenSearch] --displays--> [Dashboard :3000]
```

---

## Your SIEM Server Info

| Item | Value |
|------|-------|
| Dashboard URL | `http://<your-server-IP>:3000` |
| API Gateway (HTTP) | `http://<your-server-IP>:8001` |
| API Gateway (HTTPS) | `https://<your-server-IP>:8443` |
| Default Login | `admin` / `ChaelSIEMStrongPass1!` |

Find your server's IP: Run `ipconfig` on the SIEM server and look for your LAN IP (e.g., `192.168.1.x`).

---

## Deployment Methods

### Method 1: One-Line PowerShell (Recommended for Windows)

This is the easiest way. It installs Python, downloads the agent, and starts it automatically.

**Step 1:** On the agent PC, open PowerShell as Administrator

**Step 2:** Run this command (replace `<SIEM-IP>` with your server's IP):

```powershell
irm http://<SIEM-IP>:8001/api/agent/download/deploy-agent.ps1 | iex
```

Or if that doesn't work, download and run the script manually:

```powershell
# Download the script
Invoke-WebRequest -Uri "http://<SIEM-IP>:8001/api/agent/download/deploy-agent.ps1" -OutFile "$env:TEMP\deploy-agent.ps1"

# Run it
& "$env:TEMP\deploy-agent.ps1" -SiemUrl "http://<SIEM-IP>:8001"
```

**What the script does:**
1. Checks if Python 3.9+ is installed (installs it if missing)
2. Downloads agent files from the SIEM server
3. Installs Python dependencies (requests, psutil, etc.)
4. Creates a Windows Scheduled Task so the agent starts on boot
5. Starts the agent immediately

**After running, you should see:**
```
>>> Agent deployment complete!
  Agent directory: C:\Program Files\Chael\agent
  Scheduled task: ChaelSIEM-Agent (auto-starts on boot)
```

**To verify the agent is running:**
```powershell
Get-ScheduledTask -TaskName "ChaelSIEM-Agent"
```

---

### Method 2: Manual PowerShell Deployment

If the one-liner doesn't work, do it step by step:

**Step 1:** Check Python
```powershell
python --version
# If not installed, download from https://www.python.org/downloads/
```

**Step 2:** Create agent folder
```powershell
New-Item -ItemType Directory -Path "C:\ChaelAgent" -Force
```

**Step 3:** Download agent files
```powershell
$baseUrl = "http://<SIEM-IP>:8001/api/agent/download"
$files = @("agent.py", "requirements.txt", "yara_scanner.py", "registry_monitor.py", "docker_monitor.py", "cis_benchmark.py", "vuln_scanner.py", "auto_update.py")

foreach ($file in $files) {
    Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile "C:\ChaelAgent\$file"
    Write-Host "Downloaded: $file"
}
```

**Step 4:** Install dependencies
```powershell
pip install requests psutil
```

**Step 5:** Start the agent
```powershell
python C:\ChaelAgent\agent.py --siem-url http://<SIEM-IP>:8001 --agent-name $env:COMPUTERNAME --mode windows-events
```

---

### Method 3: Linux Agent

**Step 1:** Download agent files
```bash
wget http://<SIEM-IP>:8001/api/agent/download/agent.py -O /opt/chael/agent.py
wget http://<SIEM-IP>:8001/api/agent/download/requirements.txt -O /opt/chael/requirements.txt
```

**Step 2:** Install dependencies
```bash
pip3 install requests psutil
```

**Step 3:** Start the agent
```bash
python3 /opt/chael/agent.py --siem-url http://<SIEM-IP>:8001 --agent-name $(hostname) --mode linux-syslog
```

**Step 4 (Optional):** Run as a systemd service
```bash
cat > /etc/systemd/system/chael-agent.service << 'EOF'
[Unit]
Description=Chael SIEM Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/chael/agent.py --siem-url http://<SIEM-IP>:8001 --mode linux-syslog
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now chael-agent
```

---

### Method 4: Docker Agent

If you prefer Docker on the agent machine:

```bash
# Clone the repo or copy the services/agent directory
git clone https://github.com/your-org/chael-siem.git
cd chael-siem

# Build and run
docker compose --profile agent up agent
```

Or run the agent container directly:
```bash
docker run -d --name chael-agent \
  -e CHAEL_SIEM_URL=http://<SIEM-IP>:8001 \
  -e AGENT_MODE=tail \
  -v /var/log:/var/log:ro \
  chael-agent
```

---

## Network Scenarios

### Scenario A: Same LAN (Same Wi-Fi/Network)

Both PCs are on the same home/office network.

1. Find the SIEM server's LAN IP (run `ipconfig` on server)
2. Use that IP in all agent commands: `http://192.168.1.x:8001`
3. Make sure Windows Firewall allows Python outbound on the agent PC
4. Make sure port 8001 is accessible (the deploy script adds a firewall rule automatically)

**Test connectivity from agent PC:**
```powershell
curl http://<SIEM-IP>:8001/health
# Should return: {"status":"healthy","service":"gateway"}
```

### Scenario B: Radmin VPN (Remote/Different Networks)

Radmin VPN creates a virtual LAN over the internet. Both PCs appear to be on the same network.

**On the SIEM Server PC:**
1. Install Radmin VPN from https://www.radmin-vpn.com/
2. Create a new network (Network > Create Network)
3. Note the Radmin VPN IP (e.g., `26.x.x.x` or `10.x.x.x`)

**On the Agent PC:**
1. Install Radmin VPN
2. Join the same network (Network > Join Network)
3. Use the Radmin VPN IP as the SIEM URL:

```powershell
& "$env:TEMP\deploy-agent.ps1" -SiemUrl "http://<RADMIN-VPN-IP>:8001"
```

**Important:** The agent uses the Radmin VPN IP, not the LAN IP.

### Scenario C: Over Internet (Port Forwarding)

If you want agents outside your network:

1. On your router, forward port 8001 to the SIEM server's LAN IP
2. Find your public IP (search "what is my ip" on Google)
3. Use the public IP in agent commands:

```powershell
& "$env:TEMP\deploy-agent.ps1" -SiemUrl "http://<PUBLIC-IP>:8001"
```

**Security Warning:** Exposing port 8001 to the internet is risky. Consider:
- Using HTTPS (port 8443) instead
- Setting up a VPN (Radmin, WireGuard, Tailscale)
- Using a firewall to restrict access

### Scenario D: Tailscale (Zero-Config VPN)

Tailscale is the easiest VPN option:

1. Install Tailscale on both PCs from https://tailscale.com/
2. Sign in with the same account
3. Both PCs get a Tailscale IP (e.g., `100.x.x.x`)
4. Use the Tailscale IP:

```powershell
& "$env:TEMP\deploy-agent.ps1" -SiemUrl "http://<TAILSCALE-IP>:8001"
```

---

## Agent Modes

| Mode | What It Collects | Use Case |
|------|-----------------|----------|
| `windows-events` | Windows Security Event Log | Default for Windows PCs |
| `linux-syslog` | /var/log/syslog, auth.log, kern.log | Default for Linux servers |
| `tail` | Any log file you specify | Custom log files |
| `journald` | systemd journal | Modern Linux with systemd |

**Tail specific files:**
```powershell
python agent.py --siem-url http://<SIEM-IP>:8001 --mode tail --paths "C:\nginx\logs\access.log" "C:\app\logs\app.log"
```

---

## Verifying the Agent Works

**On the agent PC:**
```powershell
# Check the agent log
Get-Content "$env:TEMP\chael-agent.log" -Tail 20

# Look for "Forwarded X logs" messages
```

**On the SIEM Dashboard:**
1. Open `http://<SIEM-IP>:3000`
2. Log in with `admin` / `ChaelSIEMStrongPass1!`
3. Go to **Agents** page — your new agent should appear
4. Go to **Logs** page — you should see logs from the agent

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Agent won't register | Check `curl http://<SIEM-IP>:8001/health` returns OK |
| "Connection refused" | Port 8001 may be blocked by firewall |
| Agent shows offline | Check agent log for errors, restart the scheduled task |
| No logs in dashboard | Wait 30 seconds, check agent log for "Forwarded" messages |
| Python not found | Install Python 3.9+ and add to PATH |
| SSL certificate error | Use HTTP (port 8001) instead of HTTPS (8443) |

**Restart the agent:**
```powershell
Stop-ScheduledTask -TaskName "ChaelSIEM-Agent" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "ChaelSIEM-Agent"
```

---

## Agent Options Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--siem-url` | SIEM gateway URL | `http://localhost:8000` |
| `--mode` | Collection mode | auto-detected |
| `--agent-name` | Display name | computer hostname |
| `--batch-size` | Logs per batch | 50 |
| `--poll-interval` | Seconds between polls | 2 |
| `--yara-scan` | Enable YARA scanning | off |
| `--cis-scan` | Enable CIS benchmark | off |
| `--vuln-scan` | Enable vuln scanning | off |
| `--docker-monitor` | Monitor Docker | off |
