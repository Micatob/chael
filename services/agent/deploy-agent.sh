#!/usr/bin/env bash
set -euo pipefail

# Chael SIEM Agent — Linux one-liner deployment
# Usage:
#   curl -s http://SIEM:8000/api/agent/static/deploy-agent.sh | bash -s -- \
#     --siem-url http://10.0.0.5:8000
#
# Or download & run:
#   wget -q http://SIEM:8000/api/agent/static/deploy-agent.sh
#   bash deploy-agent.sh --siem-url http://10.0.0.5:8000

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
step()  { echo -e "${CYAN}>>>${NC} $1"; }
ok()    { echo -e "  ${GREEN}OK${NC} $1"; }
warn()  { echo -e "  ${YELLOW}WARN${NC} $1"; }
fail()  { echo -e "  ${RED}FAIL${NC} $1"; exit 1; }

SIEM_URL=""
AGENT_NAME=""
AGENT_ID=""
AGENT_KEY=""
AGENT_DIR="/opt/chael/agent"
NO_START=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --siem-url) SIEM_URL="$2"; shift 2 ;;
    --agent-name) AGENT_NAME="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --agent-key) AGENT_KEY="$2"; shift 2 ;;
    --agent-dir) AGENT_DIR="$2"; shift 2 ;;
    --no-start) NO_START=true; shift ;;
    *) fail "Unknown argument: $1" ;;
  esac
done

if [[ -z "$SIEM_URL" ]]; then
  fail "Missing --siem-url (e.g. http://10.0.0.5:8000)"
fi
if [[ -z "$AGENT_NAME" ]]; then
  AGENT_NAME="$(hostname)"
fi

# Root check
if [[ $EUID -ne 0 ]]; then
  warn "Not running as root — systemd service creation will be skipped"
fi

# ── Step 1: Python ──────────────────────────────────────────────────────────
step "Checking for Python 3.9+..."
PYTHON=""
for cmd in python3 python; do
  if command -v "$cmd" &>/dev/null; then
    ver=$("$cmd" --version 2>&1 | grep -oP 'Python \K(\d+\.\d+)')
    major="${ver%.*}"; minor="${ver#*.}"
    if [[ "$major" -ge 3 && "$minor" -ge 9 ]]; then
      PYTHON=$(command -v "$cmd")
      ok "Python $ver found at $PYTHON"
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  step "Python 3.9+ not found. Installing..."
  if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv
  elif command -v yum &>/dev/null; then
    yum install -y -q python3 python3-pip
  elif command -v dnf &>/dev/null; then
    dnf install -y -q python3 python3-pip
  elif command -v zypper &>/dev/null; then
    zypper install -y python3 python3-pip
  else
    fail "No package manager found. Install Python 3.9+ manually."
  fi
  PYTHON=$(command -v python3 || command -v python)
  if [[ -z "$PYTHON" ]]; then
    fail "Python installation failed"
  fi
  ok "Python installed at $PYTHON ($("$PYTHON" --version 2>&1))"
fi

# ── Step 2: Create agent directory ──────────────────────────────────────────
step "Creating agent directory: $AGENT_DIR"
mkdir -p "$AGENT_DIR"

# ── Step 3: Download agent files ────────────────────────────────────────────
step "Downloading agent files from $SIEM_URL..."
BASE_URL="$SIEM_URL/api/agent/static"
FILES=(
  agent.py requirements.txt
  yara_scanner.py docker_monitor.py cis_benchmark.py
  vuln_scanner.py registry_monitor.py auto_update.py
)
DOWNLOADED=false

for file in "${FILES[@]}"; do
  if curl -sf "$BASE_URL/$file" -o "$AGENT_DIR/$file" 2>/dev/null; then
    ok "Downloaded $file"
    DOWNLOADED=true
  else
    warn "Could not download $file from SIEM server"
  fi
done

if ! $DOWNLOADED; then
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  if [[ -f "$SCRIPT_DIR/agent.py" ]]; then
    step "Copying agent files from local repo: $SCRIPT_DIR"
    cp "$SCRIPT_DIR"/*.py "$SCRIPT_DIR"/requirements.txt "$AGENT_DIR"/ 2>/dev/null || true
    DOWNLOADED=true
  else
    fail "Could not download agent files. Try running from the cloned repo."
  fi
fi

chmod +x "$AGENT_DIR"/*.py 2>/dev/null || true

# ── Step 4: Install Python dependencies ─────────────────────────────────────
step "Installing Python dependencies..."
"$PYTHON" -m pip install --upgrade pip --quiet || warn "pip upgrade failed"
"$PYTHON" -m pip install -r "$AGENT_DIR/requirements.txt" --quiet || warn "pip install failed for some packages"
# Additional optional deps
"$PYTHON" -m pip install watchdog --quiet 2>/dev/null || true
"$PYTHON" -m pip install docker --quiet 2>/dev/null || true
"$PYTHON" -m pip install yara-python --quiet 2>/dev/null || warn "yara-python skipped (requires build tools)"
ok "Dependencies installed"

# ── Step 5: Write launcher ──────────────────────────────────────────────────
step "Creating agent launcher..."
LOG_FILE="/var/log/chael-agent.log"

LAUNCHER="$AGENT_DIR/start-agent.sh"
cat > "$LAUNCHER" <<LAUNCHER_EOF
#!/usr/bin/env bash
exec >> "$LOG_FILE" 2>&1
cd "$AGENT_DIR"
exec "$PYTHON" "$AGENT_DIR/agent.py" \
  --siem-url "$SIEM_URL" \
  --agent-name "$AGENT_NAME" \
  ${AGENT_ID:+--agent-id "$AGENT_ID"} \
  ${AGENT_KEY:+--agent-key "$AGENT_KEY"}
LAUNCHER_EOF
chmod +x "$LAUNCHER"
ok "Launcher created at $LAUNCHER"

# ── Step 6: systemd service (if root) ───────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
  step "Creating systemd service..."
  SERVICE_FILE="/etc/systemd/system/chael-agent.service"
  if [[ ! -f "$SERVICE_FILE" ]]; then
    cat > "$SERVICE_FILE" <<SERVICE_EOF
[Unit]
Description=Chael SIEM Agent
After=network.target

[Service]
Type=simple
ExecStart=$LAUNCHER
Restart=on-failure
RestartSec=10
User=nobody
Group=nogroup
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$AGENT_DIR /var/log

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    systemctl daemon-reload
    systemctl enable chael-agent.service
    ok "systemd service created & enabled (chael-agent)"
  else
    ok "systemd service already exists"
  fi
fi

# ── Step 7: Start agent ─────────────────────────────────────────────────────
if ! $NO_START; then
  step "Starting Chael SIEM agent..."
  if [[ $EUID -eq 0 ]]; then
    systemctl start chael-agent.service 2>/dev/null || warn "systemctl start failed, launching directly..."
  fi
  if ! systemctl is-active --quiet chael-agent.service 2>/dev/null; then
    nohup "$LAUNCHER" > /dev/null 2>&1 &
    ok "Agent started in background (PID $!)"
  fi
  ok "Agent startup initiated"
else
  step "Installation complete (--no-start flag set)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}OK Chael SIEM Agent deployment complete!${NC}"
echo "  Agent directory: $AGENT_DIR"
echo "  Launcher:        $LAUNCHER"
echo "  Log file:        $LOG_FILE"
if [[ $EUID -eq 0 ]]; then
  echo "  Service:         chael-agent (systemd, auto-starts on boot)"
fi
echo "  Run manually:    $LAUNCHER"
echo ""
echo "  To watch logs:   tail -f $LOG_FILE"
echo "  To check status: systemctl status chael-agent (if root)"
