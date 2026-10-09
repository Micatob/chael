"""Endpoint response module for the Chael SIEM agent.

Polls the SOAR service for containment tasks (isolate / unisolate /
block / unblock) and executes them locally with the OS firewall
(netsh on Windows, iptables on Linux). Best-effort: every outcome —
success or failure — is reported back so the analyst sees verification
instead of a silent queue.

Runs as a daemon thread started from agent.py main().
"""

import logging
import platform
import subprocess
import threading
import time

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

log = logging.getLogger("chael-agent-response")

VALID_ACTIONS = ("isolate", "unisolate", "block", "unblock",
                   "kill_process", "quarantine_file",
                   "delete_persistence", "collect_triage")

# Never kill these, even if ordered to (typo/malice guard).
PROTECTED_PROCESSES = {
    "windows": {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                "lsass.exe", "winlogon.exe", "explorer.exe", "idle"},
    "linux": {"systemd", "init", "kthreadd", "sshd", "systemd-journald"},
}

QUARANTINE_DIRNAME = "chael-quarantine"


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        ok = r.returncode == 0
        err = "" if ok else (r.stderr.decode(errors="replace")[:300] if r.stderr else f"exit {r.returncode}")
        return ok, err
    except FileNotFoundError:
        return False, f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "command timed out"
    except Exception as e:
        return False, str(e)[:300]


def isolate_host():
    """Cut outbound traffic, keep loopback + established (forensics stay alive)."""
    system = platform.system()
    if system == "Windows":
        ok, err = _run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,blockoutbound"])
        return {"success": ok, "backend": "netsh", "error": err}
    if system == "Linux":
        for rule in (["iptables", "-C", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],):
            ok, _ = _run(rule)
            if not ok:
                _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        ok, _ = _run(["iptables", "-C", "OUTPUT", "-m", "state",
                      "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        if not ok:
            _run(["iptables", "-A", "OUTPUT", "-m", "state",
                  "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        ok, err = _run(["iptables", "-P", "OUTPUT", "DROP"])
        return {"success": ok, "backend": "iptables", "error": err}
    return {"success": False, "backend": "none", "error": f"unsupported OS: {system}"}


def unisolate_host():
    system = platform.system()
    if system == "Windows":
        ok, err = _run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,allowoutbound"])
        return {"success": ok, "backend": "netsh", "error": err}
    if system == "Linux":
        ok, err = _run(["iptables", "-P", "OUTPUT", "ACCEPT"])
        return {"success": ok, "backend": "iptables", "error": err}
    return {"success": False, "backend": "none", "error": f"unsupported OS: {system}"}


def block_ip(ip):
    if not ip:
        return {"success": False, "error": "missing IP"}
    system = platform.system()
    if system == "Windows":
        rule = f"Chael_Block_{ip.replace('.', '_').replace(':', '_')}"
        ok, err = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule}", "dir=in", "action=block", f"remoteip={ip}"])
        return {"success": ok, "backend": "netsh", "rule": rule, "error": err}
    if system == "Linux":
        ok, err = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
        if ok:
            return {"success": True, "backend": "iptables", "note": "already blocked"}
        ok, err = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        return {"success": ok, "backend": "iptables", "error": err}
    return {"success": False, "backend": "none", "error": f"unsupported OS: {system}"}


def unblock_ip(ip):
    if not ip:
        return {"success": False, "error": "missing IP"}
    system = platform.system()
    if system == "Windows":
        rule = f"Chael_Block_{ip.replace('.', '_').replace(':', '_')}"
        ok, err = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])
        return {"success": ok, "backend": "netsh", "error": err}
    if system == "Linux":
        ok, err = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        return {"success": ok, "backend": "iptables", "error": err}
    return {"success": False, "backend": "none", "error": f"unsupported OS: {system}"}


def execute_task(task, ctx=None):
    action = (task.get("action") or "").lower()
    target = task.get("target") or ""
    if action == "isolate":
        return isolate_host()
    if action == "unisolate":
        return unisolate_host()
    if action == "block":
        return block_ip(target)
    if action == "unblock":
        return unblock_ip(target)
    if action == "kill_process":
        return kill_process(task)
    if action == "quarantine_file":
        return quarantine_file(task)
    if action == "delete_persistence":
        return delete_persistence(task)
    if action == "collect_triage":
        return collect_triage(task, ctx)
    return {"success": False, "error": f"unknown action: {action}"}


def kill_process(task):
    name = str(task.get("process") or task.get("target") or "").strip()
    pid = str(task.get("pid") or "").strip()
    if not name and not pid:
        return {"success": False, "error": "kill_process needs 'process' name or 'pid'"}
    system = platform.system()
    if name.lower() in PROTECTED_PROCESSES.get("windows" if system == "Windows" else "linux", set()):
        return {"success": False, "error": f"refusing to kill protected process {name}"}
    if pid and pid.isdigit():
        cmd = (["taskkill", "/PID", pid, "/F"] if system == "Windows"
               else ["kill", "-9", pid])
    else:
        cmd = (["taskkill", "/IM", name, "/F"] if system == "Windows"
               else ["pkill", "-f", name])
    ok, err = _run(cmd)
    return {"success": ok, "backend": "os", "target": pid or name, "error": err}


def quarantine_file(task):
    import hashlib
    import shutil
    import tempfile
    path = str(task.get("path") or task.get("target") or "").strip()
    if not path:
        return {"success": False, "error": "quarantine_file needs 'path'"}
    import os
    if not os.path.isfile(path):
        return {"success": False, "error": f"not a file: {path}"}
    try:
        with open(path, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        qdir = os.path.join(tempfile.gettempdir(), QUARANTINE_DIRNAME)
        os.makedirs(qdir, exist_ok=True)
        dest = os.path.join(qdir, os.path.basename(path) + ".quarantined")
        shutil.move(path, dest)
        if platform.system() == "Windows":
            _run(["icacls", dest, "/deny", "Everyone:(F)"])
        else:
            _run(["chmod", "000", dest])
        return {"success": True, "backend": "os", "quarantined_to": dest, "sha256": sha}
    except Exception as e:
        return {"success": False, "error": str(e)[:300]}


def delete_persistence(task):
    kind = str(task.get("persistence_kind") or "").strip().lower()
    name = str(task.get("persistence_name") or task.get("target") or "").strip()
    if not kind or not name:
        return {"success": False,
                "error": "delete_persistence needs 'persistence_kind' (schtask|service|unit) and 'persistence_name'"}
    system = platform.system()
    if kind == "schtask" and system == "Windows":
        ok, err = _run(["schtasks", "/delete", "/tn", name, "/f"])
        return {"success": ok, "backend": "schtasks", "target": name, "error": err}
    if kind == "service" and system == "Windows":
        _run(["sc", "stop", name])
        ok, err = _run(["sc", "delete", name])
        return {"success": ok, "backend": "sc", "target": name, "error": err}
    if kind == "unit" and system == "Linux":
        _run(["systemctl", "stop", name])
        _run(["systemctl", "disable", name])
        ok, err = _run(["systemctl", "reset-failed", name])
        return {"success": ok, "backend": "systemctl", "target": name, "error": err}
    return {"success": False, "error": f"unsupported {kind} on {system}"}


def _triage_snapshot():
    """Read-only host snapshot: processes, connections, autostart, users."""
    import json as _json
    snap = {"tool": "chael-triage", "platform": platform.system()}
    system = platform.system()
    if system == "Windows":
        ok, out = _run_text(["tasklist", "/FO", "CSV", "/NH"])
        snap["processes"] = out[:20000] if ok else ""
        ok, out = _run_text(["netstat", "-ano"])
        snap["connections"] = out[:20000] if ok else ""
        ok, out = _run_text(["schtasks", "/query", "/FO", "CSV"])
        snap["scheduled_tasks"] = out[:20000] if ok else ""
        ok, out = _run_text(["reg", "query",
                             r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"])
        snap["run_keys"] = out[:8000] if ok else ""
        ok, out = _run_text(["net", "user"])
        snap["users"] = out[:4000] if ok else ""
    else:
        ok, out = _run_text(["ps", "aux"])
        snap["processes"] = out[:20000] if ok else ""
        ok, out = _run_text(["ss", "-tulpn"])
        if not ok:
            ok, out = _run_text(["netstat", "-tulpn"])
        snap["connections"] = out[:20000] if ok else ""
        ok, out = _run_text(["systemctl", "list-timers", "--all", "--no-pager"])
        snap["timers"] = out[:10000] if ok else ""
        ok, out = _run_text(["ls", "-la", "/etc/cron.d", "/etc/cron.daily"])
        snap["cron"] = out[:4000] if ok else ""
        ok, out = _run_text(["who"])
        snap["logons"] = out[:4000] if ok else ""
    return snap


def _run_text(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode == 0:
            return True, r.stdout.decode(errors="replace")
        return False, (r.stderr or b"").decode(errors="replace")[:300]
    except FileNotFoundError:
        return False, f"not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)[:300]


def collect_triage(task, ctx=None):
    """Build the triage bundle (JSON snapshot + zip). With ctx, upload it
    as incident evidence; without ctx, leave it on disk and report the hash."""
    import hashlib
    import json as _json
    import tempfile
    import zipfile
    import os
    import time as _time
    try:
        snap = _triage_snapshot()
        snap["collected_at"] = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        snap["incident_id"] = task.get("incident_id", "")
        raw = _json.dumps(snap, default=str).encode("utf-8")
        zpath = os.path.join(tempfile.gettempdir(),
                             f"chael-triage-{int(_time.time())}.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("triage.json", raw)
        with open(zpath, "rb") as fh:
            blob = fh.read()
        sha = hashlib.sha256(blob).hexdigest()
        if ctx and task.get("incident_id"):
            up = _upload_bundle(ctx, task["incident_id"],
                                os.path.basename(zpath), blob)
            try:
                os.remove(zpath)
            except Exception:
                pass
            if up.get("success"):
                return {"success": True, "backend": "triage",
                        "sha256": sha, "bytes": len(blob),
                        "evidence_id": up.get("evidence_id", "")}
            return {"success": False, "backend": "triage",
                    "sha256": sha, "bundle": zpath,
                    "error": "upload failed: " + up.get("error", "?")}
        return {"success": True, "backend": "triage", "sha256": sha,
                "bytes": len(blob), "bundle": zpath,
                "note": "no upload ctx — bundle kept locally"}
    except Exception as e:
        return {"success": False, "backend": "triage", "error": str(e)[:300]}


def _upload_bundle(ctx, incident_id, filename, blob):
    url = (ctx.get("siem_url") or "").rstrip("/") + \
        f"/api/incidents/{incident_id}/evidence/bundle"
    try:
        r = requests.post(url, files={"bundle": (filename, blob, "application/zip")},
                          headers=(ctx.get("auth_headers") or {})(),
                          timeout=60, verify=False)
        if r.status_code == 200:
            return {"success": True,
                    "evidence_id": r.json().get("evidence", {}).get("evidence_id", "")}
        return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


class ResponsePoller:
    """Poll loop: fetch tasks → execute → report. Stops on STOP event."""

    def __init__(self, siem_url, agent_id, hostname, auth_header_func,
                 interval=30, stop_event=None):
        self.siem_url = (siem_url or "").rstrip("/")
        self.agent_id = agent_id or ""
        self.hostname = hostname or ""
        self.auth_header_func = auth_header_func
        self.interval = max(10, int(interval or 30))
        self.stop_event = stop_event or threading.Event()
        self._thread = None

    def start(self):
        if requests is None:
            log.warning("requests not installed — response poller disabled")
            return None
        self._thread = threading.Thread(target=self.run, daemon=True,
                                        name="chael-response-poller")
        self._thread.start()
        log.info("Response poller started (interval %ds)", self.interval)
        return self._thread

    def _poll(self):
        url = f"{self.siem_url}/api/soar/agent/tasks"
        try:
            r = requests.get(url, params={"agent_id": self.agent_id,
                                          "hostname": self.hostname},
                             headers=self.auth_header_func(), timeout=15,
                             verify=False)
            if r.status_code == 401:
                return None  # token refresh handled by reconnect loop
            if r.status_code != 200:
                log.debug("Task poll HTTP %s", r.status_code)
                return []
            return r.json().get("tasks", [])
        except Exception as e:
            log.debug("Task poll failed: %s", e)
            return []

    def _report(self, task_id, success, detail):
        url = f"{self.siem_url}/api/soar/agent/tasks/{task_id}/result"
        try:
            requests.post(url, json={"success": bool(success),
                                     "detail": str(detail)[:500],
                                     "agent_id": self.agent_id},
                          headers=self.auth_header_func(), timeout=15,
                          verify=False)
        except Exception as e:
            log.debug("Task result report failed: %s", e)

    def run(self):
        ctx = {"siem_url": self.siem_url, "auth_headers": self.auth_header_func}
        while not self.stop_event.is_set():
            try:
                tasks = self._poll()
                for task in tasks or []:
                    tid = task.get("task_id", "?")
                    log.info("Executing response task %s: %s %s",
                             tid, task.get("action"), task.get("target"))
                    try:
                        outcome = execute_task(task, ctx)
                    except Exception as e:
                        outcome = {"success": False, "error": str(e)[:300]}
                    ok = bool(outcome.get("success"))
                    detail = outcome.get("error") or f"{outcome.get('backend', '?')} ok"
                    self._report(tid, ok, detail)
                    log.info("Task %s %s: %s", tid,
                             "DONE" if ok else "FAILED", detail[:120])
            except Exception as e:
                log.debug("Response poller error: %s", e)
            self.stop_event.wait(self.interval)
