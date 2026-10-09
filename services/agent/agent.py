#!/usr/bin/env python3
"""
Chael SIEM Remote Agent — deploy on endpoints to forward logs to the SIEM.
Supports Linux (syslog, auth.log, custom files) and Windows (Event Log).
Usage:
    python agent.py --siem-url http://your-siem:8000 --mode linux-syslog
    python agent.py --siem-url http://your-siem:8000 --mode windows-events
    python agent.py --siem-url http://your-siem:8000 --mode tail --paths /var/log/nginx/access.log
"""

import argparse
import json
import os
import sys
import time
import platform
import socket
import logging
import tempfile
from datetime import datetime, timezone
from threading import Thread, Event, Lock
from queue import Queue, Empty
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Missing 'requests' library. Install with: pip install requests")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("chael-agent")

QUEUE: Queue = Queue(maxsize=10000)
STOP = Event()
HOSTNAME = socket.gethostname()

# ── High-signal Windows Event IDs (Security log) ─────────────────────────
SECURITY_EVENT_IDS = {
    # Account Logon/Logoff
    4624, 4625, 4634, 4648, 4672, 4740,
    # Account Management
    4720, 4722, 4723, 4724, 4725, 4726, 4732, 4738,
    # Privilege Use
    4673, 4674,
    # Process Tracking
    4688,
    # Policy Change
    4719, 4739,
    # Object Access (sensitive)
    4656, 4663, 4657,
    # System Events
    4608, 4697, 7045, 1102,
    # PowerShell
    4103, 4104,
    # Kerberos
    4768, 4769, 4771, 4772,
    # RDP / Network
    4778, 4779, 5156,
    # Task scheduling
    4698,
}

ALL_EVENT_IDS = "all"

_agent_token: Optional[str] = None
_token_lock = Lock()


def _authenticate(auth_url: str, agent_id: str, agent_key: str) -> str | None:
    try:
        resp = requests.post(
            f"{auth_url.rstrip('/')}/api/auth/agent/verify",
            json={"agent_id": agent_id, "agent_key": agent_key},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["access_token"]
        log.error("Auth failed: %s %s", resp.status_code, resp.text[:100])
    except requests.RequestException as e:
        log.error("Auth connection error: %s", e)
    return None


def _get_auth_header() -> dict:
    global _agent_token
    with _token_lock:
        if _agent_token:
            return {"Authorization": f"Bearer {_agent_token}"}
    return {}


_AGENT_CRED_PATH = os.path.join(os.path.expanduser("~"), ".chael", "agent", "credentials.json")


def _load_saved_credentials() -> tuple[str, str] | None:
    try:
        if os.path.exists(_AGENT_CRED_PATH):
            import json
            with open(_AGENT_CRED_PATH, "r") as f:
                data = json.load(f)
            aid, akey = data.get("agent_id"), data.get("agent_key")
            if aid and akey:
                return aid, akey
    except Exception as e:
        log.warning("Failed to load saved credentials: %s", e)
    return None


def _invalidate_saved_credentials():
    try:
        os.makedirs(os.path.dirname(_AGENT_CRED_PATH), exist_ok=True)
        with open(_AGENT_CRED_PATH, "w") as f:
            json.dump({"agent_id": "", "agent_key": ""}, f)
        log.info("Invalidated saved credentials")
    except Exception as e:
        log.warning("Failed to invalidate credentials: %s", e)


def _save_credentials(agent_id: str, agent_key: str):
    try:
        import json
        os.makedirs(os.path.dirname(_AGENT_CRED_PATH), exist_ok=True)
        with open(_AGENT_CRED_PATH, "w") as f:
            json.dump({"agent_id": agent_id, "agent_key": agent_key}, f, indent=2)
        log.info("Saved credentials to %s", _AGENT_CRED_PATH)
    except Exception as e:
        log.warning("Failed to save credentials: %s", e)


def _auto_register(siem_url: str, agent_name: str) -> tuple[str, str] | None:
    try:
        resp = requests.post(
            f"{siem_url.rstrip('/')}/api/auth/agent/auto-register",
            json={"agent_name": agent_name, "hostname": HOSTNAME},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            log.info("Auto-registered agent id=%s name=%s", data["agent_id"], agent_name)
            return data["agent_id"], data["agent_key"]
        log.error("Auto-register failed: %s %s", resp.status_code, resp.text[:200])
    except requests.RequestException as e:
        log.error("Auto-register connection error: %s", e)
    return None


# ── Windows Event Log Reader ────────────────────────────────────────────────

def _read_windows_events_wevtutil(log_name: str = "Security", poll_interval: int = 2, watched_ids: set = None):
    import subprocess
    import xml.etree.ElementTree as ET

    ns = {"s": "http://schemas.microsoft.com/win/2004/08/events/event"}
    last_record = 0
    watch_all = watched_ids is None or watched_ids == ALL_EVENT_IDS
    if watch_all:
        log.info("Watching ALL Windows %s log events via wevtutil", log_name)
    else:
        log.info("Watching %d sensitive Event IDs from Windows %s log via wevtutil", len(watched_ids), log_name)

    while not STOP.is_set():
        try:
            result = subprocess.run(
                ["wevtutil", "qe", log_name, "/c:100", "/rd:true", "/format:xml", "/e:true"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                STOP.wait(poll_interval * 5)
                continue

            root = ET.fromstring(result.stdout)
            seen = 0
            max_rec_id = last_record
            for event in root.findall(".//s:Event", ns):
                sys_el = event.find("s:System", ns)
                if sys_el is None:
                    continue

                rec_el = sys_el.find("s:EventRecordID", ns)
                if rec_el is None or not rec_el.text:
                    continue
                rec_id = int(rec_el.text)
                max_rec_id = max(max_rec_id, rec_id)
                if rec_id <= last_record:
                    continue

                eid_el = sys_el.find("s:EventID", ns)
                event_id = int(eid_el.text) if eid_el is not None and eid_el.text else 0

                # Skip non-watched Event IDs (reduces noise by ~90%)
                if not watch_all and event_id not in watched_ids:
                    continue

                time_el = sys_el.find("s:TimeCreated", ns)
                timestamp = time_el.get("SystemTime") if time_el is not None else datetime.now(timezone.utc).isoformat()

                comp_el = sys_el.find("s:Computer", ns)
                computer = comp_el.text if comp_el is not None else HOSTNAME

                provider_el = sys_el.find("s:Provider", ns)
                source_name = provider_el.get("Name") if provider_el is not None else ""

                level_el = sys_el.find("s:Level", ns)
                level = int(level_el.text) if level_el is not None and level_el.text else 4
                severity = {1: "CRITICAL", 2: "HIGH", 3: "WARNING", 4: "INFO", 5: "INFO"}.get(level, "INFO")

                task_el = sys_el.find("s:Task", ns)
                task = int(task_el.text) if task_el is not None and task_el.text else 0

                # Build message from EventData
                msg_parts = []
                data_el = event.find("s:EventData", ns)
                if data_el is not None:
                    for data in data_el.findall("s:Data", ns):
                        name = data.get("Name", "")
                        val = data.text or ""
                        if val:
                            msg_parts.append(f"{name}={val}")
                message = "; ".join(msg_parts) if msg_parts else f"Event {event_id} from {source_name}"

                entry = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source": f"Windows:{log_name}",
                    "log_type": "windows",
                    "severity": severity,
                    "message": message[:2000],
                    "metadata": {
                        "EventID": event_id,
                        "SourceName": source_name,
                        "Level": level,
                        "Task": task,
                        "RecordNumber": rec_id,
                        "ComputerName": computer,
                    },
                }
                QUEUE.put(entry)
                seen += 1

            if seen:
                last_record = max_rec_id
                log.info("Forwarded %d new events from Windows %s log", seen, log_name)

        except subprocess.TimeoutExpired:
            log.warning("wevtutil query timed out")
        except ET.ParseError as e:
            log.debug("Failed to parse wevtutil XML: %s", e)
        except FileNotFoundError:
            log.error("wevtutil not found — Windows Event Log reading unavailable")
            return
        except Exception as e:
            log.debug("Event log read error: %s", e)

        STOP.wait(poll_interval)


def _read_windows_events(log_name: str = "Security", poll_interval: int = 2, watched_ids: set = None):
    try:
        _read_windows_events_wevtutil(log_name, poll_interval, watched_ids)
    except Exception as e:
        log.warning("wevtutil reader failed (%s), trying pywin32...", e)
        try:
            import win32evtlog
            import win32evtlogutil
            _read_windows_events_pywin32(log_name, poll_interval, watched_ids)
        except ImportError:
            log.error("pywin32 not available either — cannot read Windows Event Log")


def _read_windows_events_pywin32(log_name: str = "Security", poll_interval: int = 2, watched_ids: set = None):
    import win32evtlog
    import win32evtlogutil

    last_record = 0
    watch_all = watched_ids is None or watched_ids == ALL_EVENT_IDS
    if watch_all:
        log.info("Watching ALL Windows %s log events via pywin32", log_name)
    else:
        log.info("Watching %d sensitive Event IDs from Windows %s log via pywin32", len(watched_ids), log_name)

    while not STOP.is_set():
        try:
            hand = win32evtlog.OpenEventLog("localhost", log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            current_last = oldest + total - 1

            if current_last > last_record:
                seen = 0
                while not STOP.is_set():
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                    for ev in events:
                        if ev.RecordNumber <= last_record:
                            continue
                        event_id = ev.EventID & 0xFFFF
                        # Skip non-watched Event IDs (reduces noise by ~90%)
                        if not watch_all and event_id not in watched_ids:
                            last_record = max(last_record, ev.RecordNumber)
                            continue
                        last_record = max(last_record, ev.RecordNumber)
                        msg = ""
                        try:
                            msg = str(win32evtlogutil.SafeFormatMessage(ev))
                        except Exception:
                            if ev.StringInserts:
                                msg = " ".join(str(s) for s in ev.StringInserts)
                        entry = {
                            "timestamp": ev.TimeGenerated.isoformat() if ev.TimeGenerated else datetime.now(timezone.utc).isoformat(),
                            "host": HOSTNAME,
                            "source": f"Windows:{log_name}",
                            "log_type": "windows",
                            "severity": _win32_event_type(ev.EventType),
                            "message": msg.strip() or f"Event {ev.EventID & 0xFFFF} from {ev.SourceName}",
                            "metadata": {
                                "EventID": ev.EventID & 0xFFFF,
                                "SourceName": ev.SourceName,
                                "EventType": ev.EventType,
                                "Category": ev.EventCategory,
                                "RecordNumber": ev.RecordNumber,
                                "ComputerName": ev.ComputerName or HOSTNAME,
                            },
                        }
                        QUEUE.put(entry)
                        seen += 1
                if seen:
                    log.info("Forwarded %d new events from Windows %s log", seen, log_name)

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            log.error("Windows Event Log read error: %s", e)
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

        STOP.wait(poll_interval)


def _win32_event_type(et: int) -> str:
    return {1: "CRITICAL", 2: "HIGH", 3: "WARNING", 4: "INFO", 5: "INFO"}.get(et, "INFO")


# ── Linux Syslog / Auth Log Reader ─────────────────────────────────────────

def _tail_file(path: str, seek_end: bool = True):
    if not os.path.isfile(path):
        log.error("File not found: %s", path)
        return
    log.info("Tailing %s", path)

    with open(path, "r", errors="replace") as f:
        if seek_end:
            f.seek(0, 2)
        while not STOP.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue

            entry = _parse_syslog_line(line, path)
            if entry:
                QUEUE.put(entry)


def _parse_syslog_line(line: str, source_path: str) -> Optional[dict]:
    severity = "INFO"
    msg_lower = line.lower()
    if any(w in msg_lower for w in ["error", "critical", "emerg"]):
        severity = "CRITICAL"
    elif any(w in msg_lower for w in ["warn", "fail", "denied"]):
        severity = "HIGH"
    elif any(w in msg_lower for w in ["notice", "auth"]):
        severity = "MEDIUM"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": HOSTNAME,
        "source": f"file:{os.path.basename(source_path)}",
        "log_type": "syslog",
        "severity": severity,
        "message": line[:2000],
        "metadata": {"file": source_path, "length": len(line)},
    }


# ── Journald Reader (Linux only) ───────────────────────────────────────────

def _read_journald(units: List[str]):
    try:
        import systemd.journal
    except ImportError:
        log.warning("systemd-python not installed, journald disabled")
        return

    j = systemd.journal.Reader()
    j.this_boot()
    j.log_level(systemd.journal.LOG_INFO)
    if units:
        j.add_match(_SYSTEMD_UNIT=[u for u in units])
    j.seek_tail()
    j.get_previous()

    log.info("Watching journald units: %s", units or "all")
    while not STOP.is_set():
        event = j.wait(1)
        if event == systemd.journal.APPEND:
            for entry in j:
                entry_data = {k: v for k, v in entry.items() if isinstance(v, (str, int, float))}
                msg = entry_data.pop("MESSAGE", str(entry.get("__REALTIME_TIMESTAMP", "")))
                sev = "INFO"
                pri = entry.get("PRIORITY", 6)
                if pri <= 2:
                    sev = "CRITICAL"
                elif pri <= 4:
                    sev = "HIGH"
                QUEUE.put({
                    "timestamp": datetime.fromtimestamp(entry.get("__REALTIME_TIMESTAMP", 0) / 1_000_000, tz=timezone.utc).isoformat(),
                    "host": HOSTNAME,
                    "source": f"journald:{entry.get('_SYSTEMD_UNIT', 'unknown')}",
                    "log_type": "syslog",
                    "severity": sev,
                    "message": str(msg)[:2000],
                    "metadata": {"unit": entry.get("_SYSTEMD_UNIT", ""), "pid": entry.get("_PID", "")},
                })


# ── Config Fetcher (SIEM tells agent what to monitor) ─────────────────────

def _fetch_agent_config(siem_url: str, agent_id: str) -> dict:
    headers = _get_auth_header()
    if not headers:
        return {}
    try:
        resp = requests.get(
            f"{siem_url.rstrip('/')}/api/auth/agent/{agent_id}/config",
            headers=headers,
            timeout=10,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            cfg = data.get("config", {})
            log.info("Fetched agent config from SIEM: %s", {k: v for k, v in cfg.items() if k != "windows_event_ids"})
            return cfg
        log.warning("Config fetch returned %s: %s", resp.status_code, resp.text[:100])
    except Exception as e:
        log.debug("Failed to fetch agent config: %s", e)
    return {}


# ── Windows Additional Log Readers (PowerShell, Sysmon, Defender) ────────

def _read_additional_log_wevtutil(log_name: str, source_tag: str, poll_interval: int = 10):
    import subprocess
    import xml.etree.ElementTree as ET

    ns = {"s": "http://schemas.microsoft.com/win/2004/08/events/event"}
    last_record = 0
    log.info("Watching %s (%s) via wevtutil", log_name, source_tag)

    while not STOP.is_set():
        try:
            result = subprocess.run(
                ["wevtutil", "qe", log_name, "/c:50", "/rd:true", "/format:xml", "/e:true"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                STOP.wait(poll_interval * 3)
                continue

            root = ET.fromstring(result.stdout)
            seen = 0
            max_rec_id = last_record
            for event in root.findall(".//s:Event", ns):
                sys_el = event.find("s:System", ns)
                if sys_el is None:
                    continue
                rec_el = sys_el.find("s:EventRecordID", ns)
                if rec_el is None or not rec_el.text:
                    continue
                rec_id = int(rec_el.text)
                max_rec_id = max(max_rec_id, rec_id)
                if rec_id <= last_record:
                    continue

                eid_el = sys_el.find("s:EventID", ns)
                event_id = int(eid_el.text) if eid_el is not None and eid_el.text else 0
                time_el = sys_el.find("s:TimeCreated", ns)
                timestamp = time_el.get("SystemTime") if time_el is not None else datetime.now(timezone.utc).isoformat()
                comp_el = sys_el.find("s:Computer", ns)
                computer = comp_el.text if comp_el is not None else HOSTNAME
                provider_el = sys_el.find("s:Provider", ns)
                source_name = provider_el.get("Name") if provider_el is not None else ""
                level_el = sys_el.find("s:Level", ns)
                level = int(level_el.text) if level_el is not None and level_el.text else 4
                severity = {1: "CRITICAL", 2: "HIGH", 3: "WARNING", 4: "INFO", 5: "INFO"}.get(level, "INFO")

                msg_parts = []
                data_el = event.find("s:EventData", ns)
                if data_el is not None:
                    for data in data_el.findall("s:Data", ns):
                        name = data.get("Name", "")
                        val = data.text or ""
                        if val:
                            msg_parts.append(f"{name}={val}")
                message = "; ".join(msg_parts) if msg_parts else f"Event {event_id} from {source_name}"

                entry = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source": source_tag,
                    "log_type": "windows",
                    "severity": severity,
                    "message": message[:2000],
                    "metadata": {
                        "EventID": event_id,
                        "SourceName": source_name,
                        "Level": level,
                        "RecordNumber": rec_id,
                        "ComputerName": computer,
                        "ProviderLog": log_name,
                    },
                }
                QUEUE.put(entry)
                seen += 1

            if seen:
                last_record = max_rec_id
                log.info("Forwarded %d new events from %s", seen, source_tag)

        except subprocess.TimeoutExpired:
            pass
        except ET.ParseError:
            pass
        except FileNotFoundError:
            log.error("wevtutil not found — cannot read %s", log_name)
            return
        except Exception as e:
            log.debug("Additional log read error (%s): %s", log_name, e)

        STOP.wait(poll_interval)


def _read_powershell_operational(poll_interval: int = 10):
    _read_additional_log_wevtutil(
        "Microsoft-Windows-PowerShell/Operational",
        "Windows:PowerShell",
        poll_interval,
    )


def _read_sysmon_log(poll_interval: int = 10):
    _read_additional_log_wevtutil(
        "Microsoft-Windows-Sysmon/Operational",
        "Windows:Sysmon",
        poll_interval,
    )


def _read_defender_log(poll_interval: int = 10):
    _read_additional_log_wevtutil(
        "Microsoft-Windows-Windows Defender/Operational",
        "Windows:Defender",
        poll_interval,
    )


# ── Heartbeat Sender ───────────────────────────────────────────────────────

def _heartbeat_sender(siem_url: str, interval: int = 60, agent_version: str = "", agent_id: str = "", agent_key: str = ""):
    global _agent_token
    log_heartbeat_url = f"{siem_url.rstrip('/')}/api/logs/heartbeat"
    auth_heartbeat_url = f"{siem_url.rstrip('/')}/api/auth/agent/{agent_id}/heartbeat"
    session = requests.Session()
    session.verify = False
    while not STOP.is_set():
        payload = {
            "hostname": HOSTNAME,
            "source_type": "chael-agent",
            "status": "online",
            "metadata": {
                "mode": os.environ.get("AGENT_MODE", "unknown"),
                "python_version": platform.python_version(),
                "platform": platform.system(),
                "agent_version": agent_version,
            },
        }
        headers = _get_auth_header()
        try:
            session.post(log_heartbeat_url, json=payload, headers=headers, timeout=10)
        except Exception as e:
            log.debug("Log heartbeat failed: %s", e)
        if agent_id:
            try:
                r = session.post(auth_heartbeat_url, json={"version": agent_version, "metadata": payload["metadata"]}, headers=headers, timeout=10)
                if r.status_code == 401:
                    log.info("Heartbeat auth expired, refreshing token...")
                    token = _authenticate(siem_url, agent_id, agent_key)
                    if token:
                        with _token_lock:
                            _agent_token = token
                        continue
            except Exception as e:
                log.debug("Auth heartbeat failed: %s", e)
        STOP.wait(interval)


# ── Reconnection Loop ────────────────────────────────────────────────────

def _reconnect_loop(siem_url: str, agent_id: str, agent_key: str, interval: int = 30):
    """Periodically re-authenticate to keep the agent online.
    If the token is missing or expired, retries auth. Updates global _agent_token on success.
    Runs as a daemon thread until STOP is set.
    """
    global _agent_token
    mark_online_url = f"{siem_url.rstrip('/')}/api/auth/agent/{agent_id}/mark-online"
    while not STOP.is_set():
        try:
            with _token_lock:
                needs_refresh = _agent_token is None
            if needs_refresh and agent_id and agent_key:
                log.info("Reconnect: attempting to re-authenticate...")
                token = _authenticate(siem_url, agent_id, agent_key)
                if token:
                    with _token_lock:
                        _agent_token = token
                    log.info("Reconnect: authentication successful — marking agent online")
                    try:
                        requests.post(mark_online_url, json={"status": "online"}, timeout=5, verify=False)
                    except Exception:
                        pass
        except Exception as e:
            log.debug("Reconnect loop error: %s", e)
        STOP.wait(interval)


# ── HTTP Forwarder ─────────────────────────────────────────────────────────

def _forwarder(siem_url: str, batch_size: int = 50, agent_id: str = "", agent_key: str = "", retry_interval: int = 10):
    ingest_url = f"{siem_url.rstrip('/')}/api/logs/ingest"
    auth_url = siem_url
    session = requests.Session()
    session.verify = False
    adapter = requests.adapters.HTTPAdapter(pool_connections=2, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    while not STOP.is_set():
        batch = []
        try:
            while len(batch) < batch_size:
                entry = QUEUE.get(timeout=1)
                batch.append(entry)
        except Empty:
            pass

        if not batch:
            continue

        headers = _get_auth_header()
        sent = 0
        for entry in batch:
            for attempt in range(3):
                try:
                    r = session.post(ingest_url, json=entry, headers=headers, timeout=10)
                    if r.status_code == 202:
                        sent += 1
                        break
                    if r.status_code == 401 and agent_id and agent_key:
                        log.info("Token expired, re-authenticating...")
                        token = _authenticate(auth_url, agent_id, agent_key)
                        if token:
                            with _token_lock:
                                global _agent_token
                                _agent_token = token
                            headers = _get_auth_header()
                            continue
                    if attempt < 2:
                        time.sleep(1)
                    else:
                        log.warning("API returned %s: %s", r.status_code, r.text[:100])
                except requests.RequestException as e:
                    if attempt < 2:
                        time.sleep(1)
                    else:
                        log.debug("Failed to send log: %s", e)

        if sent:
            log.info("Forwarded %d/%d logs to %s", sent, len(batch), ingest_url)

        time.sleep(0.5)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Chael SIEM Remote Log Forwarding Agent")
    parser.add_argument("--siem-url", default=os.environ.get("CHAEL_SIEM_URL", "http://localhost:8000"), help="SIEM API base URL")
    parser.add_argument("--mode", default=None, choices=["linux-syslog", "windows-events", "tail", "journald"], help="Log collection mode (auto-detected if omitted)")
    parser.add_argument("--paths", nargs="*", default=[], help="File paths for tail mode")
    parser.add_argument("--journald-units", nargs="*", default=[], help="systemd unit names for journald mode")
    parser.add_argument("--windows-log", default="Security", help="Windows Event Log name (default: Security)")
    parser.add_argument("--windows-event-ids", default=os.environ.get("CHAEL_WINDOWS_EVENT_IDS", ""), help="Comma-separated Event IDs to watch (default: security-relevant IDs only). Use 'all' to forward every event.")
    parser.add_argument("--batch-size", type=int, default=50, help="Logs per batch")
    parser.add_argument("--poll-interval", type=int, default=2, help="Poll interval in seconds")
    parser.add_argument("--agent-id", default=os.environ.get("CHAEL_AGENT_ID", ""), help="Agent ID")
    parser.add_argument("--agent-key", default=os.environ.get("CHAEL_AGENT_KEY", ""), help="Agent key")
    parser.add_argument("--agent-name", default=HOSTNAME, help="Agent display name (defaults to hostname; used for auto-registration if no --agent-id/--agent-key)")

    parser.add_argument("--docker-monitor", action="store_true", default=os.environ.get("CHAEL_DOCKER_MONITOR", "").lower() in ("1", "true", "yes"), help="Enable Docker container monitoring")
    parser.add_argument("--docker-poll-interval", type=int, default=300, help="Docker stats poll interval in seconds")
    parser.add_argument("--registry-monitor", action="store_true", default=os.environ.get("CHAEL_REGISTRY_MONITOR", "").lower() in ("1", "true", "yes"), help="Enable Windows registry monitoring")
    parser.add_argument("--registry-keys", nargs="*", default=[], help="Registry keys to monitor (Windows only)")
    parser.add_argument("--registry-interval", type=int, default=120, help="Registry poll interval in seconds")
    parser.add_argument("--auto-update", action="store_true", default=os.environ.get("CHAEL_AUTO_UPDATE", "").lower() in ("1", "true", "yes"), help="Enable automatic agent updates")
    parser.add_argument("--update-interval", type=int, default=3600, help="Update check interval in seconds")
    parser.add_argument("--agent-version", default=os.environ.get("CHAEL_AGENT_VERSION", "1.0.0"), help="Current agent version")
    parser.add_argument("--powershell-monitor", action="store_true", default=os.environ.get("CHAEL_POWERSHELL_MONITOR", "").lower() in ("1", "true", "yes"), help="Enable PowerShell Operational log monitoring")
    parser.add_argument("--sysmon-monitor", action="store_true", default=os.environ.get("CHAEL_SYSMON_MONITOR", "").lower() in ("1", "true", "yes"), help="Enable Sysmon log monitoring (if Sysmon installed)")
    parser.add_argument("--defender-monitor", action="store_true", default=os.environ.get("CHAEL_DEFENDER_MONITOR", "").lower() in ("1", "true", "yes"), help="Enable Windows Defender log monitoring")
    parser.add_argument("--cis-scan", action="store_true", default=os.environ.get("CHAEL_CIS_SCAN", "").lower() in ("1", "true", "yes"), help="Enable CIS Benchmark scanning")
    parser.add_argument("--cis-interval", type=int, default=86400, help="CIS scan interval in seconds")
    parser.add_argument("--vuln-scan", action="store_true", default=os.environ.get("CHAEL_VULN_SCAN", "").lower() in ("1", "true", "yes"), help="Enable vulnerability scanning")
    parser.add_argument("--vuln-interval", type=int, default=86400, help="Vulnerability scan interval in seconds")
    parser.add_argument("--yara-scan", action="store_true", default=os.environ.get("CHAEL_YARA_SCAN", "").lower() in ("1", "true", "yes"), help="Enable YARA-based file/process scanning")
    parser.add_argument("--yara-interval", type=int, default=3600, help="YARA scan interval in seconds")
    parser.add_argument("--yara-rules-dir", default=os.environ.get("CHAEL_YARA_RULES_DIR", ""), help="Directory containing custom .yar/.yara rule files")
    parser.add_argument("--yara-scan-dirs", nargs="*", default=[], help="Directories to scan with YARA (default: /tmp, /var/tmp, /dev/shm, /home, /root)")
    parser.add_argument("--response-poll", action="store_true", default=os.environ.get("CHAEL_RESPONSE_POLL", "1").lower() not in ("0", "false", "no"), help="Poll SOAR for containment tasks (isolate/block) and execute locally")
    parser.add_argument("--response-interval", type=int, default=int(os.environ.get("CHAEL_RESPONSE_INTERVAL", "30")), help="Response task poll interval in seconds")
    args = parser.parse_args()

    # ── Auto-detect platform and defaults ──────────────────────────────────
    args.mode = args.mode or ("windows-events" if platform.system() == "Windows" else "linux-syslog")
    is_windows = platform.system() == "Windows"

    # ── Resolve watched Event IDs ─────────────────────────────────────────
    watched_ids = None
    if args.windows_event_ids and args.windows_event_ids.strip().lower() == "all":
        watched_ids = ALL_EVENT_IDS
        log.info("--windows-event-ids=all: forwarding ALL Windows Event Log entries")
    elif args.windows_event_ids and args.windows_event_ids.strip():
        try:
            custom_ids = {int(x.strip()) for x in args.windows_event_ids.split(",") if x.strip()}
            watched_ids = custom_ids
            log.info("Using custom Windows Event ID filter: %d IDs", len(watched_ids))
        except ValueError:
            log.error("Invalid --windows-event-ids format. Use comma-separated numbers, e.g. '4624,4625,4720'")
            sys.exit(1)
    else:
        watched_ids = SECURITY_EVENT_IDS
        log.info("Using default security-focused Event ID filter (%d IDs)", len(watched_ids))

    log.info("Chael SIEM Agent starting on %s", HOSTNAME)
    log.info("Platform: %s | Mode: %s | SIEM URL: %s", platform.system(), args.mode, args.siem_url)

    # ── Auto-registration if no agent-id/agent-key provided ──────────────
    if not (args.agent_id and args.agent_key):
        saved = _load_saved_credentials()
        if saved:
            args.agent_id, args.agent_key = saved
            log.info("Loaded saved credentials for agent id=%s", args.agent_id)
        else:
            log.info("No agent-id/agent-key provided — auto-registering as '%s'...", args.agent_name)
            result = _auto_register(args.siem_url, args.agent_name)
            if result:
                args.agent_id, args.agent_key = result
                _save_credentials(args.agent_id, args.agent_key)
                log.info("Auto-registration successful — agent id=%s", args.agent_id)
            else:
                log.error("Auto-registration failed — agent will run without auth.")

    if args.agent_id and args.agent_key:
        log.info("Authenticating with identity service...")
        token = _authenticate(args.siem_url, args.agent_id, args.agent_key)
        if token:
            global _agent_token
            _agent_token = token
            log.info("Authentication successful")
            # ── Fetch agent config from SIEM ──────────────────────────────
            siem_config = _fetch_agent_config(args.siem_url, args.agent_id)
            if siem_config:
                if "windows_event_ids" in siem_config and isinstance(siem_config["windows_event_ids"], list):
                    ids_from_config = {int(x) for x in siem_config["windows_event_ids"] if isinstance(x, int) or (isinstance(x, str) and x.strip().isdigit())}
                    if ids_from_config:
                        watched_ids = ids_from_config
                        log.info("Applied %d watched Event IDs from SIEM config", len(watched_ids))
                if "powershell_log" in siem_config:
                    args.powershell_monitor = bool(siem_config["powershell_log"])
                if "sysmon_log" in siem_config:
                    args.sysmon_monitor = bool(siem_config["sysmon_log"])
                if "defender_log" in siem_config:
                    args.defender_monitor = bool(siem_config["defender_log"])
                if "poll_interval" in siem_config:
                    args.poll_interval = int(siem_config["poll_interval"])
                if "batch_size" in siem_config:
                    args.batch_size = int(siem_config["batch_size"])
        else:
            log.error("Initial authentication failed — credentials may be stale. Clearing and re-registering...")
            _invalidate_saved_credentials()
            result = _auto_register(args.siem_url, args.agent_name)
            if result:
                args.agent_id, args.agent_key = result
                _save_credentials(args.agent_id, args.agent_key)
                token = _authenticate(args.siem_url, args.agent_id, args.agent_key)
                if token:
                    _agent_token = token
                    log.info("Re-registration successful, authenticated")
    else:
        log.warning("No agent-id/agent-key provided — running without authentication")

    # Start reconnection loop: retries auth periodically if token is missing
    reconnect = Thread(
        target=_reconnect_loop,
        args=(args.siem_url, args.agent_id, args.agent_key, 30),
        daemon=True,
    )
    reconnect.start()

    threads = []

    if args.mode == "windows-events":
        if platform.system() != "Windows":
            log.error("windows-events mode requires Windows + pywin32")
            sys.exit(1)
        t = Thread(target=_read_windows_events, args=(args.windows_log, args.poll_interval, watched_ids), daemon=True)
        threads.append(t)

    elif args.mode == "linux-syslog":
        default_paths = ["/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"]
        found = False
        for path in default_paths:
            if os.path.exists(path):
                t = Thread(target=_tail_file, args=(path,), daemon=True)
                threads.append(t)
                found = True
            else:
                log.warning("Log path '%s' not found — skipping", path)
        if not found:
            log.warning("None of the default linux-syslog paths exist — continuing without file tails")

    elif args.mode == "tail":
        if not args.paths:
            log.error("tail mode requires --paths with one or more file paths")
            sys.exit(1)
        for path in args.paths:
            if not os.path.isfile(path):
                log.warning("tail path '%s' not found — skipping", path)
                continue
            t = Thread(target=_tail_file, args=(path,), daemon=True)
            threads.append(t)


    # ── Windows Additional Log Sources ─────────────────────────────────────
    if is_windows:
        if args.powershell_monitor:
            log.info("Starting PowerShell Operational log monitor")
            t = Thread(target=_read_powershell_operational, args=(args.poll_interval,), daemon=True)
            threads.append(t)

        if args.sysmon_monitor:
            log.info("Starting Sysmon log monitor (if installed)")
            t = Thread(target=_read_sysmon_log, args=(args.poll_interval,), daemon=True)
            threads.append(t)

        if args.defender_monitor:
            log.info("Starting Windows Defender log monitor")
            t = Thread(target=_read_defender_log, args=(args.poll_interval,), daemon=True)
            threads.append(t)

    # ── Docker Container Monitoring ────────────────────────────────────────
    if args.docker_monitor:
        log.info("Starting Docker container monitor")
        try:
            from docker_monitor import DockerMonitor
            docker_mon = DockerMonitor(QUEUE, HOSTNAME, args.docker_poll_interval)
            docker_mon.start()
        except ImportError:
            log.warning("Docker SDK not installed. Run: pip install docker")
        except Exception as e:
            log.error("Failed to start Docker monitor: %s", e)

    # ── Agent Auto-Update ──────────────────────────────────────────────────
    if args.auto_update and args.agent_id:
        log.info("Starting auto-updater (version: %s)", args.agent_version)
        try:
            from auto_update import AgentUpdater
            updater = AgentUpdater(
                args.siem_url, args.agent_id, _get_auth_header,
                args.update_interval, args.agent_version
            )
            update_thread = Thread(target=updater.run, daemon=True)
            update_thread.start()
        except Exception as e:
            log.error("Failed to start auto-updater: %s", e)

    # ── Registry Monitoring (Windows) ──────────────────────────────────────
    registry_thread = None
    if args.registry_monitor:
        log.info("Starting Windows registry monitor")
        try:
            from registry_monitor import RegistryMonitor, DEFAULT_REGISTRY_KEYS
            reg_keys = args.registry_keys or DEFAULT_REGISTRY_KEYS
            reg_mon = RegistryMonitor(QUEUE, HOSTNAME, reg_keys, args.registry_interval)
            registry_thread = Thread(target=reg_mon.start, daemon=True)
            registry_thread.start()
            log.info("Registry monitor started (%d keys)", len(reg_keys))
        except ImportError:
            log.warning("registry_monitor module not available")
        except Exception as e:
            log.error("Failed to start registry monitor: %s", e)

    # ── CIS Benchmark Scanning ────────────────────────────────────────────
    if args.cis_scan:
        log.info("Starting CIS Benchmark scanner")
        try:
            from cis_benchmark import CISBenchmark
            cis = CISBenchmark(QUEUE, HOSTNAME, args.cis_interval)
            cis_thread = Thread(target=cis.start, daemon=True)
            cis_thread.start()
            log.info("CIS Benchmark scanner started (interval: %ds)", args.cis_interval)
        except Exception as e:
            log.error("Failed to start CIS Benchmark scanner: %s", e)

    # ── Vulnerability Scanning ────────────────────────────────────────────
    if args.vuln_scan:
        log.info("Starting vulnerability scanner")
        try:
            from vuln_scanner import VulnerabilityScanner
            vuln = VulnerabilityScanner(QUEUE, HOSTNAME, args.vuln_interval)
            vuln_thread = Thread(target=vuln.start, daemon=True)
            vuln_thread.start()
            log.info("Vulnerability scanner started (interval: %ds)", args.vuln_interval)
        except Exception as e:
            log.error("Failed to start vulnerability scanner: %s", e)

    # ── YARA Scanning ────────────────────────────────────────────────────
    if args.yara_scan:
        log.info("Starting YARA scanner")
        try:
            from yara_scanner import YaraScanner
            yara_dirs = args.yara_scan_dirs or None
            yara_scanner = YaraScanner(
                QUEUE, HOSTNAME, args.yara_interval,
                rules_dir=args.yara_rules_dir or None,
                scan_dirs=yara_dirs,
            )
            yara_thread = Thread(target=yara_scanner.start, daemon=True)
            yara_thread.start()
            log.info("YARA scanner started (interval: %ds)", args.yara_interval)
        except Exception as e:
            log.error("Failed to start YARA scanner: %s", e)

    if not threads:
        log.warning("No log sources found for mode '%s' — agent will forward heartbeats only", args.mode)

    for t in threads:
        t.start()

    fwd = Thread(target=_forwarder, args=(args.siem_url, args.batch_size, args.agent_id, args.agent_key), daemon=True)
    fwd.start()

    hb = Thread(target=_heartbeat_sender, args=(args.siem_url, 60, args.agent_version, args.agent_id, args.agent_key), daemon=True)
    hb.start()

    # ── Endpoint response (contain / recover tasks from SOAR) ─────────────
    if args.response_poll and args.agent_id:
        log.info("Starting endpoint response poller")
        try:
            from response import ResponsePoller
            resp_poller = ResponsePoller(
                args.siem_url, args.agent_id, HOSTNAME,
                _get_auth_header, args.response_interval, STOP,
            )
            resp_poller.start()
        except ImportError:
            log.warning("response module not available — containment tasks disabled")
        except Exception as e:
            log.error("Failed to start response poller: %s", e)
    elif not args.agent_id:
        log.warning("No agent-id — response poller needs authentication, skipping")

    try:
        while not STOP.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down...")
        STOP.set()

    for t in threads:
        t.join(timeout=5)
    fwd.join(timeout=5)
    log.info("Agent stopped.")


if __name__ == "__main__":
    main()
