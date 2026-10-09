"""Windows Registry Monitoring Module for Chael SIEM Agent.

Monitors Windows registry keys for changes (create, modify, delete)
using winreg notification APIs. Emits structured log entries to the
agent's forwarding queue.

Windows-only: requires the _winreg / winreg built-in module.
"""

import os
import logging
import threading
import time
from datetime import datetime, timezone
from queue import Queue
from typing import List, Optional, Dict, Any

log = logging.getLogger("chael-registry")

DEFAULT_POLL_INTERVAL = 120

# Default critical registry keys to monitor
DEFAULT_REGISTRY_KEYS = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog",
]

_HIVE_MAP = {
    "HKEY_LOCAL_MACHINE": 0x80000002,
    "HKEY_CURRENT_USER": 0x80000001,
    "HKEY_CLASSES_ROOT": 0x80000000,
    "HKEY_USERS": 0x80000003,
    "HKEY_CURRENT_CONFIG": 0x80000005,
}


def _parse_reg_path(full_path: str) -> Optional[Dict[str, Any]]:
    try:
        parts = full_path.replace("/", "\\").split("\\", 1)
        hive_name = parts[0].upper()
        if hive_name not in _HIVE_MAP and hive_name.startswith("HKEY_"):
            hive_name = hive_name
        hive_const = _HIVE_MAP.get(hive_name)
        sub_key = parts[1] if len(parts) > 1 else ""
        return {"hive": hive_name, "hive_const": hive_const, "sub_key": sub_key}
    except Exception:
        return None


class RegistryMonitor:
    """Monitor Windows registry for changes.

    Uses periodic polling with value comparison since winreg does not
    natively support cross-process change notification from Python.
    For each monitored key, snapshots values and compares against
    previous snapshot to detect additions, modifications, and deletions.
    """

    def __init__(self, queue: Queue, hostname: str,
                 keys: Optional[List[str]] = None,
                 poll_interval: int = DEFAULT_POLL_INTERVAL):
        self.queue = queue
        self.hostname = hostname
        self.keys = keys or DEFAULT_REGISTRY_KEYS
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._snapshots: Dict[str, Dict[str, Any]] = {}

    def _snapshot_key(self, parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        import winreg
        try:
            hive = parsed["hive_const"]
            sub_key = parsed["sub_key"]
            with winreg.OpenKey(hive, sub_key, 0, winreg.KEY_READ) as key:
                values = {}
                i = 0
                while True:
                    try:
                        name, data, dtype = winreg.EnumValue(key, i)
                        values[name] = {
                            "data": data,
                            "type": dtype,
                        }
                        i += 1
                    except OSError:
                        break
                return values
        except FileNotFoundError:
            return None
        except Exception as e:
            log.debug("Cannot snapshot %s: %s", parsed["sub_key"], e)
            return None

    def _key_name(self, parsed: Dict[str, Any]) -> str:
        return f"{parsed['hive']}\\{parsed['sub_key']}"

    def _emit_event(self, key_path: str, change_type: str,
                    value_name: str = "", old_value: Any = None,
                    new_value: Any = None):
        severity = "HIGH" if change_type in ("modified", "deleted") else "MEDIUM"

        # Run keys are high-severity
        if "\\Run" in key_path or "\\RunOnce" in key_path:
            severity = "HIGH"

        if change_type == "added" and "\\Run" in key_path:
            severity = "CRITICAL"

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": self.hostname,
            "source": "registry",
            "log_type": "windows",
            "severity": severity,
            "message": f"Registry: {change_type.upper()} {value_name} in {key_path}",
            "metadata": {
                "registry_event_type": f"registry:{change_type}",
                "key_path": key_path,
                "value_name": value_name,
                "old_value": str(old_value) if old_value is not None else "",
                "new_value": str(new_value) if new_value is not None else "",
                "platform": "Windows",
                "hostname": self.hostname,
            },
        }
        self.queue.put(entry)

    def _poll_once(self):
        import winreg as _  # noqa: ensure winreg available
        for key_path in self.keys:
            if self._stop.is_set():
                break
            parsed = _parse_reg_path(key_path)
            if not parsed:
                log.warning("Invalid registry path: %s", key_path)
                continue

            key_name = self._key_name(parsed)
            snapshot = self._snapshot_key(parsed)
            prev = self._snapshots.get(key_name)

            if prev is None and snapshot is None:
                continue
            if prev is None and snapshot is not None:
                # First time seeing this key — snapshot only, no events
                self._snapshots[key_name] = snapshot
                continue

            if prev is not None and snapshot is None:
                # Key was deleted
                self._emit_event(key_name, "deleted", value_name="(entire key)")
                del self._snapshots[key_name]
                continue

            if prev is not None and snapshot is not None:
                # Compare snapshots
                prev_values = prev
                curr_values = snapshot

                # Added values
                for name in curr_values:
                    if name not in prev_values:
                        data = curr_values[name].get("data", "")
                        self._emit_event(key_name, "added", value_name=str(name),
                                         new_value=str(data))

                # Deleted values
                for name in prev_values:
                    if name not in curr_values:
                        data = prev_values[name].get("data", "")
                        self._emit_event(key_name, "deleted", value_name=str(name),
                                         old_value=str(data))

                # Modified values
                for name in curr_values:
                    if name in prev_values:
                        if curr_values[name] != prev_values[name]:
                            old = prev_values[name].get("data", "")
                            new = curr_values[name].get("data", "")
                            self._emit_event(key_name, "modified",
                                             value_name=str(name),
                                             old_value=str(old),
                                             new_value=str(new))

                self._snapshots[key_name] = snapshot

    def start(self):
        if os.name != "nt":
            log.warning("Registry monitor is Windows-only — not starting")
            return

        try:
            import winreg
        except ImportError:
            log.warning("winreg module not available — registry monitor disabled")
            return

        log.info("Registry monitor started (%d keys, interval: %ds)",
                 len(self.keys), self.poll_interval)

        # Initial snapshot
        for key_path in self.keys:
            parsed = _parse_reg_path(key_path)
            if parsed:
                snapshot = self._snapshot_key(parsed)
                if snapshot is not None:
                    self._snapshots[self._key_name(parsed)] = snapshot

        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(self.poll_interval)

        log.info("Registry monitor stopped")

    def stop(self):
        self._stop.set()
