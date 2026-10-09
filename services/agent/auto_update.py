"""Agent Auto-Update Module for Chael SIEM Agent.

Periodically polls the identity service for the latest agent version.
If a newer version is available, downloads the update package and
applies it (restarting the agent process).

Uses a simple version comparison and can download from URL or local path.
"""

import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("chael-update")

AGENT_VERSION = "1.0.0"
DEFAULT_CHECK_INTERVAL = 3600


class AgentUpdater:
    def __init__(self, siem_url: str, agent_id: str, auth_header_func,
                 check_interval: int = DEFAULT_CHECK_INTERVAL,
                 current_version: str = AGENT_VERSION):
        self.siem_url = siem_url.rstrip("/")
        self.agent_id = agent_id
        self._get_auth_header = auth_header_func
        self.check_interval = check_interval
        self.current_version = current_version
        self._stop = threading.Event()
        self._downloading = False

    def _check_version(self) -> Optional[dict]:
        try:
            import requests
            resp = requests.get(
                f"{self.siem_url}/api/auth/agent/version",
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            log.debug("Version check failed: %s", e)
        return None

    def _send_heartbeat(self, version: str):
        try:
            import requests
            headers = self._get_auth_header()
            resp = requests.post(
                f"{self.siem_url}/api/auth/agent/{self.agent_id}/heartbeat",
                json={
                    "version": version,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {
                        "platform": platform.system(),
                        "python_version": platform.python_version(),
                    },
                },
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("update_available"):
                    log.info("Update available: %s", data.get("latest_version"))
                    return data
        except Exception as e:
            log.debug("Heartbeat failed: %s", e)
        return None

    def _download_update(self, download_url: str, target_path: str) -> bool:
        try:
            import requests
            log.info("Downloading update from %s", download_url)
            resp = requests.get(download_url, stream=True, timeout=120)
            resp.raise_for_status()
            with open(target_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            log.info("Downloaded update to %s", target_path)
            return True
        except Exception as e:
            log.error("Download failed: %s", e)
            return False

    def _apply_update(self, update_path: str) -> bool:
        try:
            if platform.system() == "Windows":
                script = (
                    f'@echo off\n'
                    f'timeout /t 2 /nobreak >nul\n'
                    f'copy /y "{update_path}" "{sys.argv[0]}"\n'
                    f'start "" "{sys.argv[0]}" {" ".join(sys.argv[1:])}\n'
                    f'del "%~f0"\n'
                )
                bat_path = os.path.join(tempfile.gettempdir(), "chael_update.bat")
                with open(bat_path, "w") as f:
                    f.write(script)
                subprocess.Popen(["cmd", "/c", bat_path],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                shutil.copy2(update_path, sys.argv[0])
                os.chmod(sys.argv[0], 0o755)

            log.info("Update applied, restarting...")
            os._exit(0)
            return True
        except Exception as e:
            log.error("Failed to apply update: %s", e)
            return False

    def run(self):
        log.info("Agent updater started (version: %s, check interval: %ds)",
                 self.current_version, self.check_interval)

        while not self._stop.is_set():
            # Send heartbeat with current version
            update_info = self._send_heartbeat(self.current_version)

            if update_info and update_info.get("update_available"):
                version_info = self._check_version()
                if version_info:
                    latest = version_info.get("latest_version", "")
                    download_url = version_info.get("download_url", "")
                    log.info("New version available: %s (current: %s)",
                             latest, self.current_version)

                    if download_url and not self._downloading:
                        self._downloading = True
                        try:
                            ext = ".exe" if platform.system() == "Windows" else ".py"
                            with tempfile.NamedTemporaryFile(
                                    suffix=ext, delete=False) as tmp:
                                tmp_path = tmp.name
                            if self._download_update(download_url, tmp_path):
                                self._apply_update(tmp_path)
                        finally:
                            self._downloading = False

            self._stop.wait(self.check_interval)

        log.info("Agent updater stopped")

    def stop(self):
        self._stop.set()
