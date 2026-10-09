import logging
import os
import platform
import subprocess
import json
import re
from datetime import datetime, timezone
from queue import Queue
from typing import List, Dict, Any, Optional, Tuple
from threading import Thread, Event

log = logging.getLogger("chael-vuln")

KNOWN_VULN_APPS = {
    "openssl": "openssl version",
    "bash": "bash --version",
    "sudo": "sudo --version",
    "curl": "curl --version",
    "wget": "wget --version",
    "git": "git --version",
    "python3": "python3 --version",
    "nginx": "nginx -v 2>&1",
    "apache2": "apache2 -v 2>&1",
    "mysql": "mysql --version",
    "postgresql": "psql --version",
    "redis-server": "redis-server --version",
    "docker": "docker --version",
    "node": "node --version",
    "npm": "npm --version",
    "php": "php --version",
    "ruby": "ruby --version",
    "java": "java -version 2>&1",
    "openssh": "ssh -V 2>&1",
    "libssh": "dpkg -l libssh-* 2>/dev/null | grep '^ii'",
}


class VulnerabilityScanner:
    def __init__(self, queue: Queue, hostname: str, scan_interval: int = 86400):
        self.queue = queue
        self.hostname = hostname
        self.scan_interval = scan_interval
        self._stop = Event()
        self._system = platform.system()

    def _run_command(self, command: str) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15
            )
            output = (result.stdout + result.stderr).strip()
            return result.returncode == 0, output
        except Exception as e:
            return False, str(e)

    def _get_installed_packages_deb(self) -> List[Dict[str, str]]:
        success, output = self._run_command("dpkg-query -W -f '${Package} ${Version} ${Source}\\n' 2>/dev/null | head -500")
        if not success:
            return []
        packages = []
        for line in output.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 2:
                packages.append({
                    "name": parts[0],
                    "version": parts[1],
                    "source": parts[2] if len(parts) > 2 else parts[0],
                })
        return packages

    def _get_installed_packages_rpm(self) -> List[Dict[str, str]]:
        success, output = self._run_command("rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null | head -500")
        if not success:
            return []
        packages = []
        for line in output.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1]})
        return packages

    def _check_cve_for_package(self, pkg_name: str, pkg_version: str) -> Optional[Dict[str, Any]]:
        known_cves = {
            "sudo": {
                "1.8.0": {"cve": "CVE-2021-3156", "severity": "CRITICAL", "min_fixed": "1.8.31"},
                "1.9.0": {"cve": "CVE-2023-22809", "severity": "HIGH", "min_fixed": "1.9.12"},
            },
            "openssl": {
                "1.0.1": {"cve": "CVE-2014-0160", "severity": "CRITICAL", "min_fixed": "1.0.1g"},
                "1.1.0": {"cve": "CVE-2023-0286", "severity": "HIGH", "min_fixed": "1.1.1t"},
                "3.0.0": {"cve": "CVE-2023-3446", "severity": "MEDIUM", "min_fixed": "3.0.10"},
            },
            "bash": {
                "4.3": {"cve": "CVE-2014-6271", "severity": "CRITICAL", "min_fixed": "4.3-beta2"},
            },
            "openssh": {
                "8.9": {"cve": "CVE-2023-38408", "severity": "HIGH", "min_fixed": "9.3"},
                "9.0": {"cve": "CVE-2024-6387", "severity": "HIGH", "min_fixed": "9.8"},
            },
            "curl": {
                "7.80": {"cve": "CVE-2023-38545", "severity": "HIGH", "min_fixed": "8.4.0"},
            },
        }

        for prefix, info in known_cves.get(pkg_name, {}).items():
            if pkg_version.startswith(prefix):
                return {
                    "package": pkg_name,
                    "version": pkg_version,
                    "cve": info["cve"],
                    "severity": info["severity"],
                    "min_fixed_version": info["min_fixed"],
                }
        return None

    def _check_app_versions(self) -> List[Dict[str, Any]]:
        vulns = []
        for app_name, command in KNOWN_VULN_APPS.items():
            success, output = self._run_command(command)
            if not success or not output:
                continue
            version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
            if not version_match:
                continue
            version = version_match.group(1)
            cve_info = self._check_cve_for_package(app_name, version)
            if cve_info:
                log.warning("Vulnerability found: %s %s - %s", app_name, version, cve_info["cve"])
                vulns.append(cve_info)
        return vulns

    def _scan_installed_packages(self) -> List[Dict[str, Any]]:
        if self._system == "Windows":
            return []
        packages = self._get_installed_packages_deb()
        if not packages:
            packages = self._get_installed_packages_rpm()
        vulns = []
        for pkg in packages:
            try:
                cve_info = self._check_cve_for_package(pkg["name"], pkg["version"])
                if cve_info:
                    vulns.append(cve_info)
            except Exception:
                continue
        return vulns

    def run_scan(self) -> List[Dict[str, Any]]:
        log.info("Starting vulnerability scan on %s", self.hostname)
        all_vulns = self._check_app_versions()
        all_vulns.extend(self._scan_installed_packages())
        if all_vulns:
            log.warning("Found %d vulnerabilities", len(all_vulns))
            for vuln in all_vulns:
                self._emit_vuln_event(vuln)
        else:
            log.info("No vulnerabilities found")
        return all_vulns

    def _emit_vuln_event(self, vuln: Dict[str, Any]):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": self.hostname,
            "source": "vuln_scanner",
            "log_type": "vulnerability",
            "severity": vuln.get("severity", "MEDIUM"),
            "message": f"Vulnerability: {vuln['cve']} in {vuln['package']} {vuln['version']} (fix: {vuln.get('min_fixed_version', 'N/A')})",
            "metadata": {
                "cve_id": vuln["cve"],
                "package_name": vuln["package"],
                "package_version": vuln["version"],
                "min_fixed_version": vuln.get("min_fixed_version", ""),
                "severity": vuln.get("severity", "MEDIUM"),
                "platform": self._system,
                "hostname": self.hostname,
            },
        }
        self.queue.put(event)

    def start(self):
        self.run_scan()

    def stop(self):
        self._stop.set()