import logging
import os
import platform
import subprocess
import threading
from typing import Optional, List, Type

logger = logging.getLogger(__name__)


class FirewallBackend:
    name = "base"

    @classmethod
    def is_available(cls) -> bool:
        return False

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        raise NotImplementedError

    def unblock_ip(self, ip: str) -> dict:
        raise NotImplementedError


class IptablesBackend(FirewallBackend):
    name = "iptables"

    @classmethod
    def is_available(cls) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            subprocess.run(["iptables", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        logger.info("Blocking IP %s via iptables (duration: %d min)", ip, duration_minutes)
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            if duration_minutes > 0:
                threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()
            return {"success": True, "backend": "iptables", "ip": ip, "duration_minutes": duration_minutes}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("iptables block failed for %s: %s", ip, err)
            return {"success": False, "backend": "iptables", "ip": ip, "error": err}

    def unblock_ip(self, ip: str) -> dict:
        logger.info("Unblocking IP %s via iptables", ip)
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            return {"success": True, "backend": "iptables", "ip": ip}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.warning("iptables unblock failed for %s: %s", ip, err)
            return {"success": False, "backend": "iptables", "ip": ip, "error": err}


class NetshBackend(FirewallBackend):
    name = "netsh"

    @classmethod
    def is_available(cls) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            subprocess.run(["netsh", "advfirewall", "show", "currentprofile"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        logger.info("Blocking IP %s via Windows Firewall (duration: %d min)", ip, duration_minutes)
        rule_name = f"SOAR_Block_{ip.replace('.', '_')}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True, capture_output=True, timeout=10,
            )
            if duration_minutes > 0:
                threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()
            return {"success": True, "backend": "netsh", "ip": ip, "duration_minutes": duration_minutes, "rule_name": rule_name}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("netsh block failed for %s: %s", ip, err)
            return {"success": False, "backend": "netsh", "ip": ip, "error": err}

    def unblock_ip(self, ip: str) -> dict:
        rule_name = f"SOAR_Block_{ip.replace('.', '_')}"
        logger.info("Unblocking IP %s via Windows Firewall", ip)
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=True, capture_output=True, timeout=10,
            )
            return {"success": True, "backend": "netsh", "ip": ip}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.warning("netsh unblock failed for %s: %s", ip, err)
            return {"success": False, "backend": "netsh", "ip": ip, "error": err}


class UfwBackend(FirewallBackend):
    name = "ufw"

    @classmethod
    def is_available(cls) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, timeout=5)
            return result.returncode == 0 and b"inactive" not in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        logger.info("Blocking IP %s via UFW (duration: %d min)", ip, duration_minutes)
        try:
            subprocess.run(["ufw", "deny", "from", ip], check=True, capture_output=True, timeout=10)
            if duration_minutes > 0:
                threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()
            return {"success": True, "backend": "ufw", "ip": ip, "duration_minutes": duration_minutes}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("ufw block failed for %s: %s", ip, err)
            return {"success": False, "backend": "ufw", "ip": ip, "error": err}

    def unblock_ip(self, ip: str) -> dict:
        logger.info("Unblocking IP %s via UFW", ip)
        try:
            subprocess.run(["ufw", "delete", "deny", "from", ip], check=True, capture_output=True, timeout=10)
            return {"success": True, "backend": "ufw", "ip": ip}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.warning("ufw unblock failed for %s: %s", ip, err)
            return {"success": False, "backend": "ufw", "ip": ip, "error": err}


class SimulatedBackend(FirewallBackend):
    name = "simulated"

    @classmethod
    def is_available(cls) -> bool:
        return True

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        logger.info("[SIMULATED] Blocking IP %s for %d minutes", ip, duration_minutes)
        return {"success": True, "backend": "simulated", "ip": ip, "duration_minutes": duration_minutes, "simulated": True}

    def unblock_ip(self, ip: str) -> dict:
        logger.info("[SIMULATED] Unblocking IP %s", ip)
        return {"success": True, "backend": "simulated", "ip": ip, "simulated": True}


class FirewallBlocker:
    _backends: List[Type[FirewallBackend]] = [IptablesBackend, NetshBackend, UfwBackend, SimulatedBackend]

    def __init__(self, backend_name: Optional[str] = None):
        self.backend = self._select_backend(backend_name)
        logger.info("Firewall backend selected: %s", self.backend.name)

    @classmethod
    def _select_backend(cls, backend_name: Optional[str] = None) -> FirewallBackend:
        if backend_name and backend_name != "auto":
            for bk in cls._backends:
                if bk.name == backend_name:
                    if bk.is_available():
                        return bk()
                    logger.warning("Requested firewall backend '%s' unavailable, falling back", backend_name)
                    break
        for bk in cls._backends:
            if bk.is_available():
                return bk()
        return SimulatedBackend()

    def block_ip(self, ip: str, duration_minutes: int = 0) -> dict:
        return self.backend.block_ip(ip, duration_minutes)

    def unblock_ip(self, ip: str) -> dict:
        return self.backend.unblock_ip(ip)
