import logging
import os
import platform
import subprocess
import threading
import json
import time
from typing import Optional, List, Type
try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class IsolationBackend:
    name = "base"

    @classmethod
    def is_available(cls) -> bool:
        return False

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        raise NotImplementedError

    def unisolate(self, hostname: str) -> dict:
        raise NotImplementedError


class NetshIsolationBackend(IsolationBackend):
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

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        logger.info("Isolating host %s via Windows Firewall (duration: %d min)", hostname, duration_minutes)
        try:
            if hostname in ("localhost", "127.0.0.1", platform.node(), ""):
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
                    check=True, capture_output=True, timeout=10,
                )
                if duration_minutes > 0:
                    threading.Timer(duration_minutes * 60, self.unisolate, args=[hostname]).start()
                return {"success": True, "backend": "netsh", "hostname": hostname, "local": True, "duration_minutes": duration_minutes}
            else:
                logger.warning("Remote isolation via netsh not supported for %s", hostname)
                return {"success": False, "backend": "netsh", "hostname": hostname, "error": "Remote isolation not supported via Windows Firewall"}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("netsh isolation failed for %s: %s", hostname, err)
            return {"success": False, "backend": "netsh", "hostname": hostname, "error": err}

    def unisolate(self, hostname: str) -> dict:
        logger.info("Restoring firewall policy for host %s", hostname)
        try:
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                check=True, capture_output=True, timeout=10,
            )
            return {"success": True, "backend": "netsh", "hostname": hostname}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("Failed to restore firewall policy: %s", err)
            return {"success": False, "backend": "netsh", "hostname": hostname, "error": err}


class IptablesIsolationBackend(IsolationBackend):
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

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        logger.info("Isolating host %s via iptables (duration: %d min)", hostname, duration_minutes)
        try:
            if hostname in ("localhost", "127.0.0.1", platform.node(), ""):
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["iptables", "-P", "OUTPUT", "DROP"],
                    check=True, capture_output=True, timeout=10,
                )
                if duration_minutes > 0:
                    threading.Timer(duration_minutes * 60, self.unisolate, args=[hostname]).start()
                return {"success": True, "backend": "iptables", "hostname": hostname, "local": True, "duration_minutes": duration_minutes}
            else:
                logger.warning("Remote isolation via iptables not directly supported for %s", hostname)
                return {"success": False, "backend": "iptables", "hostname": hostname, "error": "Remote isolation not supported via iptables"}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("iptables isolation failed for %s: %s", hostname, err)
            return {"success": False, "backend": "iptables", "hostname": hostname, "error": err}

    def unisolate(self, hostname: str) -> dict:
        logger.info("Restoring iptables policy for host %s", hostname)
        try:
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True, capture_output=True, timeout=10)
            return {"success": True, "backend": "iptables", "hostname": hostname}
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error("Failed to restore iptables policy: %s", err)
            return {"success": False, "backend": "iptables", "hostname": hostname, "error": err}


class EDRIsolationBackend(IsolationBackend):
    name = "edr"

    EDR_PROVIDERS = {
        "crowdstrike": {"env_api": "CS_API_KEY", "env_client_id": "CS_CLIENT_ID", "env_host": "CS_API_HOST"},
        "sentinelone": {"env_api": "S1_API_TOKEN", "env_host": "S1_API_HOST"},
        "defender": {"env_api": "DEFENDER_API_KEY", "env_client_id": "DEFENDER_CLIENT_ID", "env_tenant": "DEFENDER_TENANT_ID", "env_host": "DEFENDER_API_HOST"},
    }

    def __init__(self, provider: Optional[str] = None):
        self.provider = provider or os.getenv("EDR_PROVIDER", "")
        if not self.provider:
            for name, config in self.EDR_PROVIDERS.items():
                if os.getenv(config["env_api"]):
                    self.provider = name
                    break
        if requests is None:
            logger.warning("requests library not available, EDR calls will be simulated")

    @classmethod
    def is_available(cls) -> bool:
        for config in cls.EDR_PROVIDERS.values():
            if os.getenv(config["env_api"]):
                return True
        return False

    def _crowdstrike_isolate(self, hostname: str, duration_minutes: int) -> dict:
        api_key = os.getenv("CS_API_KEY", "")
        client_id = os.getenv("CS_CLIENT_ID", "")
        api_host = os.getenv("CS_API_HOST", "https://api.crowdstrike.com")
        try:
            token_resp = requests.post(
                f"{api_host}/oauth2/token",
                data={"client_id": client_id, "client_secret": api_key},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if token_resp.status_code != 201:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Auth failed: {token_resp.status_code}"}
            token = token_resp.json().get("access_token")
            headers = {"Authorization": f"bearer {token}", "Content-Type": "application/json"}
            device_resp = requests.get(
                f"{api_host}/devices/queries/devices/v1?filter=hostname:'{hostname}'",
                headers=headers, timeout=15,
            )
            if device_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Device lookup failed: {device_resp.status_code}"}
            devices = device_resp.json().get("resources", [])
            if not devices:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Host {hostname} not found"}
            resp = requests.post(
                f"{api_host}/devices/entities/devices-actions/v1?action_name=contain",
                headers=headers, json={"ids": devices}, timeout=30,
            )
            if resp.status_code in (200, 202):
                return {"success": True, "backend": "edr", "provider": "crowdstrike", "hostname": hostname, "duration_minutes": duration_minutes, "action": "contain"}
            return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Isolation failed: {resp.status_code}"}
        except Exception as e:
            logger.error("CrowdStrike isolation error: %s", e)
            return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": str(e), "simulated": True}

    def _crowdstrike_unisolate(self, hostname: str) -> dict:
        api_key = os.getenv("CS_API_KEY", "")
        client_id = os.getenv("CS_CLIENT_ID", "")
        api_host = os.getenv("CS_API_HOST", "https://api.crowdstrike.com")
        try:
            token_resp = requests.post(
                f"{api_host}/oauth2/token",
                data={"client_id": client_id, "client_secret": api_key},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if token_resp.status_code != 201:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Auth failed: {token_resp.status_code}"}
            token = token_resp.json().get("access_token")
            headers = {"Authorization": f"bearer {token}", "Content-Type": "application/json"}
            device_resp = requests.get(
                f"{api_host}/devices/queries/devices/v1?filter=hostname:'{hostname}'",
                headers=headers, timeout=15,
            )
            if device_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Device lookup failed: {device_resp.status_code}"}
            devices = device_resp.json().get("resources", [])
            if not devices:
                return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Host {hostname} not found"}
            resp = requests.post(
                f"{api_host}/devices/entities/devices-actions/v1?action_name=lift_containment",
                headers=headers, json={"ids": devices}, timeout=30,
            )
            if resp.status_code in (200, 202):
                return {"success": True, "backend": "edr", "provider": "crowdstrike", "hostname": hostname, "action": "lift_containment"}
            return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": f"Unisolate failed: {resp.status_code}"}
        except Exception as e:
            logger.error("CrowdStrike unisolate error: %s", e)
            return {"success": False, "backend": "edr", "provider": "crowdstrike", "error": str(e), "simulated": True}

    def _sentinelone_isolate(self, hostname: str, duration_minutes: int) -> dict:
        token = os.getenv("S1_API_TOKEN", "")
        api_host = os.getenv("S1_API_HOST", "https://your-instance.sentinelone.net")
        try:
            headers = {"Authorization": f"APIToken {token}", "Content-Type": "application/json"}
            agent_resp = requests.get(
                f"{api_host}/web/api/v2.1/agents?hostname={hostname}",
                headers=headers, timeout=15,
            )
            if agent_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Agent lookup failed: {agent_resp.status_code}"}
            data = agent_resp.json()
            agents = data.get("data", []) if isinstance(data, dict) else []
            if not agents:
                return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Host {hostname} not found"}
            agent_id = agents[0].get("id")
            resp = requests.post(
                f"{api_host}/web/api/v2.1/agents/actions/disconnect",
                headers=headers, json={"filter": {"ids": [agent_id]}, "data": {"shouldDisconnect": True}},
                timeout=30,
            )
            if resp.status_code == 200:
                return {"success": True, "backend": "edr", "provider": "sentinelone", "hostname": hostname, "duration_minutes": duration_minutes}
            return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Isolation failed: {resp.status_code}"}
        except Exception as e:
            logger.error("SentinelOne isolation error: %s", e)
            return {"success": False, "backend": "edr", "provider": "sentinelone", "error": str(e), "simulated": True}

    def _sentinelone_unisolate(self, hostname: str) -> dict:
        token = os.getenv("S1_API_TOKEN", "")
        api_host = os.getenv("S1_API_HOST", "https://your-instance.sentinelone.net")
        try:
            headers = {"Authorization": f"APIToken {token}", "Content-Type": "application/json"}
            agent_resp = requests.get(
                f"{api_host}/web/api/v2.1/agents?hostname={hostname}",
                headers=headers, timeout=15,
            )
            if agent_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Agent lookup failed: {agent_resp.status_code}"}
            data = agent_resp.json()
            agents = data.get("data", []) if isinstance(data, dict) else []
            if not agents:
                return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Host {hostname} not found"}
            agent_id = agents[0].get("id")
            resp = requests.post(
                f"{api_host}/web/api/v2.1/agents/actions/connect",
                headers=headers, json={"filter": {"ids": [agent_id]}},
                timeout=30,
            )
            if resp.status_code == 200:
                return {"success": True, "backend": "edr", "provider": "sentinelone", "hostname": hostname}
            return {"success": False, "backend": "edr", "provider": "sentinelone", "error": f"Unisolate failed: {resp.status_code}"}
        except Exception as e:
            logger.error("SentinelOne unisolate error: %s", e)
            return {"success": False, "backend": "edr", "provider": "sentinelone", "error": str(e), "simulated": True}

    def _defender_isolate(self, hostname: str, duration_minutes: int) -> dict:
        tenant_id = os.getenv("DEFENDER_TENANT_ID", "")
        client_id = os.getenv("DEFENDER_CLIENT_ID", "")
        client_secret = os.getenv("DEFENDER_API_KEY", "")
        api_host = os.getenv("DEFENDER_API_HOST", "https://api.security.microsoft.com")
        try:
            token_resp = requests.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={"client_id": client_id, "client_secret": client_secret, "scope": "https://api.security.microsoft.com/.default", "grant_type": "client_credentials"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if token_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Auth failed: {token_resp.status_code}"}
            token = token_resp.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            machine_resp = requests.get(
                f"{api_host}/api/machines?$filter=computerDnsName eq '{hostname}'",
                headers=headers, timeout=15,
            )
            if machine_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Machine lookup failed: {machine_resp.status_code}"}
            machines = machine_resp.json().get("value", [])
            if not machines:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Host {hostname} not found"}
            machine_id = machines[0].get("id")
            resp = requests.post(
                f"{api_host}/api/machines/{machine_id}/isolate",
                headers=headers,
                json={"IsolationType": "Full", "DurationInMinutes": duration_minutes if duration_minutes > 0 else 60},
                timeout=30,
            )
            if resp.status_code in (200, 201):
                return {"success": True, "backend": "edr", "provider": "defender", "hostname": hostname, "duration_minutes": duration_minutes}
            return {"success": False, "backend": "edr", "provider": "defender", "error": f"Isolation failed: {resp.status_code}"}
        except Exception as e:
            logger.error("Defender isolation error: %s", e)
            return {"success": False, "backend": "edr", "provider": "defender", "error": str(e), "simulated": True}

    def _defender_unisolate(self, hostname: str) -> dict:
        tenant_id = os.getenv("DEFENDER_TENANT_ID", "")
        client_id = os.getenv("DEFENDER_CLIENT_ID", "")
        client_secret = os.getenv("DEFENDER_API_KEY", "")
        api_host = os.getenv("DEFENDER_API_HOST", "https://api.security.microsoft.com")
        try:
            token_resp = requests.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={"client_id": client_id, "client_secret": client_secret, "scope": "https://api.security.microsoft.com/.default", "grant_type": "client_credentials"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if token_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Auth failed: {token_resp.status_code}"}
            token = token_resp.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            machine_resp = requests.get(
                f"{api_host}/api/machines?$filter=computerDnsName eq '{hostname}'",
                headers=headers, timeout=15,
            )
            if machine_resp.status_code != 200:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Machine lookup failed: {machine_resp.status_code}"}
            machines = machine_resp.json().get("value", [])
            if not machines:
                return {"success": False, "backend": "edr", "provider": "defender", "error": f"Host {hostname} not found"}
            machine_id = machines[0].get("id")
            resp = requests.post(
                f"{api_host}/api/machines/{machine_id}/unisolate",
                headers=headers, timeout=30,
            )
            if resp.status_code in (200, 201):
                return {"success": True, "backend": "edr", "provider": "defender", "hostname": hostname}
            return {"success": False, "backend": "edr", "provider": "defender", "error": f"Unisolate failed: {resp.status_code}"}
        except Exception as e:
            logger.error("Defender unisolate error: %s", e)
            return {"success": False, "backend": "edr", "provider": "defender", "error": str(e), "simulated": True}

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        if not self.provider:
            return {"success": False, "backend": "edr", "hostname": hostname, "error": "No EDR provider configured. Set EDR_PROVIDER and corresponding API key."}
        logger.info("Isolating host %s via %s (duration: %d min)", hostname, self.provider, duration_minutes)
        if requests is None:
            logger.warning("requests not available, simulating EDR call")
            return {"success": True, "backend": "edr", "provider": self.provider, "hostname": hostname, "duration_minutes": duration_minutes, "simulated": True}
        dispatch = {"crowdstrike": self._crowdstrike_isolate, "sentinelone": self._sentinelone_isolate, "defender": self._defender_isolate}
        handler = dispatch.get(self.provider)
        if not handler:
            return {"success": False, "backend": "edr", "provider": self.provider, "error": f"Unknown EDR provider: {self.provider}"}
        result = handler(hostname, duration_minutes)
        if result.get("simulated"):
            logger.info("EDR API call simulated (credentials may be missing or invalid)")
        return result

    def unisolate(self, hostname: str) -> dict:
        if not self.provider:
            return {"success": False, "backend": "edr", "hostname": hostname, "error": "No EDR provider configured"}
        logger.info("Releasing isolation for host %s via %s", hostname, self.provider)
        if requests is None:
            return {"success": True, "backend": "edr", "provider": self.provider, "hostname": hostname, "simulated": True}
        dispatch = {"crowdstrike": self._crowdstrike_unisolate, "sentinelone": self._sentinelone_unisolate, "defender": self._defender_unisolate}
        handler = dispatch.get(self.provider)
        if not handler:
            return {"success": False, "backend": "edr", "provider": self.provider, "error": f"Unknown EDR provider: {self.provider}"}
        return handler(hostname)


class SimulatedIsolationBackend(IsolationBackend):
    name = "simulated"

    @classmethod
    def is_available(cls) -> bool:
        return True

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        logger.info("[SIMULATED] Isolating host %s for %d minutes", hostname, duration_minutes)
        return {"success": True, "backend": "simulated", "hostname": hostname, "duration_minutes": duration_minutes, "simulated": True}

    def unisolate(self, hostname: str) -> dict:
        logger.info("[SIMULATED] Releasing isolation for host %s", hostname)
        return {"success": True, "backend": "simulated", "hostname": hostname, "simulated": True}


class HostIsolator:
    _backends: List[Type[IsolationBackend]] = [NetshIsolationBackend, IptablesIsolationBackend, EDRIsolationBackend, SimulatedIsolationBackend]

    def __init__(self, backend_name: Optional[str] = None, edr_provider: Optional[str] = None):
        self.backend = self._select_backend(backend_name, edr_provider)
        name = getattr(self.backend, 'provider', self.backend.name)
        logger.info("Host isolation backend selected: %s", name)

    @classmethod
    def _select_backend(cls, backend_name: Optional[str] = None, edr_provider: Optional[str] = None) -> IsolationBackend:
        if backend_name and backend_name != "auto":
            if backend_name == "edr" and edr_provider:
                return EDRIsolationBackend(provider=edr_provider)
            for bk in cls._backends:
                if bk.name == backend_name and bk != EDRIsolationBackend:
                    if bk.is_available():
                        return bk()
                    logger.warning("Requested isolation backend '%s' unavailable, falling back", backend_name)
                    break
        for bk in cls._backends:
            if bk.is_available():
                if bk == EDRIsolationBackend:
                    return bk(provider=edr_provider)
                return bk()
        return SimulatedIsolationBackend()

    def isolate(self, hostname: str, duration_minutes: int = 0) -> dict:
        return self.backend.isolate(hostname, duration_minutes)

    def unisolate(self, hostname: str) -> dict:
        return self.backend.unisolate(hostname)
