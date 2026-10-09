"""Docker Container Monitoring Module for Chael SIEM Agent.

Monitors Docker daemon events and container statistics,
emitting structured log entries to the agent's forwarding queue.

Requires: docker SDK (pip install docker)
"""

import os
import json
import logging
import threading
import time
from datetime import datetime, timezone
from queue import Queue
from typing import Optional

log = logging.getLogger("chael-docker")

DEFAULT_POLL_INTERVAL = 300
DEFAULT_EVENT_TIMEOUT = 5


class DockerMonitor:
    def __init__(
        self,
        queue: Queue,
        hostname: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ):
        self.queue = queue
        self.hostname = hostname
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import docker
            self._client = docker.from_env()
            self._client.ping()
            return self._client
        except Exception as e:
            log.error("Docker client init failed: %s", e)
            return None

    def _emit_event(self, event_type: str, container_info: dict, severity: str,
                    message: str, metadata: dict):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": self.hostname,
            "source": "docker",
            "log_type": "docker",
            "severity": severity,
            "message": message,
            "metadata": {
                "docker_event_type": event_type,
                "container_id": container_info.get("id", ""),
                "container_name": container_info.get("name", ""),
                "container_image": container_info.get("image", ""),
                "container_status": container_info.get("status", ""),
                **metadata,
            },
        }
        self.queue.put(entry)

    def _monitor_events(self):
        client = self._get_client()
        if not client:
            return

        log.info("Started Docker event monitor")
        while not self._stop.is_set():
            try:
                for event in client.events(decode=True, since=None):
                    if self._stop.is_set():
                        break
                    self._process_event(event)
            except Exception as e:
                if not self._stop.is_set():
                    log.warning("Docker event stream error: %s", e)
                    self._stop.wait(5)

    def _process_event(self, event: dict):
        etype = event.get("Type", "")
        action = event.get("Action", "")
        actor = event.get("Actor", {})
        attributes = actor.get("Attributes", {})

        if etype != "container":
            return

        container_info = {
            "id": event.get("id", actor.get("ID", ""))[:12],
            "name": attributes.get("name", "unknown"),
            "image": attributes.get("image", "unknown"),
            "status": action,
        }

        # Only emit security-relevant container events (reduces noise)
        if action in ("die", "oom", "kill"):
            severity = "HIGH"
            message = f"Container {container_info['name']} {action} (image: {container_info['image']})"
        elif action in ("health_status: unhealthy",):
            severity = "CRITICAL"
            message = f"Container {container_info['name']} health check FAILED"
        elif action in ("destroy", "remove"):
            severity = "MEDIUM"
            message = f"Container {container_info['name']} removed"
        else:
            # Skip routine start/stop/restart events
            return

        self._emit_event(
            event_type=f"docker:{action}",
            container_info=container_info,
            severity=severity,
            message=message,
            metadata={
                "action": action,
                "event_type": etype,
                "attributes": attributes,
            },
        )

    def _poll_stats(self):
        client = self._get_client()
        if not client:
            return

        log.info("Started Docker stats poller (interval: %ds)", self.poll_interval)
        while not self._stop.is_set():
            try:
                containers = client.containers.list(all=False)
                for container in containers:
                    if self._stop.is_set():
                        break
                    try:
                        stats = container.stats(stream=False)
                        self._process_stats(container, stats)
                    except Exception as e:
                        log.debug("Stats error for %s: %s", container.name, e)
            except Exception as e:
                log.warning("Docker stats poll error: %s", e)

            self._stop.wait(self.poll_interval)

    def _process_stats(self, container, stats: dict):
        name = container.name
        cid = container.short_id

        cpu_delta = stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        precpu_delta = stats.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        system_delta = stats.get("cpu_stats", {}).get("system_cpu_usage", 0)
        precpu_system = stats.get("precpu_stats", {}).get("system_cpu_usage", 0)
        num_cpus = stats.get("cpu_stats", {}).get("online_cpus", 1)

        cpu_percent = 0.0
        cpu_diff = cpu_delta - precpu_delta
        sys_diff = system_delta - precpu_system
        if sys_diff > 0 and cpu_diff > 0:
            cpu_percent = (cpu_diff / sys_diff) * num_cpus * 100.0

        mem_stats = stats.get("memory_stats", {})
        mem_usage = mem_stats.get("usage", 0)
        mem_limit = mem_stats.get("limit", 1)
        mem_percent = (mem_usage / mem_limit) * 100.0 if mem_limit > 0 else 0.0

        # Only emit stats events when resource usage is high (reduces noise)
        if cpu_percent < 80 and mem_percent < 80:
            return

        severity = "INFO"
        if cpu_percent > 90 or mem_percent > 90:
            severity = "HIGH"
        elif cpu_percent > 75 or mem_percent > 75:
            severity = "MEDIUM"

        self._emit_event(
            event_type="docker:stats",
            container_info={"id": cid, "name": name, "image": container.image.tags[0] if container.image.tags else "unknown", "status": container.status},
            severity=severity,
            message=f"Container {name} high resource usage — CPU: {cpu_percent:.1f}%, MEM: {mem_percent:.1f}%",
            metadata={
                "cpu_percent": round(cpu_percent, 1),
                "mem_usage_bytes": mem_usage,
                "mem_limit_bytes": mem_limit,
                "mem_percent": round(mem_percent, 1),
                "num_cpus": num_cpus,
            },
        )

    def start(self):
        event_thread = threading.Thread(target=self._monitor_events, daemon=True)
        event_thread.start()
        stats_thread = threading.Thread(target=self._poll_stats, daemon=True)
        stats_thread.start()
        log.info("DockerMonitor started")

    def stop(self):
        self._stop.set()
        log.info("DockerMonitor stopped")
