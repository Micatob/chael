import logging
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from queue import Queue
from typing import List, Dict, Any, Optional, Set
from threading import Event

log = logging.getLogger("chael-yara")

YARA_RULES_BUILTIN: Dict[str, str] = {
    "linux_malware_basic": """
rule linux_malware_basic {
    meta:
        description = "Basic Linux malware indicators"
        author = "Chael SIEM"
        severity = "HIGH"
        mitre_id = "T1204"
    strings:
        $m1 = { 7f 45 4c 46 }  // ELF magic
        $s1 = "/dev/tcp" nocase
        $s2 = "/dev/udp" nocase
        $s3 = "socket(" nocase
        $s4 = "connect(" nocase
        $s5 = "exec(" nocase
        $s6 = "system(" nocase
        $s7 = "chmod 777" nocase
        $s8 = "wget " nocase
        $s9 = "curl " nocase
    condition:
        $m1 and 2 of ($s*)
}
""",
    "suspicious_file_names": """
rule suspicious_file_names {
    meta:
        description = "Files with suspicious names commonly used by malware"
        author = "Chael SIEM"
        severity = "HIGH"
        mitre_id = "T1204"
    strings:
        $s1 = /powershell\s+-ex\s+/i
        $s2 = /cmd\.exe\s+\/c\s+/i
        $s3 = /rundll32\.exe\s+/i
        $s4 = /regsvr32\.exe\s+/i
        $s5 = /mshta\.exe\s+/i
        $s6 = /cscript\.exe\s+/i
        $s7 = /wscript\.exe\s+/i
        $s8 = /certutil\.exe\s+-urlcache\s+/i
        $s9 = /bitsadmin\.exe\s+\/transfer\s+/i
    condition:
        any of ($s*)
}
""",
    "suspicious_encoded_strings": """
rule suspicious_encoded_strings {
    meta:
        description = "Base64/base32 hex encoded strings often used for obfuscation"
        author = "Chael SIEM"
        severity = "MEDIUM"
        mitre_id = "T1027"
    strings:
        $b64_1 = /[A-Za-z0-9+\/]{40,}[=]{0,2}/  // long base64
        $hex_1 = /[0-9a-fA-F]{32,}/              // MD5/SHA hash-like
    condition:
        any of them
}
""",
    "webshell_detection": """
rule webshell_detection {
    meta:
        description = "Common webshell patterns in script files"
        author = "Chael SIEM"
        severity = "CRITICAL"
        mitre_id = "T1505.003"
    strings:
        $p1 = "eval(" nocase
        $p2 = "exec(" nocase
        $p3 = "system(" nocase
        $p4 = "passthru(" nocase
        $p5 = "shell_exec(" nocase
        $p6 = "popen(" nocase
        $p7 = "proc_open(" nocase
        $p8 = "assert(" nocase
        $p9 = "base64_decode(" nocase
        $p10 = /str_rot13|gzinflate|gzuncompress/i
        $p11 = "create_function(" nocase
        $p12 = "preg_replace('/.*e/" nocase
    condition:
        4 of ($p*)
}
""",
    "windows_persistence": """
rule windows_persistence {
    meta:
        description = "Windows persistence mechanism indicators"
        author = "Chael SIEM"
        severity = "HIGH"
        mitre_id = "T1547"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "CurrentVersion\\RunServices" nocase
        $r4 = "User Shell Folders" nocase
        $s1 = "schtasks" nocase
        $s2 = "/create" nocase
        $s3 = "/sc" nocase
        $s4 = "onlogon" nocase
        $s5 = "Wscript.Shell" nocase
        $s6 = "Shell.Application" nocase
    condition:
        any of ($r*) or (2 of ($s*))
}
""",
    "suspicious_network_strings": """
rule suspicious_network_strings {
    meta:
        description = "Suspicious network-related strings in files"
        author = "Chael SIEM"
        severity = "HIGH"
        mitre_id = "T1071"
    strings:
        $n1 = "mimikatz" nocase
        $n2 = "Invoke-Mimikatz" nocase
        $n3 = "Invoke-Shellcode" nocase
        $n4 = "Invoke-ReflectivePEInjection" nocase
        $n5 = "PowerSploit" nocase
        $n6 = "Empire" nocase
        $n7 = "Cobalt Strike" nocase
        $n8 = "beacon" nocase
        $n9 = "metasploit" nocase
        $n10 = "reverse shell" nocase
        $n11 = "bind shell" nocase
        $n12 = "keylog" nocase
    condition:
        any of ($n*)
}
""",
}

DEFAULT_SCAN_DIRS_LINUX = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "/root",
    "/opt",
]

DEFAULT_SCAN_DIRS_WINDOWS = [
    "C:\\Users",
    "C:\\Windows\\Temp",
    "C:\\Temp",
]

FILE_EXTENSIONS_SCRIPT = {
    ".ps1", ".py", ".pl", ".rb", ".php", ".asp", ".aspx", ".jsp",
    ".sh", ".bash", ".vbs", ".vba", ".hta", ".js", ".jar", ".exe",
    ".dll", ".bin", ".scr", ".com", ".pif", ".gadget",
}

PROCESS_CMD_SCAN = [
    "nc", "ncat", "netcat",
    "nmap", "masscan",
    "niki", "sqlmap",
    "hydra", "john", "hashcat",
    "msfconsole", "msfvenom",
    "socat",
    "tcpdump", "tshark",
    "proxychains",
    "tor", "nyx",
    "cryptom",
    "minerd",
    "xigminer",
    "ccminer",
    "xmrig",
]


class YaraScanner:
    def __init__(
        self,
        queue: Queue,
        hostname: str,
        scan_interval: int = 3600,
        rules_dir: Optional[str] = None,
        scan_dirs: Optional[List[str]] = None,
        file_extensions: Optional[Set[str]] = None,
    ):
        self.queue = queue
        self.hostname = hostname
        self.scan_interval = scan_interval
        self.rules_dir = rules_dir
        self.scan_dirs = scan_dirs or (
            DEFAULT_SCAN_DIRS_WINDOWS if platform.system() == "Windows" else DEFAULT_SCAN_DIRS_LINUX
        )
        self.file_extensions = file_extensions or FILE_EXTENSIONS_SCRIPT
        self._stop = Event()
        self._system = platform.system()
        self._yara_available = False
        self._rules = {}
        self._load_rules()

    def _load_rules(self):
        try:
            import yara
            self._yara_available = True
            if self.rules_dir and os.path.isdir(self.rules_dir):
                rule_files = []
                for f in os.listdir(self.rules_dir):
                    if f.endswith((".yar", ".yara", ".rule")):
                        rule_files.append(os.path.join(self.rules_dir, f))
                if rule_files:
                    log.info("Loading %d YARA rules from %s", len(rule_files), self.rules_dir)
                    for rf in rule_files:
                        try:
                            self._rules[rf] = yara.compile(filepath=rf)
                        except Exception as e:
                            log.warning("Failed to compile %s: %s", rf, e)
            builtin_compiled = {}
            for name, source in YARA_RULES_BUILTIN.items():
                try:
                    builtin_compiled[name] = yara.compile(source=source)
                except Exception as e:
                    log.warning("Failed to compile builtin rule '%s': %s", name, e)
            if builtin_compiled:
                self._rules["__builtin__"] = builtin_compiled
            if not self._rules:
                log.warning("No YARA rules loaded (builtin or custom)")
        except ImportError:
            log.warning("yara-python not installed — YARA scanning disabled")
            self._yara_available = False
        except Exception as e:
            log.warning("Failed to initialize YARA: %s", e)
            self._yara_available = False

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        if not self._yara_available:
            return []
        matches = []
        try:
            if not os.path.isfile(filepath):
                return []
            try:
                with open(filepath, "rb") as f:
                    data = f.read(10485760)
            except (PermissionError, OSError):
                return []
            for source_name, ruleset in self._rules.items():
                if isinstance(ruleset, dict):
                    for rule_name, compiled in ruleset.items():
                        try:
                            result = compiled.match(data=data)
                            for r in result:
                                matches.append(self._match_to_dict(r, filepath, source_name, rule_name))
                        except Exception:
                            continue
                else:
                    try:
                        result = ruleset.match(data=data)
                        for r in result:
                            matches.append(self._match_to_dict(r, filepath, source_name, source_name))
                    except Exception:
                        continue
        except Exception as e:
            log.debug("Error scanning %s: %s", filepath, e)
        return matches

    def _match_to_dict(self, rule_match, filepath: str, source: str, rule_name: str) -> Dict[str, Any]:
        return {
            "rule_name": rule_name or str(rule_match),
            "rule_source": source,
            "file_path": filepath,
            "tags": list(getattr(rule_match, "tags", [])),
            "strings": [
                {
                    "identifier": s.identifier if hasattr(s, "identifier") else "",
                    "offset": s.instances[0].offset if hasattr(s, "instances") and s.instances else 0,
                    "data": s.instances[0].matched_data.decode("latin-1", errors="replace")[:100]
                    if hasattr(s, "instances") and s.instances else "",
                }
                for s in getattr(rule_match, "strings", [])
            ],
            "meta": {
                k: v for k, v in getattr(rule_match, "meta", {}).items()
            } if hasattr(rule_match, "meta") else {},
        }

    def _walk_files(self) -> List[str]:
        files = []
        for scan_dir in self.scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            try:
                for root, dirs, filenames in os.walk(scan_dir, followlinks=False):
                    if self._stop.is_set():
                        return files
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for fname in filenames:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in self.file_extensions or not ext:
                            files.append(os.path.join(root, fname))
                            if len(files) >= 500:
                                return files
            except (PermissionError, OSError):
                continue
        return files

    def _scan_processes(self) -> List[Dict[str, Any]]:
        matches = []
        if self._system == "Windows":
            try:
                result = subprocess.run(
                    'powershell -Command "Get-Process | Select-Object -Property Id,ProcessName,Path"',
                    shell=True, capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.split("\n")[3:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        proc_name = parts[1] if len(parts) > 1 else parts[0]
                        proc_name_lower = proc_name.lower()
                        for suspicious_cmd in PROCESS_CMD_SCAN:
                            if suspicious_cmd in proc_name_lower:
                                matches.append({
                                    "rule_name": "suspicious_process",
                                    "rule_source": "builtin_process_scan",
                                    "file_path": f"process:{proc_name}",
                                    "tags": ["process", "suspicious"],
                                    "strings": [],
                                    "meta": {
                                        "description": f"Suspicious process running: {proc_name}",
                                        "severity": "HIGH",
                                        "process_name": proc_name,
                                        "process_id": parts[0] if len(parts) > 0 else "",
                                    },
                                })
                                break
            except Exception as e:
                log.debug("Process scan error: %s", e)
        else:
            try:
                for pid_dir in os.listdir("/proc"):
                    if not pid_dir.isdigit():
                        continue
                    try:
                        with open(f"/proc/{pid_dir}/comm", "r") as f:
                            proc_name = f.read().strip().lower()
                    except (IOError, PermissionError):
                        continue
                    for suspicious_cmd in PROCESS_CMD_SCAN:
                        if suspicious_cmd in proc_name:
                            try:
                                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                                    cmdline = f.read().decode("latin-1", errors="replace").replace("\0", " ")
                            except (IOError, PermissionError):
                                cmdline = proc_name
                            matches.append({
                                "rule_name": "suspicious_process",
                                "rule_source": "builtin_process_scan",
                                "file_path": f"process:{pid_dir}",
                                "tags": ["process", "suspicious"],
                                "strings": [],
                                "meta": {
                                    "description": f"Suspicious process running: {proc_name}",
                                    "severity": "HIGH",
                                    "process_name": proc_name,
                                    "process_id": pid_dir,
                                    "cmdline": cmdline[:200],
                                },
                            })
                            break
            except (PermissionError, FileNotFoundError):
                pass
        return matches

    def run_scan(self) -> List[Dict[str, Any]]:
        if not self._yara_available:
            log.warning("YARA not available — skipping scan")
            return []
        log.info("Starting YARA scan on %s", self.hostname)
        all_matches = []
        files = self._walk_files()
        log.info("Scanning %d files on %s", len(files), self.hostname)
        for i, filepath in enumerate(files):
            if self._stop.is_set():
                break
            matches = self.scan_file(filepath)
            for match in matches:
                all_matches.append(match)
                self._emit_yara_event(match)
            if (i + 1) % 100 == 0:
                log.debug("YARA scanned %d/%d files on %s", i + 1, len(files), self.hostname)
        proc_matches = self._scan_processes()
        for match in proc_matches:
            all_matches.append(match)
            self._emit_yara_event(match)
        if all_matches:
            log.warning("YARA found %d matches on %s", len(all_matches), self.hostname)
        else:
            log.info("YARA scan complete — no matches on %s", self.hostname)
        return all_matches

    def _emit_yara_event(self, match: Dict[str, Any]):
        meta = match.get("meta", {})
        severity = meta.get("severity", "HIGH") if isinstance(meta, dict) else "HIGH"
        tags = match.get("tags", [])
        tag_str = ",".join(tags) if tags else "none"
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": self.hostname,
            "source": "yara_scanner",
            "log_type": "yara",
            "severity": severity,
            "message": f"YARA match: rule={match['rule_name']} file={match['file_path']} tags={tag_str}",
            "metadata": {
                "yara_rule_name": match["rule_name"],
                "yara_rule_source": match.get("rule_source", ""),
                "yara_file_path": match["file_path"],
                "yara_tags": tags,
                "yara_strings": match.get("strings", []),
                "yara_meta": meta,
                "platform": self._system,
                "hostname": self.hostname,
            },
        }
        self.queue.put(event)

    def start(self):
        self.run_scan()

    def stop(self):
        self._stop.set()
