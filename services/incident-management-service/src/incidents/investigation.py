import re
import os
import json
import time
import ipaddress
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

MTTR = {"label": "Mean Time to Respond", "value": "N/A"}

# ── Reusable thread pool ──────────────────────────────────────────────────

_SHARED_EXECUTOR = ThreadPoolExecutor(max_workers=20)

# ── In-memory cache (fallback when OpenSearch cache is unavailable) ───────

_MEMORY_CACHE: Dict[str, Tuple[float, Any]] = {}
_MEMORY_CACHE_TTL = 300  # 5 minutes

def _mem_cache_get(key: str) -> Optional[Any]:
    entry = _MEMORY_CACHE.get(key)
    if entry and time.time() - entry[0] < _MEMORY_CACHE_TTL:
        return entry[1]
    return None

def _mem_cache_set(key: str, value: Any):
    _MEMORY_CACHE[key] = (time.time(), value)

# ── Enrichment Cache (OpenSearch-backed with TTL) ─────────────────────────

ENRICHMENT_CACHE_INDEX = "chaelsiem-enrichment-cache"
ENRICHMENT_CACHE_TTL_SECONDS = 86400

_opensearch_cache = None

def _get_cache_client():
    global _opensearch_cache
    if _opensearch_cache is not None:
        return _opensearch_cache
    try:
        from storage.factory import get_storage_client
        client = get_storage_client()
        if hasattr(client, "client"):
            _opensearch_cache = client.client
            _ensure_cache_index(_opensearch_cache)
            return _opensearch_cache
    except Exception:
        pass
    return None

def _ensure_cache_index(os_client):
    try:
        if not os_client.indices.exists(index=ENRICHMENT_CACHE_INDEX):
            os_client.indices.create(
                index=ENRICHMENT_CACHE_INDEX,
                body={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {
                        "properties": {
                            "cache_key": {"type": "keyword"},
                            "cache_type": {"type": "keyword"},
                            "data": {"type": "object", "enabled": True},
                            "cached_at": {"type": "date"},
                            "ttl": {"type": "long"},
                        }
                    },
                },
            )
    except Exception:
        pass

def _cache_get(cache_key: str) -> Optional[Dict[str, Any]]:
    cached = _mem_cache_get(cache_key)
    if cached:
        return cached
    try:
        os_client = _get_cache_client()
        if not os_client:
            return None
        resp = os_client.get(index=ENRICHMENT_CACHE_INDEX, id=cache_key, ignore_unavailable=True, _source_includes=["data", "cached_at", "ttl"])
        source = resp.get("_source", {})
        cached_at = source.get("cached_at")
        ttl = source.get("ttl", ENRICHMENT_CACHE_TTL_SECONDS)
        if cached_at:
            age = time.time() - datetime.fromisoformat(cached_at.replace("Z", "+00:00")).timestamp()
            if age < ttl:
                _mem_cache_set(cache_key, source.get("data"))
                return source.get("data")
    except Exception:
        pass
    return None

def _cache_set(cache_key: str, cache_type: str, data: Dict[str, Any]):
    _mem_cache_set(cache_key, data)
    try:
        os_client = _get_cache_client()
        if not os_client:
            return
        os_client.index(
            index=ENRICHMENT_CACHE_INDEX,
            id=cache_key,
            body={
                "cache_key": cache_key,
                "cache_type": cache_type,
                "data": data,
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "ttl": ENRICHMENT_CACHE_TTL_SECONDS,
            },
            refresh=False,
        )
    except Exception:
        pass


MITRE_ATTACK_CACHE: Optional[Dict[str, Dict[str, str]]] = None
MITRE_ATTACK_FALLBACK = {
    "kerberoasting": {
        "technique": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/003/"
    },
    "asrep_roasting": {
        "technique": "T1558.002",
        "name": "AS-REP Roasting",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/002/"
    },
    "golden_ticket": {
        "technique": "T1558.001",
        "name": "Golden Ticket",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/001/"
    },
    "lateral_movement": {
        "technique": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1021/001/"
    },
    "pass_the_hash": {
        "technique": "T1550.002",
        "name": "Pass the Hash",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1550/002/"
    },
    "dns_tunneling": {
        "technique": "T1071.004",
        "name": "DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/"
    },
    "c2_communication": {
        "technique": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "persistence": {
        "technique": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/"
    },
    "brute_force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "critical": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "repeated_errors": {
        "technique": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/"
    }
}

def _build_mitre_cache() -> Dict[str, Dict[str, str]]:
    # Prefer the pre-baked cache shipped in the image (built at docker build
    # time) — downloading ~10MB synchronously inside a request blocks the
    # single event-loop worker for minutes on slow links.
    for local_path in ("enterprise-attack.json", "/app/enterprise-attack.json"):
        try:
            if os.path.isfile(local_path) and os.path.getsize(local_path) > 100:
                with open(local_path, "r", encoding="utf-8") as fh:
                    cached = json.load(fh)
                if isinstance(cached, dict) and cached:
                    # Build-time format is already {tid: {...}}; raw GitHub
                    # format is {"objects": [...]} — normalize both.
                    if "objects" not in cached:
                        return cached
                    data = cached
                    break
        except Exception:
            continue
    else:
        data = None
    try:
        if data is None:
            req = urllib.request.Request(
                "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                headers={"Accept": "application/json", "User-Agent": "ChaelSIEM/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        cache: Dict[str, Dict[str, str]] = {}
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext = obj.get("external_references", [{}])[0] if obj.get("external_references") else {}
            tid = ext.get("external_id", "")
            if not tid:
                continue
            kill_chain = obj.get("kill_chain_phases", [])
            tactic = kill_chain[0].get("phase_name", "").replace("-", " ").title() if kill_chain else ""
            cache[tid] = {
                "technique": tid,
                "name": obj.get("name", ""),
                "tactic": tactic,
                "url": f"https://attack.mitre.org/techniques/{tid}/",
            }
        return cache
    except Exception:
        return {}

KNN_MITRE_MAP = {
    "kerberoasting": ["T1558.003"],
    "asrep_roasting": ["T1558.002"],
    "golden_ticket": ["T1558.001"],
    "lateral_movement": ["T1021.001"],
    "pass_the_hash": ["T1550.002"],
    "dns_tunneling": ["T1071.004"],
    "c2_communication": ["T1071.001"],
    "persistence": ["T1053"],
    "brute_force": ["T1110"],
    "critical": ["T1190"],
    "repeated_errors": ["T1498"],
}

SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW"
}

def _extract_ips(text: str) -> List[str]:
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

def _extract_users(text: str) -> List[str]:
    users = re.findall(r'for user (\S+)', text, re.IGNORECASE)
    users += re.findall(r'user[=:](\S+)', text, re.IGNORECASE)
    return users

def _extract_cves(text: str) -> List[str]:
    return re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)

def _extract_file_paths(text: str) -> List[str]:
    return re.findall(r'(?:/[a-zA-Z0-9_.-]+)+', text)

def _extract_domains(text: str) -> List[str]:
    return re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)

def _extract_hashes(text: str) -> List[str]:
    hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
    hashes += re.findall(r'\b[a-fA-F0-9]{40}\b', text)
    hashes += re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    return hashes

# ── Threat Intel Enrichment ──────────────────────────────────────────────
# Env vars: VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, OTX_API_KEY,
#           GREYNOISE_API_KEY, IPINFO_API_KEY

VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", "")
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY", "")

def _fetch_json(url: str, headers: dict = None, timeout: int = 5) -> Optional[dict]:
    try:
        # Shodan's keyless APIs (InternetDB/CVEDB) 403 Python's default UA —
        # identify as Chael so free threat-intel stays reachable.
        merged = {"User-Agent": "ChaelSIEM/1.0"}
        if headers:
            merged.update(headers)
        req = urllib.request.Request(url, headers=merged)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None

def _enrich_geoip(ip: str) -> Dict[str, Any]:
    data = _fetch_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,query",
        headers={"Accept": "application/json"},
        timeout=3,
    )
    if data and data.get("status") == "success":
        return {
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "latitude": data.get("lat", 0),
            "longitude": data.get("lon", 0),
        }
    return {}

def _enrich_ip_virustotal(ip: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {}
    data = _fetch_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
        timeout=5,
    )
    if data:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
        }
    return {}

def _enrich_ip_abuseipdb(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {}
    data = _fetch_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        timeout=5,
    )
    if data:
        d = data.get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported_at": d.get("lastReportedAt", ""),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "hostnames": d.get("hostnames", []),
            "usage_type": d.get("usageType", ""),
            "is_public": d.get("isPublic", True),
            "is_whitelisted": d.get("isWhitelisted", False),
        }
    return {}

def _enrich_ip_shodan(ip: str) -> Dict[str, Any]:
    if not SHODAN_API_KEY:
        return {}
    data = _fetch_json(
        f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
        timeout=5,
    )
    if data:
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_code", ""),
            "city": data.get("city", ""),
            "os": data.get("os", ""),
            "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
            "tags": data.get("tags", []),
        }
    return {}

def _enrich_ip_greynoise(ip: str) -> Dict[str, Any]:
    if not GREYNOISE_API_KEY:
        return {}
    data = _fetch_json(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"Accept": "application/json", "key": GREYNOISE_API_KEY},
        timeout=5,
    )
    if data:
        return {
            "classification": data.get("classification", ""),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "name": data.get("name", ""),
            "last_seen": data.get("last_seen", ""),
        }
    return {}

def _enrich_ip_ipinfo(ip: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if IPINFO_API_KEY:
        headers["Authorization"] = f"Bearer {IPINFO_API_KEY}"
    data = _fetch_json(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=3)
    if data:
        return {
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "loc": data.get("loc", ""),
            "org": data.get("org", ""),
            "postal": data.get("postal", ""),
            "timezone": data.get("timezone", ""),
            "bogon": bool(data.get("bogon", False)),
        }
    return {}

def _enrich_ip_internetdb(ip: str) -> Dict[str, Any]:
    """Shodan InternetDB — keyless exposure snapshot (ports/hostnames/tags/vulns).

    No account or API key needed. Skips non-routable IPs (no public exposure data).
    """
    routable, _ = _classify_ip(ip)
    if not routable:
        return {}
    data = _fetch_json(
        f"https://internetdb.shodan.io/{ip}",
        headers={"Accept": "application/json"},
        timeout=5,
    )
    if data and isinstance(data, dict):
        return {
            "ports": data.get("ports", []) or [],
            "hostnames": data.get("hostnames", []) or [],
            "tags": data.get("tags", []) or [],
            "vulns": data.get("vulns", []) or [],
            "cpes": data.get("cpes", []) or [],
        }
    return {}

def _enrich_cve_nvd(cve_id: str) -> Dict[str, Any]:
    data = _fetch_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers={"Accept": "application/json"},
        timeout=5,
    )
    if data:
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve = vulns[0].get("cve", {})
            metrics = cve.get("metrics", {})
            cvss31 = (metrics.get("cvssMetricV31", [{}])[0] or {}).get("cvssData", {})
            return {
                "base_score": cvss31.get("baseScore", 0),
                "severity": cvss31.get("baseSeverity", ""),
                "attack_vector": cvss31.get("attackVector", ""),
                "published": cve.get("published", ""),
                "description": (
                    cve.get("descriptions", [{}])[0].get("value", "")
                    if cve.get("descriptions") else ""
                ),
            }
    return {}

def _enrich_cve_cvedb(cve_id: str) -> Dict[str, Any]:
    """Shodan CVEDB — keyless vuln detail (CVSS, EPSS, KEV, ransomware flag).

    No account or API key needed (free for non-commercial use). Complements
    NVD with exploitability signals NVD lacks (EPSS score, known-exploited,
    ransomware-campaign association).
    """
    cu = (cve_id or "").upper()
    data = _fetch_json(
        f"https://cvedb.shodan.io/cve/{cu}",
        headers={"Accept": "application/json"},
        timeout=5,
    )
    if data and isinstance(data, dict) and data.get("cve_id"):
        return {
            "cvss": data.get("cvss", 0),
            "epss": data.get("epss", 0),
            "kev": bool(data.get("kev", False)),
            "ransomware_campaign": data.get("ransomware_campaign") or "",
            "summary": str(data.get("summary", ""))[:600],
            "published": data.get("published_time", ""),
            "references": (data.get("references", []) or [])[:5],
        }
    return {}

def _enrich_hash_otx(ip_or_hash: str) -> Dict[str, Any]:
    if not OTX_API_KEY:
        return {}
    data = _fetch_json(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_or_hash}/general",
        headers={"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"},
        timeout=5,
    )
    if data:
        return {
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
            "reputation": data.get("reputation", 0),
            "country": data.get("country_code", ""),
            "whois": data.get("whois", ""),
        }
    return {}

_ENRICHMENT_FUNCTIONS = {
    "geoip": _enrich_geoip,
    "internetdb": _enrich_ip_internetdb,
    "virustotal": _enrich_ip_virustotal,
    "abuseipdb": _enrich_ip_abuseipdb,
    "shodan": _enrich_ip_shodan,
    "greynoise": _enrich_ip_greynoise,
    "ipinfo": _enrich_ip_ipinfo,
}

def _enrich_ip_parallel(ip: str) -> Dict[str, Any]:
    cache_key = f"enrich_ip:{ip}:{_source_sig()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    routable, label = _classify_ip(ip)
    if not routable:
        # Deterministic, zero-network: no reputation source tracks these ranges.
        # Returned (not {}) so the hunt popup explains instead of dead-ending.
        entry = {"routability": {
            "routable": False, "class": label,
            "note": (f"{ip} is {label} — external reputation sources "
                     "(VirusTotal, AbuseIPDB, Shodan, GreyNoise) do not track this range. "
                     "This 'no data' is expected, not a missing key. Scope it via the "
                     "internal Hunt page (host/time-window) instead."),
        }}
        _cache_set(cache_key, "ip_enrichment", entry)
        return entry

    entry = {}
    fut_map = {_SHARED_EXECUTOR.submit(fn, ip): name for name, fn in _ENRICHMENT_FUNCTIONS.items()}
    try:
        # Bounded: on a loaded box DNS/outbound can stall — return partial fast.
        for fut in as_completed(fut_map, timeout=8):
            name = fut_map[fut]
            try:
                result = fut.result()
                if result:
                    entry[name] = result
            except Exception:
                pass
    except TimeoutError:
        pass

    if entry:
        _cache_set(cache_key, "ip_enrichment", entry)
    return entry

def _enrich_iocs(ips: List[str], cves: List[str], hashes: List[str] = None, domains: List[str] = None) -> Dict[str, Any]:
    enrichment = {}
    hashes = hashes or []
    domains = domains or []

    if ips:
        fut_map = {_SHARED_EXECUTOR.submit(_enrich_ip_parallel, ip): ip for ip in ips[:5]}
        try:
            # Overall deadline: investigate must return even when enrichment stalls.
            for fut in as_completed(fut_map, timeout=12):
                ip = fut_map[fut]
                try:
                    result = fut.result()
                    if result:
                        enrichment[ip] = result
                except Exception:
                    pass
        except TimeoutError:
            pass

    cve_futs = {}
    for cve in cves[:3]:
        cache_key = f"enrich_cve:{cve}"
        cached = _cache_get(cache_key)
        if cached:
            enrichment[cve] = cached
            continue
        # Both free + keyless: NVD (authoritative scores) + CVEDB (EPSS/KEV/ransomware).
        cve_futs[_SHARED_EXECUTOR.submit(_enrich_cve_nvd, cve)] = ("nvd", cve, cache_key)
        cve_futs[_SHARED_EXECUTOR.submit(_enrich_cve_cvedb, cve)] = ("cvedb", cve, cache_key)
    cve_merged: Dict[str, Dict[str, Any]] = {}
    try:
        for fut in as_completed(cve_futs, timeout=10):
            src, cve, cache_key = cve_futs[fut]
            try:
                res = fut.result()
                if res:
                    cve_merged.setdefault(cve, {})[src] = res
            except Exception:
                pass
    except TimeoutError:
        pass
    for cve, merged in cve_merged.items():
        enrichment[cve] = merged
        _cache_set(f"enrich_cve:{cve}", "cve_enrichment", merged)

    hash_futs = {}
    for h in hashes[:3]:
        if OTX_API_KEY:
            cache_key = f"enrich_hash:{h}:{_source_sig()}"
            cached = _cache_get(cache_key)
            if cached:
                enrichment[f"hash:{h[:16]}..."] = cached
                continue
            hash_futs[_SHARED_EXECUTOR.submit(_enrich_hash_otx, h)] = (h, cache_key)
    try:
        for fut in as_completed(hash_futs, timeout=10):
            h, cache_key = hash_futs[fut]
            try:
                otx = fut.result()
                if otx:
                    enrichment[f"hash:{h[:16]}..."] = {"otx": otx}
                    _cache_set(cache_key, "hash_enrichment", {"otx": otx})
            except Exception:
                pass
    except TimeoutError:
        pass

    # Domains: OTX-backed when a key exists, otherwise analyst reference links
    # so the hunt never dead-ends on "no data".
    for d in (domains or [])[:5]:
        dl = (d or "").lower()
        if not dl or "." not in dl or dl.endswith((".local", ".internal", ".lan")):
            continue
        if OTX_API_KEY:
            cache_key = f"enrich_domain:{dl}:{_source_sig()}"
            cached = _cache_get(cache_key)
            if cached:
                enrichment[dl] = cached
                continue
            otx = _enrich_domain_otx(dl)
            if otx:
                enrichment[dl] = {"otx": otx}
                _cache_set(cache_key, "domain_enrichment", {"otx": otx})
                continue
        enrichment.setdefault(dl, {}).setdefault(
            "references", _reference_links("domain", dl))

    return enrichment


# ── Production-grade hunt support: source status + single-IOC live lookup ──

def _is_private_ip(ip: str) -> bool:
    routable, _ = _classify_ip(ip)
    return not routable


def _classify_ip(ip: str):
    """Local zero-network routability check. Returns (routable, label).

    Documentation/TEST-NET, private, loopback, multicast, link-local and
    reserved ranges are NOT tracked by external reputation sources — hunting
    them externally always dead-ends, so callers short-circuit with an
    explanation instead of burning API quota (AbuseIPDB free = 1000/day).
    """
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False, "invalid"
    # NOTE: special-purpose ranges first — is_global is True for some of them
    # (e.g. multicast) on certain Python versions.
    if addr.is_loopback:
        return False, "loopback"
    if addr.is_multicast:
        return False, "multicast"
    if addr.is_link_local:
        return False, "link-local"
    if addr.is_unspecified:
        return False, "unspecified"
    for net, name in (("192.0.2.0/24", "documentation (RFC 5737 TEST-NET-1)"),
                      ("198.51.100.0/24", "documentation (RFC 5737 TEST-NET-2)"),
                      ("203.0.113.0/24", "documentation (RFC 5737 TEST-NET-3)")):
        try:
            if addr in ipaddress.ip_network(net):
                return False, name
        except ValueError:
            pass
    if addr.is_global:
        return True, "public"
    if addr.is_private:
        return False, "private (RFC 1918)"
    if addr.is_reserved:
        return False, "reserved (IANA special-purpose)"
    return False, "non-routable"


def _source_sig() -> str:
    """Short signature of the currently keyed sources. Baked into cache keys so
    adding a key (e.g. ABUSEIPDB_API_KEY) instantly busts stale entries that
    were cached while the source was unconfigured."""
    try:
        keyed = _source_status()["keyed"]
        on = "".join(sorted(k[:2] for k, v in keyed.items() if v)) or "nokeys"
        return f"v2-{on}"
    except Exception:
        return "v2"


def _source_status() -> Dict[str, Any]:
    """Which external sources are live right now (keys vs free)."""
    return {
        "free_live": ["ip-api (geoip)", "internetdb (shodan exposure, keyless)",
                      "nvd (cve)", "cvedb (shodan vuln detail, keyless)"],
        "keyed": {
            "virustotal": bool(VT_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "shodan": bool(SHODAN_API_KEY),
            "otx": bool(OTX_API_KEY),
            "greynoise": bool(GREYNOISE_API_KEY),
            "ipinfo": bool(IPINFO_API_KEY),
        },
        "note": ("Free sources (ip-api geo, Shodan InternetDB exposure, NVD + "
                 "Shodan CVEDB vuln detail) work with no keys. "
                 "Add VT_API_KEY / SHODAN_API_KEY / OTX_API_KEY / "
                 "GREYNOISE_API_KEY to .env and restart incident-management-service "
                 "for full confirmation."),
    }


def _reference_links(ioc_type: str, value: str) -> Dict[str, str]:
    v = (value or "").strip()
    if ioc_type == "ip":
        return {
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{v}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{v}",
            "shodan": f"https://www.shodan.io/host/{v}",
            "greynoise": f"https://viz.greynoise.io/riot/{v}",
        }
    if ioc_type == "domain":
        return {
            "virustotal": f"https://www.virustotal.com/gui/domain/{v}",
            "otx": f"https://otx.alienvault.com/indicator/domain/{v}",
        }
    if ioc_type == "hash":
        return {
            "virustotal": f"https://www.virustotal.com/gui/file/{v}",
            "otx": f"https://otx.alienvault.com/indicator/file/{v}",
        }
    if ioc_type == "cve":
        cu = v.upper()
        return {"nvd": f"https://nvd.nist.gov/vuln/detail/{cu}"}
    return {}


def _enrich_domain_otx(domain: str) -> Dict[str, Any]:
    if not OTX_API_KEY:
        return {}
    data = _fetch_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers={"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"},
        timeout=5,
    )
    if data:
        return {
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
            "reputation": data.get("reputation", 0),
            "whois": str(data.get("whois", ""))[:500],
        }
    return {}


def enrich_single_ioc(ioc_type: str, value: str) -> Dict[str, Any]:
    """Live single-IOC lookup for the Hunt page (no incident required).

    Always tries free sources; keyed sources only when configured. Returns
    per-source results + source status + manual reference links so analysts
    can confirm externally even with zero API keys.
    """
    t = (ioc_type or "").lower().strip()
    v = (value or "").strip()
    if not v:
        return {"error": "empty value"}
    if t in ("ip", "ipv4", "ip_address"):
        routable, label = _classify_ip(v)
        if not routable:
            return {"type": "ip", "value": v, "private": True,
                    "results": {"routability": {"routable": False, "class": label}},
                    "sources_queried": ["routability (local — no external source tracks this range)"],
                    "references": {},
                    "source_status": _source_status(),
                    "verdict_hint": f"Non-routable {label} address - scope to internal asset inventory and the Hunt page, not external reputation."}
        cache_key = f"enrich_ip:{v}"
        cached = _cache_get(cache_key)
        results = cached or _enrich_ip_parallel(v)
        return {"type": "ip", "value": v, "private": False,
                "results": results,
                "sources_queried": list(results.keys()) or ["none (all sources unreachable or no keys)"],
                "references": _reference_links("ip", v),
                "source_status": _source_status(),
                "verdict_hint": _ip_verdict_hint(results)}
    if t in ("domain", "hostname", "url"):
        dl = v.lower()
        cached = _cache_get(f"enrich_domain:{dl}:{_source_sig()}")
        if cached:
            return {"type": "domain", "value": dl, "results": cached,
                    "sources_queried": list(cached.keys()),
                    "references": _reference_links("domain", dl),
                    "source_status": _source_status()}
        otx = _enrich_domain_otx(dl)
        res = {"otx": otx} if otx else {}
        if res:
            _cache_set(f"enrich_domain:{dl}", "domain_enrichment", res)
        return {"type": "domain", "value": dl, "results": res,
                "sources_queried": list(res.keys()) or ["none (OTX key not configured)"],
                "references": _reference_links("domain", dl),
                "source_status": _source_status(),
                "verdict_hint": ("OTX pulse_count>0 suggests known-malicious; "
                                 "otherwise confirm via VirusTotal link above.")}
    if t in ("hash", "md5", "sha1", "sha256", "file"):
        cached = _cache_get(f"enrich_hash:{v}:{_source_sig()}")
        if cached:
            return {"type": "hash", "value": v, "results": cached,
                    "sources_queried": list(cached.keys()),
                    "references": _reference_links("hash", v),
                    "source_status": _source_status()}
        otx = _enrich_hash_otx(v)
        res = {"otx": otx} if otx else {}
        if res:
            _cache_set(f"enrich_hash:{v}", "hash_enrichment", res)
        return {"type": "hash", "value": v, "results": res,
                "sources_queried": list(res.keys()) or ["none (OTX key not configured)"],
                "references": _reference_links("hash", v),
                "source_status": _source_status()}
    if t in ("cve", "cve_id"):
        cu = v.upper()
        cached = _cache_get(f"enrich_cve:{cu}")
        if cached:
            return {"type": "cve", "value": cu, "results": cached,
                    "sources_queried": ["nvd (free, live)", "cvedb (keyless, live)"],
                    "references": _reference_links("cve", cu),
                    "source_status": _source_status()}
        nvd = _enrich_cve_nvd(cu)
        cvedb = _enrich_cve_cvedb(cu)
        res = {}
        if nvd:
            res["nvd"] = nvd
        if cvedb:
            res["cvedb"] = cvedb
        if res:
            _cache_set(f"enrich_cve:{cu}", "cve_enrichment", res)
        return {"type": "cve", "value": cu, "results": res,
                "sources_queried": ["nvd (free, live)", "cvedb (keyless, live)"],
                "references": _reference_links("cve", cu),
                "source_status": _source_status()}
    return {"error": f"unknown ioc type '{ioc_type}' (use ip, domain, hash, cve)"}


def _ip_verdict_hint(results: Dict[str, Any]) -> str:
    try:
        vt = results.get("virustotal", {})
        if vt.get("malicious", 0) >= 5:
            return f"CONFIRM MALICIOUS: VirusTotal {vt.get('malicious')} engines flag this IP. Block at perimeter after change-ticket check."
        if vt.get("malicious", 0) >= 1:
            return "SUSPICIOUS: 1+ VT engines flag it — correlate with AbuseIPDB confidence before blocking."
        ab = results.get("abuseipdb", {})
        if isinstance(ab.get("abuse_confidence_score"), (int, float)) and ab["abuse_confidence_score"] >= 75:
            return f"CONFIRM MALICIOUS: AbuseIPDB {ab['abuse_confidence_score']}% confidence ({ab.get('total_reports', 0)} reports)."
        if isinstance(ab.get("abuse_confidence_score"), (int, float)) and ab["abuse_confidence_score"] >= 25:
            return (f"SUSPICIOUS: AbuseIPDB {ab['abuse_confidence_score']}% confidence "
                    f"({ab.get('total_reports', 0)} reports) — hunt internally before blocking.")
        idb = results.get("internetdb", {})
        if idb.get("vulns"):
            return (f"EXPOSED: Shodan InternetDB lists {len(idb['vulns'])} vuln(s) on open ports "
                    f"{(idb.get('ports', []) or [])[:8]} — patch/close before verdict on maliciousness.")
        gn = results.get("greynoise", {})
        if gn.get("classification") == "malicious":
            return "GreyNoise classifies as malicious internet-noise — likely scanner/exploit attempt; block if targeted."
        if gn.get("noise") is True and gn.get("classification") == "benign":
            return "GreyNoise: benign background noise (e.g. researcher/scanner) — monitor, do not block outright."
        if vt and vt.get("malicious", 0) == 0 and ab.get("abuse_confidence_score", 0) == 0:
            return "No reputation hits — treat as unverified, hunt internally (Hunt page) before verdict."
    except Exception:
        pass
    return "Cross-check references above; confirm with 2+ sources before containment."


def _detect_attack_type(incident: Dict[str, Any]) -> str:
    artifacts = incident.get("artifacts", {})
    desc = incident.get("description", "").lower()
    rule = str(artifacts.get("rule", "") or artifacts.get("attack_type", "")).lower()
    tech = str(artifacts.get("technique", "") or "").upper()
    if rule in ("kerberoasting",) or "kerberoast" in desc or tech == "T1558.003":
        return "kerberoasting"
    if rule in ("asrep_roasting",) or "as-rep" in desc or "asrep" in desc or tech == "T1558.002":
        return "asrep_roasting"
    if rule in ("golden_ticket_suspect",) or "golden ticket" in desc or "silver ticket" in desc or tech in ("T1558.001", "T1558.004"):
        return "golden_ticket"
    if rule in ("lateral_movement", "lateral_movement_rdp", "lateral_movement_smb") or "lateral movement" in desc or "4778" in desc or tech.startswith("T1021"):
        return "lateral_movement"
    if rule in ("pass_the_hash_suspect",) or "pass-the-hash" in desc or "pass the hash" in desc or tech == "T1550.002":
        return "pass_the_hash"
    if rule in ("dns_tunneling", "dns_tunneling_suspect") or "dns tunneling" in desc or tech == "T1071.004":
        return "dns_tunneling"
    if rule in ("reverse_shell", "c2_beacon_suspect") or "reverse shell" in desc or "beacon" in desc or "c2" in desc:
        return "c2_communication"
    if rule in ("persistence_schtask", "persistence_service", "registry_persistence", "new_service") or "persistence" in desc or "scheduled task" in desc or "4698" in desc:
        return "persistence"
    if artifacts.get("attack_type") == "brute_force" or "brute force" in desc:
        return "brute_force"
    if artifacts.get("event_type") == "critical" or "critical" in desc:
        return "critical"
    if "repeated" in desc or artifacts.get("event_type") == "repeated":
        return "repeated_errors"
    return "unknown"

class InvestigationEngine:
    def __init__(self, storage_client=None):
        self.storage = storage_client

    def analyze(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = _detect_attack_type(incident)
        global MITRE_ATTACK_CACHE
        if MITRE_ATTACK_CACHE is None:
            MITRE_ATTACK_CACHE = _build_mitre_cache()
        if MITRE_ATTACK_CACHE and attack_type != "unknown":
            tids = KNN_MITRE_MAP.get(attack_type, [])
            mitre = MITRE_ATTACK_CACHE.get(tids[0], {}) if tids else {}
        else:
            mitre = MITRE_ATTACK_FALLBACK.get(attack_type, {})
        severity = self._assess_severity(incident)

        source_logs = incident.get("source_logs", [])
        all_messages = " ".join(
            log.get("message", "") for log in source_logs if isinstance(log, dict)
        )

        ips = _extract_ips(all_messages)
        users = _extract_users(all_messages)
        cves = _extract_cves(all_messages)
        paths = _extract_file_paths(all_messages)
        hashes = _extract_hashes(all_messages)
        domains = _extract_domains(all_messages)

        enrichment = _enrich_iocs(ips, cves, hashes, domains)

        fp_indicators = self._flag_false_positive_indicators(incident, attack_type)
        confidence = self._calculate_confidence(source_logs, attack_type)

        findings = {
            "incident_id": incident.get("incident_id"),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "severity_assessment": severity,
            "attack_classification": attack_type,
            "false_positive_checklist": fp_indicators,
            "confidence_score": confidence,
            "confidence_label": "HIGH" if confidence >= 0.85 else "MEDIUM" if confidence >= 0.70 else "LOW",
            "soc_verdict_guide": self._generate_verdict_guide(confidence, fp_indicators),
            "threat_intel_enrichment": enrichment,
            "mitre_technique": {
                "id": mitre.get("technique"),
                "name": mitre.get("name"),
                "tactic": mitre.get("tactic"),
                "reference": mitre.get("url")
            },
            "affected_assets": self._enumerate_assets(incident),
            "indicators_extracted": {
                "ip_addresses": ips,
                "usernames": users,
                "cve_ids": cves,
                "file_paths": paths,
                "hashes": hashes,
                "domains": domains,
            },
            "recommended_actions": self._recommend_actions(
                incident, attack_type, ips, users, cves, paths
            ),
            "walkthrough": self._generate_walkthrough(
                incident, attack_type, source_logs
            ),
            "follow_up_steps": self._generate_follow_up(
                attack_type, ips, users, cves
            ),
            "ioc_matches": self._check_iocs(
                attack_type, ips, users, cves, paths
            ),
        }
        return findings

    def _assess_severity(self, incident: Dict[str, Any]) -> str:
        score = incident.get("risk_score", 0)
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        return "LOW"

    def _enumerate_assets(self, incident: Dict[str, Any]) -> List[Dict[str, str]]:
        assets = []
        artifacts = incident.get("artifacts", {})
        source_logs = incident.get("source_logs", [])
        seen = set()
        for host_field in ["target_host", "host"]:
            val = artifacts.get(host_field)
            if val and val not in seen:
                assets.append({"hostname": val, "role": "affected_target"})
                seen.add(val)
        for log in source_logs:
            if not isinstance(log, dict):
                continue
            host = log.get("host")
            src = log.get("source", "unknown")
            if host and host not in seen:
                assets.append({"hostname": host, "role": f"log_source:{src}"})
                seen.add(host)
        return assets

    def _flag_false_positive_indicators(self, incident: Dict[str, Any], attack_type: str) -> List[str]:
        indicators = []
        if attack_type in ("kerberoasting", "asrep_roasting", "golden_ticket"):
            indicators.append("CHECK: Is the ticket volume from a backup/sync service or app using a service account legitimately? Baseline 4769/day per host first.")
            indicators.append("CHECK: Is the RC4 etype 0x17 expected (legacy app)? If yes, migrate the service account to AES and re-baseline.")
            indicators.append("CHECK: Is there a matching vulnerability scan or AD audit window? Confirm with the change ticket.")
        elif attack_type in ("lateral_movement", "pass_the_hash"):
            indicators.append("CHECK: Is the RDP/logon burst from an admin jump host or patch window? Correlate with change management.")
            indicators.append("CHECK: Are the logons from a service account with known fan-out behavior? Identify the application owner.")
        elif attack_type == "dns_tunneling":
            indicators.append("CHECK: Is the DNS volume from DNS-based security tooling, software updates, or captive portal? Allowlist known-good domains.")
            indicators.append("CHECK: Are queries going to a corporate DNS filter that retries aggressively? Compare against host baseline.")
        elif attack_type == "c2_communication":
            indicators.append("CHECK: Is the beacon-like pattern actually a monitoring agent, updater, or SaaS sync on a fixed interval? Verify the process.")
        elif attack_type == "persistence":
            indicators.append("CHECK: Was the scheduled task/service created by an approved deployment (SCCM, Intune, Ansible)? Verify signer and path.")
        elif attack_type == "brute_force":
            indicators.append("CHECK: Are the failed logins from known internal scanners or vuln sweepers? If yes, CORRELATE with change window and verify expected behavior.")
            indicators.append("CHECK: Do the source IPs belong to known corporate VPN ranges or cloud NAT gateways? If yes, this may be expected authentication churn.")
            indicators.append("CHECK: Are the targeted accounts service accounts with known automated retry logic? If yes, locate the application owner.")
            indicators.append("CHECK: Is the failure count exactly at the threshold with no preceding history? If yes, consider a single-user fat-finger scenario.")
        elif attack_type == "critical":
            indicators.append("CHECK: Does the CRITICAL log originate from a known penetration test or red team exercise? If yes, verify scope.")
            indicators.append("CHECK: Is the source IP a known internal scanner (Nessus, Qualys, OpenVAS)? If yes, this is a vulnerability scan.")
            indicators.append("CHECK: Is the CVE reference a false match to a known benign log pattern? If yes, tune the detection rule.")
        elif attack_type == "repeated_errors":
            indicators.append("CHECK: Are the errors from a scheduled batch job or cron task that runs at the same time daily? If yes, this is operational noise.")
            indicators.append("CHECK: Is there a recent deployment or configuration change that correlates with the error start time?")
            indicators.append("CHECK: Are the errors limited to a single non-critical service with no security context?")
        else:
            indicators.append("CHECK: Does this log match any known application behavior or maintenance window? Correlate with change management system.")
            indicators.append("CHECK: Is the severity artificially high due to log content keywords rather than actual impact?")
        return indicators

    def _recommend_actions(self, incident: Dict[str, Any], attack_type: str, ips: List[str], users: List[str], cves: List[str], paths: Optional[List[str]] = None) -> List[str]:
        paths = paths or []
        actions = []
        if attack_type == "kerberoasting":
            actions.append("ISOLATE the requesting host and BLOCK the source IP at the perimeter")
            actions.append("ROTATE the targeted service account password immediately (Kerberoasted hashes crack offline)")
            actions.append("HUNT 4769 bursts across all hosts ±7 days for the same SPN")
            actions.append("ENFORCE AES-only Kerberos (disable RC4 0x17) where legacy allows")
        elif attack_type == "asrep_roasting":
            actions.append("ISOLATE the requesting host and BLOCK the source IP")
            actions.append("ENABLE Kerberos pre-authentication on all accounts flagged without it")
            actions.append("FORCE password reset for enumerated accounts")
            actions.append("HUNT 4771 + 4768-without-pre-auth pairs across the domain")
        elif attack_type == "golden_ticket":
            actions.append("ISOLATE the affected host immediately — treat domain as compromised until proven otherwise")
            actions.append("RESET the KRBTGT account password TWICE to invalidate forged tickets")
            actions.append("ROTATE all service account passwords with RC4 tickets")
            actions.append("HUNT anomalous ticket lifetimes and 4768/4769 mismatches domain-wide")
        elif attack_type in ("lateral_movement", "pass_the_hash"):
            actions.append("ISOLATE the source host and BLOCK its IP at the perimeter")
            actions.append(f"FORCE password reset for involved accounts: {', '.join(users) if users else 'identify from 4624/4778 logs'}")
            actions.append("MAP source→destination logons (4624/4778/4779) to scope the spread")
            actions.append("ENABLE Credential Guard / disable NTLM where possible")
        elif attack_type == "dns_tunneling":
            actions.append("ISOLATE the host and BLOCK the suspicious domain at the DNS firewall")
            actions.append("CAPTURE full DNS + flow logs for the host ±24h and decode tunneled payloads")
            actions.append("HUNT other hosts querying the same domain/NS pattern")
        elif attack_type == "c2_communication":
            actions.append("ISOLATE the host from the network immediately (keep power on for forensics)")
            actions.append(f"BLOCK attacker infrastructure at firewall/proxy: {', '.join(ips) if ips else 'identify from flows'}")
            actions.append("COLLECT memory dump and hunt sibling beacons on fleet")
        elif attack_type == "persistence":
            actions.append("ISOLATE the host and PRESERVE the scheduled task/service binary before removal")
            actions.append("REMOVE the persistence (task/service/run key) only after imaging")
            actions.append("HUNT the same task name/hash across all agents")
        elif attack_type == "brute_force":
            actions.append(f"BLOCK source IP{'S' if len(ips) > 1 else ''} at perimeter firewall: {', '.join(ips) if ips else 'identify from logs'}")
            if users:
                actions.append(f"FORCE password reset for compromised user{'S' if len(users) > 1 else ''}: {', '.join(users)}")
            actions.append("ENFORCE account lockout policy after 3 failed attempts within 15 minutes")
            actions.append("ENABLE multi-factor authentication on all externally facing authentication endpoints")
            actions.append("REVIEW failed logins across all systems")
            actions.append("CHECK for successful logins from the same source IP after failed attempts")
        elif attack_type == "critical":
            if cves:
                actions.append(f"PATCH vulnerability {' '.join(cves)}")
            if ips:
                actions.append(f"BLOCK attacker IP{'S' if len(ips) > 1 else ''}: {', '.join(ips)}")
            if paths:
                actions.append(f"REMOVE or quarantine suspicious file{'S' if len(paths) > 1 else ''}: {', '.join(paths[:3])}")
            actions.append("ISOLATE affected host from network")
            actions.append("SCAN for persistence mechanisms (scheduled tasks, registry run keys, systemd services)")
            actions.append("COLLECT memory dump and disk image for offline forensic analysis")
        elif attack_type == "repeated_errors":
            actions.append("INVESTIGATE root cause of service errors")
            actions.append("CHECK system resource utilization on affected host")
            if ips:
                actions.append(f"REVIEW connection logs from {', '.join(ips)}")
            actions.append("RESTART affected service if degraded")
            actions.append("IMPLEMENT rate limiting if external source identified")
        else:
            actions.append("REVIEW raw log payload for additional context")
            actions.append("CORRELATE with other data sources to determine scope")
            actions.append("ESCALATE to Tier 2 SOC analyst for further investigation")
        return actions

    def _generate_walkthrough(self, incident: Dict[str, Any], attack_type: str, source_logs: List[Dict[str, Any]]) -> List[str]:
        walkthrough = []
        desc = incident.get("description", "Security event")
        incident_ts = incident.get("timestamp", "unknown")
        walkthrough.append(f"[{incident_ts}] Detection engine triggered — pattern match: {attack_type.replace('_', ' ').title()}")
        if source_logs:
            first_log = source_logs[0] if isinstance(source_logs[0], dict) else {}
            last_log = source_logs[-1] if isinstance(source_logs[-1], dict) else {}
            log_count = len(source_logs)
            first_ts = first_log.get("timestamp", incident_ts)
            last_ts = last_log.get("timestamp", incident_ts)
            walkthrough.append(f"[{first_ts}] First suspicious event observed — host: {first_log.get('host', 'unknown')}, message: \"{first_log.get('message', '')[:120]}\"")
            if log_count > 1:
                walkthrough.append(f"[{last_ts}] Additional correlated events detected — total {log_count} events")
        if attack_type == "kerberoasting":
            walkthrough.append("[ANALYSIS] Kerberos service-ticket burst (4769) — consistent with Kerberoasting (T1558.003); RC4 tickets crack offline")
            walkthrough.append("[MITRE] Maps to T1558.003 (Kerberoasting) under Credential Access tactic")
        elif attack_type == "asrep_roasting":
            walkthrough.append("[ANALYSIS] Kerberos pre-auth failure burst (4771) — consistent with AS-REP Roasting (T1558.002)")
            walkthrough.append("[MITRE] Maps to T1558.002 (AS-REP Roasting) under Credential Access tactic")
        elif attack_type == "golden_ticket":
            walkthrough.append("[ANALYSIS] Forged-ticket indicators (RC4 anomalies / lifetime mismatch) — treat as Golden/Silver ticket (T1558.001/.004)")
            walkthrough.append("[MITRE] Maps to T1558.001/T1558.004 under Credential Access tactic")
        elif attack_type in ("lateral_movement", "pass_the_hash"):
            walkthrough.append("[ANALYSIS] Logon/session burst across hosts — consistent with lateral movement (T1021/T1550.002)")
            walkthrough.append("[MITRE] Maps to T1021 / T1550.002 under Lateral Movement tactic")
        elif attack_type == "dns_tunneling":
            walkthrough.append("[ANALYSIS] High-volume / long-label DNS queries — consistent with DNS tunneling C2 (T1071.004)")
            walkthrough.append("[MITRE] Maps to T1071.004 (DNS) under Command and Control tactic")
        elif attack_type == "c2_communication":
            walkthrough.append("[ANALYSIS] Beacon/reverse-shell pattern — consistent with C2 channel (T1071)")
            walkthrough.append("[MITRE] Maps to T1071 under Command and Control tactic")
        elif attack_type == "persistence":
            walkthrough.append("[ANALYSIS] New scheduled task/service — consistent with persistence (T1053/T1543)")
            walkthrough.append("[MITRE] Maps to T1053/T1543 under Persistence tactic")
        elif attack_type == "brute_force":
            artifacts = incident.get("artifacts", {})
            count = artifacts.get("failure_count", len(source_logs))
            walkthrough.append(f"[ANALYSIS] {count} failed authentication attempts in the detection window — consistent with password spraying or credential stuffing pattern")
            walkthrough.append("[MITRE] Maps to T1110 (Brute Force) under Credential Access tactic")
        elif attack_type == "critical":
            walkthrough.append("[ANALYSIS] Event classified as CRITICAL severity — immediate risk of code execution, data exfiltration, or lateral movement")
            walkthrough.append("[MITRE] Maps to T1190 (Exploit Public-Facing Application) under Initial Access tactic")
        elif attack_type == "repeated_errors":
            walkthrough.append("[ANALYSIS] Repeated error events from same source — misconfiguration, resource exhaustion, or targeted DoS")
            walkthrough.append("[MITRE] May map to T1498 (Network Denial of Service) under Impact tactic")
        walkthrough.append("[NEXT] Incident elevated to SOC command center — automated SOAR playbook triggered for containment")
        return walkthrough

    def _generate_follow_up(self, attack_type: str, ips: List[str], users: List[str], cves: List[str]) -> List[str]:
        steps = []
        if attack_type in ("kerberoasting", "asrep_roasting", "golden_ticket"):
            steps.extend(["AUDIT all service accounts for RC4-only tickets and SPNs with weak passwords",
                          "ROTATE KRBTGT twice if forgery is confirmed, then rotate service passwords",
                          "ENABLE AES Kerberos and pre-auth everywhere; alert on 4769/4771 bursts"])
            if users:
                steps.append(f"REVIEW service accounts targeted: {', '.join(users)}")
        elif attack_type in ("lateral_movement", "pass_the_hash"):
            steps.extend(["BUILD source→destination logon graph for the last 7 days", "BLOCK source IPs at WAF/firewall and rotate all traversed credentials"])
        elif attack_type in ("dns_tunneling", "c2_communication"):
            steps.extend(["BLOCK malicious domains/IPs at DNS + proxy layers", "HUNT fleet-wide for the same beacon interval/domain pattern"])
        elif attack_type == "persistence":
            steps.extend(["VERIFY task/service signer and creation parent process", "SWEEP fleet for identical task names, hashes, and run keys"])
        elif attack_type == "brute_force":
            steps.append("AUDIT IAM logs for any successful authentication from the attacking IPs within the past 7 days")
            if users:
                steps.extend([f"REVIEW privilege level and recent activity for accounts: {', '.join(users)}", "CHECK if targeted credentials appear in known breach databases"])
            steps.extend([f"BLOCK IP{'S' if len(ips) > 1 else ''} at WAF and email gateway", "ENABLE detailed audit logging on all authentication endpoints"])
        elif attack_type == "critical":
            steps.extend(["CONDUCT full incident response per NIST 800-61 guidelines", "PERFORM forensic imaging of affected host(s)", "ANALYZE network flow logs for C2 beaconing or data exfiltration"])
            if cves:
                steps.append(f"VERIFY all assets scanned for {', '.join(cves)}")
            steps.extend(["ENGAGE threat intelligence feed for indicators", "ESCALATE to CISO if PII/SPI data involved"])
        elif attack_type == "repeated_errors":
            steps.extend(["CORRELATE with deployment or configuration change timeline", "CHECK database connection pool limits", "REVIEW load balancer logs for traffic spike patterns"])
        else:
            steps.extend(["REVIEW raw log data for additional indicators", "CORRELATE with network flow data", "DOCUMENT findings and update detection rules"])
        steps.append("DOCUMENT investigation findings in the case management system with timeline and artifacts")
        return steps

    def _check_iocs(self, attack_type: str, ips: List[str], users: List[str], cves: List[str], paths: List[str]) -> List[Dict[str, Any]]:
        iocs = []
        for ip in ips:
            iocs.append({"ioc": ip, "type": "IP_ADDRESS", "confidence": 0.90 if attack_type == "brute_force" else 0.75, "context": f"Source IP associated with {attack_type.replace('_', ' ')} activity"})
        for user in users:
            iocs.append({"ioc": user, "type": "USERNAME", "confidence": 0.85, "context": "Targeted account in authentication attack"})
        for cve in cves:
            iocs.append({"ioc": cve, "type": "CVE", "confidence": 0.95, "context": "Exploited vulnerability"})
        for path in paths[:3]:
            iocs.append({"ioc": path, "type": "FILE_PATH", "confidence": 0.70, "context": "File path referenced in attack payload"})
        if not iocs:
            iocs.append({"ioc": "evidence-pending-review", "type": "MANUAL_REVIEW", "confidence": 0.30, "context": "No automated IOCs extracted"})
        return iocs

    def _generate_verdict_guide(self, confidence: float, fp_indicators: List[str]) -> str:
        if confidence >= 0.85 and not fp_indicators:
            return "VERDICT: LIKELY TRUE POSITIVE — Execute containment actions immediately. ACTION: Block IPs, isolate hosts, force password resets."
        elif confidence >= 0.85 and fp_indicators:
            return "VERDICT: POSSIBLE TRUE POSITIVE — Verify each false positive check item before containment. ACTION: Clear FP checks, then contain if still suspicious."
        elif confidence >= 0.70:
            return "VERDICT: SUSPICIOUS — moderate confidence, needs analyst review. ACTION: Check correlated logs from same host/source."
        else:
            return "VERDICT: LOW CONFIDENCE — insufficient evidence for automated decision. ACTION: Route to Tier 2 SOC for manual review."

    def _calculate_confidence(self, source_logs: List[Dict[str, Any]], attack_type: str) -> float:
        score = 0.70
        if len(source_logs) >= 5:
            score += 0.10
        if len(source_logs) >= 10:
            score += 0.05
        if attack_type == "critical":
            score += 0.10
        if attack_type == "brute_force":
            score += 0.05
        all_text = " ".join(log.get("message", "") for log in source_logs if isinstance(log, dict))
        if _extract_ips(all_text):
            score += 0.05
        if _extract_cves(all_text):
            score += 0.10
        return min(round(score, 2), 0.99)
