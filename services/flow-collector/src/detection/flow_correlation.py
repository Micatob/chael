import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from storage.opensearch_client import OpenSearchClient

logger = logging.getLogger(__name__)

class FlowCorrelationEngine:
    def __init__(self, storage: OpenSearchClient):
        self.storage = storage
        self.incident_index = "chaelsiem-incidents"

    def detect_port_scanning(self, window_minutes: int = 5, port_threshold: int = 20) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(minutes=window_minutes)).isoformat()

        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": window_start}}
            },
            "aggs": {
                "scanning_ips": {
                    "terms": {"field": "src_ip", "size": 50, "min_doc_count": port_threshold},
                    "aggs": {
                        "unique_ports": {"cardinality": {"field": "dst_port"}},
                        "destinations": {"terms": {"field": "dst_ip", "size": 10}}
                    }
                }
            }
        }

        try:
            # ignore_unavailable prevents 404 when index not yet created
            response = self.storage.client.search(index=self.storage.flow_index, body=query, params={"ignore_unavailable": "true"})
            buckets = response.get("aggregations", {}).get("scanning_ips", {}).get("buckets", [])
            results = []
            for bucket in buckets:
                unique_ports = bucket.get("unique_ports", {}).get("value", 0)
                if unique_ports >= port_threshold:
                    results.append({
                        "src_ip": bucket["key"],
                        "total_flows": bucket["doc_count"],
                        "unique_ports": int(unique_ports),
                        "top_destinations": [
                            {"ip": b["key"], "count": b["doc_count"]}
                            for b in bucket.get("destinations", {}).get("buckets", [])
                        ],
                        "type": "port_scan"
                    })
            return results
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.debug(f"Port scan: index {self.storage.flow_index} not yet created — skipping")
            else:
                logger.warning(f"Port scan detection error: {e}")
            return []

    def detect_beaconing(self, window_hours: int = 24, min_flows: int = 10) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(hours=window_hours)).isoformat()

        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": window_start}}
            },
            "aggs": {
                "beacon_pairs": {
                    "terms": {"field": "src_ip", "size": 100, "min_doc_count": min_flows},
                    "aggs": {
                        "destinations": {
                            "terms": {"field": "dst_ip", "size": 10, "min_doc_count": 3},
                            "aggs": {
                                "flow_times": {"terms": {"field": "dst_port", "size": 5}},
                                "duration_avg": {"avg": {"field": "duration_seconds"}},
                                "bytes_avg": {"avg": {"field": "bytes"}},
                            }
                        }
                    }
                }
            }
        }

        try:
            response = self.storage.client.search(index=self.storage.flow_index, body=query, params={"ignore_unavailable": "true"})
            buckets = response.get("aggregations", {}).get("beacon_pairs", {}).get("buckets", [])
            results = []
            for bucket in buckets:
                for dest_bucket in bucket.get("destinations", {}).get("buckets", []):
                    avg_duration = dest_bucket.get("duration_avg", {}).get("value", 0)
                    avg_bytes = dest_bucket.get("bytes_avg", {}).get("value", 0)
                    # Beaconing indicators: short, consistent flows
                    if avg_duration < 5 and avg_bytes < 5000:
                        results.append({
                            "src_ip": bucket["key"],
                            "dst_ip": dest_bucket["key"],
                            "total_flows": dest_bucket["doc_count"],
                            "avg_duration_seconds": round(avg_duration, 2),
                            "avg_bytes": round(avg_bytes, 0),
                            "type": "beaconing"
                        })
            return results
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.debug(f"Beaconing: index {self.storage.flow_index} not yet created — skipping")
            else:
                logger.warning(f"Beaconing detection error: {e}")
            return []

    def detect_ddos(self, window_minutes: int = 5, flow_threshold: int = 100) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(minutes=window_minutes)).isoformat()

        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": window_start}}
            },
            "aggs": {
                "targeted_ips": {
                    "terms": {"field": "dst_ip", "size": 50, "min_doc_count": flow_threshold},
                    "aggs": {
                        "unique_sources": {"cardinality": {"field": "src_ip"}},
                        "target_ports": {"terms": {"field": "dst_port", "size": 10}},
                        "total_bytes": {"sum": {"field": "bytes"}},
                        "protocols": {"terms": {"field": "protocol", "size": 5}}
                    }
                }
            }
        }

        try:
            response = self.storage.client.search(index=self.storage.flow_index, body=query, params={"ignore_unavailable": "true"})
            buckets = response.get("aggregations", {}).get("targeted_ips", {}).get("buckets", [])
            results = []
            for bucket in buckets:
                unique_sources = bucket.get("unique_sources", {}).get("value", 0)
                if unique_sources >= 10:
                    results.append({
                        "dst_ip": bucket["key"],
                        "total_flows": bucket["doc_count"],
                        "unique_sources": int(unique_sources),
                        "total_bytes": int(bucket.get("total_bytes", {}).get("value", 0)),
                        "top_ports": [
                            {"port": b["key"], "count": b["doc_count"]}
                            for b in bucket.get("target_ports", {}).get("buckets", [])
                        ],
                        "type": "ddos"
                    })
            return results
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.debug(f"DDoS: index {self.storage.flow_index} not yet created — skipping")
            else:
                logger.warning(f"DDoS detection error: {e}")
            return []

    def create_incident(self, finding: Dict[str, Any]) -> Optional[str]:
        type_labels = {
            "port_scan": "Port Scanning",
            "beaconing": "C2 Beaconing",
            "ddos": "DDoS Amplification"
        }
        type_scores = {
            "port_scan": 65,
            "beaconing": 85,
            "ddos": 95
        }

        alert_type = finding.get("type")
        label = type_labels.get(alert_type, "Network Anomaly")
        score = type_scores.get(alert_type, 50)

        if alert_type == "port_scan":
            description = f"{label} detected: {finding['src_ip']} scanned {finding['unique_ports']} ports ({finding['total_flows']} flows)"
        elif alert_type == "beaconing":
            description = f"{label} detected: {finding['src_ip']} -> {finding['dst_ip']} ({finding['total_flows']} flows, {finding['avg_duration_seconds']}s avg)"
        elif alert_type == "ddos":
            description = f"{label} detected: {finding['dst_ip']} targeted by {finding['unique_sources']} sources ({finding['total_flows']} flows)"
        else:
            description = f"Network anomaly: {finding}"

        incident = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": f"flow-{alert_type}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(str(finding)) % 10000:04d}",
            "description": description,
            "status": "OPEN",
            "risk_score": score,
            "affected_host": finding.get("src_ip") or finding.get("dst_ip", "unknown"),
            "evidence": finding,
            "tenant_id": "default"
        }

        try:
            self.storage.client.index(
                index=self.incident_index,
                body=incident,
                id=incident["incident_id"],
                refresh=True
            )
            logger.info(f"Created flow incident: {incident['incident_id']} - {description}")
            return incident["incident_id"]
        except Exception as e:
            logger.error(f"Failed to create flow incident: {e}")
            return None

    def run_all_checks(self):
        results = []

        port_scans = self.detect_port_scanning()
        for ps in port_scans:
            self.create_incident(ps)
            results.append(ps)

        beaconing = self.detect_beaconing()
        for b in beaconing:
            self.create_incident(b)
            results.append(b)

        ddos = self.detect_ddos()
        for d in ddos:
            self.create_incident(d)
            results.append(d)

        if results:
            logger.info(f"Flow correlation: {len(results)} anomalies detected")
        return results
