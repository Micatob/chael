import logging
from fastapi import APIRouter, HTTPException, Query, Depends, Request
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from storage.factory import get_storage_client
from auth.middleware import require_roles

logger = logging.getLogger(__name__)

router = APIRouter()
opensearch = get_storage_client()


@router.get("/dashboard/summary")
async def dashboard_summary(user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))):
    now = datetime.now(timezone.utc)
    last_24h = (now - timedelta(hours=24)).isoformat()
    last_7d = (now - timedelta(days=7)).isoformat()

    try:
        stats = opensearch.client.search(
            index=opensearch.log_index,
            body={
                "size": 0,
                "query": {"range": {"timestamp": {"gte": last_24h}}},
                "aggs": {
                    "total_events": {"value_count": {"field": "timestamp"}},
                    "by_severity": {"terms": {"field": "severity", "size": 10}},
                    "top_hosts": {"terms": {"field": "host", "size": 10}},
                    "top_sources": {"terms": {"field": "source", "size": 10}},
                    "events_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 0,
                            "extended_bounds": {"min": (now - timedelta(hours=24)).timestamp() * 1000, "max": now.timestamp() * 1000},
                        }
                    },
                },
            },
        )
        aggs = stats.get("aggregations", {})
        total = aggs.get("total_events", {}).get("value", 0)
        severity = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
        top_hosts = [{"host": b["key"], "count": b["doc_count"]} for b in aggs.get("top_hosts", {}).get("buckets", [])]
        top_sources = [{"source": b["key"], "count": b["doc_count"]} for b in aggs.get("top_sources", {}).get("buckets", [])]
        timeseries = [{"timestamp": b["key_as_string"], "count": b["doc_count"]} for b in aggs.get("events_over_time", {}).get("buckets", [])]

        incident_count = 0
        try:
            inc_resp = opensearch.client.count(
                index=opensearch.incident_index,
                body={"query": {"range": {"timestamp": {"gte": last_7d}}}},
            )
            incident_count = inc_resp.get("count", 0)
        except Exception:
            pass

        return {
            "total_events_24h": total,
            "incident_count_7d": incident_count,
            "severity_distribution": severity,
            "top_hosts": top_hosts,
            "top_sources": top_sources,
            "events_timeseries": timeseries,
        }
    except Exception as e:
        logger.warning("Dashboard summary failed: %s", e)
        return {
            "total_events_24h": 0,
            "incident_count_7d": 0,
            "severity_distribution": {},
            "top_hosts": [],
            "top_sources": [],
            "events_timeseries": [],
        }


@router.get("/dashboard/top-offenders")
async def top_offenders(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"])),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        resp = opensearch.client.search(
            index=opensearch.log_index,
            body={
                "size": 0,
                "query": {"range": {"timestamp": {"gte": since}}},
                "aggs": {
                    "top_ips": {
                        "terms": {"field": "metadata.src_ip.keyword", "size": limit, "min_doc_count": 5},
                    },
                    "top_users": {
                        "terms": {"field": "metadata.user.keyword", "size": limit, "min_doc_count": 5},
                    },
                    "top_event_types": {
                        "terms": {"field": "metadata.event_type.keyword", "size": limit},
                    },
                },
            },
        )
        aggs = resp.get("aggregations", {})
        return {
            "top_ips": [{"ip": b["key"], "count": b["doc_count"]} for b in aggs.get("top_ips", {}).get("buckets", [])],
            "top_users": [{"user": b["key"], "count": b["doc_count"]} for b in aggs.get("top_users", {}).get("buckets", [])],
            "top_event_types": [{"event_type": b["key"], "count": b["doc_count"]} for b in aggs.get("top_event_types", {}).get("buckets", [])],
        }
    except Exception as e:
        logger.warning("Top offenders query failed: %s", e)
        return {"top_ips": [], "top_users": [], "top_event_types": []}


@router.get("/dashboard/geo-events")
async def geo_events(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"])),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        resp = opensearch.client.search(
            index=opensearch.log_index,
            body={
                "size": 500,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": since}}},
                            {"exists": {"field": "metadata.geo_latitude"}},
                        ],
                    },
                },
                "_source": ["metadata.geo_latitude", "metadata.geo_longitude", "metadata.src_ip", "host", "severity", "timestamp"],
            },
        )
        points = []
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            meta = src.get("metadata", {})
            lat = meta.get("geo_latitude")
            lon = meta.get("geo_longitude")
            if lat is not None and lon is not None:
                points.append({
                    "lat": lat,
                    "lon": lon,
                    "ip": meta.get("src_ip", ""),
                    "host": src.get("host", ""),
                    "severity": src.get("severity", "INFO"),
                    "timestamp": src.get("timestamp", ""),
                })
        return {"events": points, "total": len(points)}
    except Exception as e:
        logger.warning("Geo events query failed: %s", e)
        return {"events": [], "total": 0}


@router.get("/dashboard/incident-trends")
async def incident_trends(
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"])),
):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        resp = opensearch.client.search(
            index=opensearch.incident_index,
            body={
                "size": 0,
                "query": {"range": {"timestamp": {"gte": since}}},
                "aggs": {
                    "by_day": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1d",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": (datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000,
                                "max": datetime.now(timezone.utc).timestamp() * 1000,
                            },
                        },
                    },
                    "by_severity": {"terms": {"field": "risk_score", "size": 10}},
                    "by_rule": {"terms": {"field": "artifacts.rule.keyword", "size": 20}},
                },
            },
        )
        aggs = resp.get("aggregations", {})
        timeseries = [{"date": b["key_as_string"], "count": b["doc_count"]} for b in aggs.get("by_day", {}).get("buckets", [])]

        risk_buckets = aggs.get("by_severity", {}).get("buckets", [])
        by_severity = {}
        for b in risk_buckets:
            score = b["key"]
            if score >= 90:
                by_severity["CRITICAL"] = by_severity.get("CRITICAL", 0) + b["doc_count"]
            elif score >= 70:
                by_severity["HIGH"] = by_severity.get("HIGH", 0) + b["doc_count"]
            elif score >= 40:
                by_severity["MEDIUM"] = by_severity.get("MEDIUM", 0) + b["doc_count"]
            else:
                by_severity["LOW"] = by_severity.get("LOW", 0) + b["doc_count"]

        return {
            "timeseries": timeseries,
            "by_severity": by_severity,
            "by_rule": {b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])},
        }
    except Exception as e:
        logger.warning("Incident trends query failed: %s", e)
        return {"timeseries": [], "by_severity": {}, "by_rule": {}}


@router.get("/report/daily")
async def daily_report(user: dict = Depends(require_roles(["ADMIN"]))):
    now = datetime.now(timezone.utc)
    yesterday = (now - timedelta(hours=24)).isoformat()
    try:
        log_count = 0
        incident_count = 0
        try:
            log_count = opensearch.client.count(
                index=opensearch.log_index,
                body={"query": {"range": {"timestamp": {"gte": yesterday}}}},
            ).get("count", 0)
        except Exception:
            pass
        try:
            incident_count = opensearch.client.count(
                index=opensearch.incident_index,
                body={"query": {"range": {"timestamp": {"gte": yesterday}}}},
            ).get("count", 0)
        except Exception:
            pass

        return {
            "report_type": "daily_summary",
            "generated_at": now.isoformat(),
            "period_start": yesterday,
            "period_end": now.isoformat(),
            "total_logs_ingested": log_count,
            "total_incidents_triggered": incident_count,
            "top_severity": {},
            "top_sources": [],
        }
    except Exception as e:
        logger.warning("Daily report failed: %s", e)
        return {"error": str(e)}


@router.get("/report/top-threats")
async def top_threats_report(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(require_roles(["ADMIN"])),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        resp = opensearch.client.search(
            index=opensearch.incident_index,
            body={
                "size": 50,
                "query": {"range": {"timestamp": {"gte": since}}},
                "sort": [{"risk_score": {"order": "desc"}}],
                "_source": ["incident_id", "description", "risk_score", "timestamp", "artifacts", "status"],
            },
        )
        incidents = []
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            incidents.append({
                "incident_id": src.get("incident_id"),
                "description": src.get("description"),
                "risk_score": src.get("risk_score"),
                "timestamp": src.get("timestamp"),
                "rule": src.get("artifacts", {}).get("rule", ""),
                "host": src.get("artifacts", {}).get("host", ""),
                "status": src.get("status", "OPEN"),
            })
        return {"report": "top_threats", "period_hours": hours, "incidents": incidents, "total": len(incidents)}
    except Exception as e:
        logger.warning("Top threats report failed: %s", e)
        return {"report": "top_threats", "incidents": [], "total": 0}


@router.get("/report/agent-uptime")
async def agent_uptime_report(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(require_roles(["ADMIN"])),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        resp = opensearch.client.search(
            index="chaelsiem-source-heartbeats",
            body={
                "size": 0,
                "query": {"range": {"timestamp": {"gte": since}}},
                "aggs": {
                    "by_host": {
                        "terms": {"field": "hostname.keyword", "size": 100},
                        "aggs": {
                            "statuses": {"terms": {"field": "status.keyword", "size": 5}},
                            "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}], "_source": {"includes": ["timestamp", "status"]}}},
                        },
                    },
                },
            },
        )
        agents = []
        for bucket in resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
            latest_hit = bucket.get("latest", {}).get("hits", {}).get("hits", [])
            last_seen = ""
            status = "unknown"
            if latest_hit:
                src = latest_hit[0].get("_source", {})
                last_seen = src.get("timestamp", "")
                status = src.get("status", "unknown")
            agents.append({
                "hostname": bucket["key"],
                "heartbeat_count": bucket["doc_count"],
                "current_status": status,
                "last_seen": last_seen,
            })
        return {"report": "agent_uptime", "period_hours": hours, "agents": agents, "total": len(agents)}
    except Exception as e:
        logger.warning("Agent uptime report failed: %s", e)
        return {"report": "agent_uptime", "agents": [], "total": 0}
