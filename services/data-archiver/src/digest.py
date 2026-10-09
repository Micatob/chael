"""SOC digest reports: daily (24h) + weekly (7d) posture summaries.

Built straight from OpenSearch (no service auth needed), delivered over
SMTP. Disabled cleanly when SMTP_HOST/SMTP_TO are unset — the API preview
endpoints still work so analysts can review the format first.
"""
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any, Dict, List

from config import settings

logger = logging.getLogger("data-archiver-digest")


def _search(os_client, index: str, body: dict) -> dict:
    try:
        return os_client.search(index=index, body=body, ignore_unavailable=True) or {}
    except Exception as e:
        logger.warning("Digest query failed on %s: %s", index, e)
        return {}


def _count(os_client, index: str, query: dict) -> int:
    try:
        resp = os_client.count(index=index, body={"query": query}, ignore_unavailable=True) or {}
        return int(resp.get("count", 0))
    except Exception:
        return 0


def build_digest(os_client, hours: int = 24) -> Dict[str, Any]:
    """Assemble the numbers for the last N hours. Never raises."""
    window = f"now-{hours}h"
    logs_total = _count(os_client, "chaelsiem-logs*", {"range": {"timestamp": {"gte": window}}})

    sev_aggs = _search(os_client, "chaelsiem-logs*", {
        "size": 0, "query": {"range": {"timestamp": {"gte": window}}},
        "aggs": {"by_sev": {"terms": {"field": "severity", "size": 10}},
                 "by_host": {"terms": {"field": "host", "size": 5}}},
    }).get("aggregations", {})
    by_sev = {b["key"]: b["doc_count"] for b in sev_aggs.get("by_sev", {}).get("buckets", [])}
    top_hosts = [(b["key"], b["doc_count"]) for b in sev_aggs.get("by_host", {}).get("buckets", [])]

    inc_hits = _search(os_client, "chaelsiem-incidents", {
        "size": 100, "query": {"range": {"timestamp": {"gte": window}}},
        "sort": [{"risk_score": {"order": "desc"}}],
        "_source": ["incident_id", "timestamp", "risk_score", "status", "description"],
    }).get("hits", {}).get("hits", [])
    incidents = [h.get("_source", {}) for h in inc_hits]
    open_now = _count(os_client, "chaelsiem-incidents",
                      {"bool": {"must_not": [{"terms": {"status": ["RESOLVED", "CLOSED", "FALSE_POSITIVE"]}}]}})
    sla_breached = _count(os_client, "chaelsiem-incidents", {"term": {"sla_breached": True}})

    top = incidents[:5]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_hours": hours,
        "logs_total": logs_total,
        "logs_by_severity": by_sev,
        "top_hosts": top_hosts,
        "incidents_created": len(incidents),
        "incidents_open": open_now,
        "sla_breached": sla_breached,
        "top_incidents": [
            {"id": i.get("incident_id", "")[:8], "risk": i.get("risk_score", 0),
             "status": i.get("status", ""), "desc": (i.get("description") or "")[:100]}
            for i in top
        ],
    }


def render_text(digest: Dict[str, Any], kind: str) -> str:
    lines = [
        f"CHAEL SIEM {kind.upper()} DIGEST — last {digest['window_hours']}h",
        f"Generated: {digest['generated_at']}",
        "",
        f"Logs ingested: {digest['logs_total']}",
    ]
    for sev, count in sorted(digest["logs_by_severity"].items()):
        lines.append(f"  {sev}: {count}")
    lines += ["",
              f"Incidents created: {digest['incidents_created']}",
              f"Incidents open: {digest['incidents_open']}",
              f"SLA breached: {digest['sla_breached']}",
              ""]
    if digest["top_hosts"]:
        lines.append("Top hosts:")
        lines += [f"  {h}: {c} logs" for h, c in digest["top_hosts"]]
        lines.append("")
    if digest["top_incidents"]:
        lines.append("Top incidents:")
        lines += [f"  [{i['risk']}] {i['id']} {i['status']} — {i['desc']}" for i in digest["top_incidents"]]
    else:
        lines.append("No incidents in window. Quiet shift — verify agents are shipping.")
    lines += ["", "— Chael SIEM (automated digest, do not reply)"]
    return "\n".join(lines)


def send_digest(kind: str, digest: Dict[str, Any]) -> Dict[str, Any]:
    """Email the rendered digest. Returns {sent, reason} — never raises."""
    to_addrs = [a.strip() for a in (settings.SMTP_TO or "").split(",") if a.strip()]
    if not settings.SMTP_HOST or not to_addrs:
        reason = "SMTP_HOST/SMTP_TO not configured — digest built but not sent"
        logger.info(reason)
        return {"sent": False, "reason": reason}
    subject = f"[Chael SIEM] {kind.title()} digest: {digest['incidents_created']} new, {digest['incidents_open']} open"
    msg = MIMEText(render_text(digest, kind), _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(to_addrs)
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as smtp:
            if settings.SMTP_TLS:
                smtp.starttls()
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.sendmail(settings.SMTP_FROM, to_addrs, msg.as_string())
        logger.info("Digest emailed to %s", to_addrs)
        return {"sent": True, "to": to_addrs, "subject": subject}
    except Exception as e:
        logger.error("Digest email failed: %s", e)
        return {"sent": False, "reason": str(e)[:300]}


def run_digest(os_client, kind: str = "daily") -> Dict[str, Any]:
    hours = 24 if kind == "daily" else 24 * 7
    digest = build_digest(os_client, hours=hours)
    result = send_digest(kind, digest)
    return {"kind": kind, "digest": digest, "delivery": result}
