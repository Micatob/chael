"""Backup/restore API for data-archiver (retention enforcement + disaster recovery)."""
import hashlib
import os
import gzip
import json
import logging
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from config import settings
from archiver import DataArchiver

logger = logging.getLogger("data-archiver-api")

app = FastAPI(title="Data Archiver & Backup Service")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


def _jwt_secret() -> str:
    return getattr(settings, "JWT_SECRET", "") or os.getenv("JWT_SECRET", "")


async def require_auth(request: Request):
    """Bearer JWT check (identity-service HS256). Public: /health, /metrics, docs."""
    secret = _jwt_secret()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not secret:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ", 1)[1]
    try:
        from jose import jwt as _jwt
        payload = _jwt.decode(token, secret, algorithms=[getattr(settings, "JWT_ALGORITHM", "HS256")])
        request.state.user = payload
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def _list_archives():
    files = []
    adir = settings.ARCHIVE_DIR
    if not os.path.isdir(adir):
        return files
    for f in sorted(os.listdir(adir), reverse=True):
        fp = os.path.join(adir, f)
        if os.path.isfile(fp):
            files.append({"name": f, "size_bytes": os.path.getsize(fp), "path": fp})
    return files


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "data-archiver"}


@app.get("/api/backup/health")
async def backup_health():
    return {"status": "healthy", "service": "data-archiver"}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/backup/list", dependencies=[Depends(require_auth)])
async def list_backups():
    return {"archive_dir": settings.ARCHIVE_DIR, "retention_days": settings.ARCHIVE_RETENTION_DAYS, "backups": _list_archives()}


@app.post("/api/backup/trigger", dependencies=[Depends(require_auth)])
async def trigger_backup():
    try:
        archiver = DataArchiver()
        archiver.run_archive_cycle()
        return {"status": "completed", "backups": _list_archives()[:5]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/backup/restore", dependencies=[Depends(require_auth)])
async def restore_backup(name: str = Query(..., description="Archive filename in ARCHIVE_DIR"),
                         index: str = Query("chaelsiem-logs-restore", description="Target index")):
    """Restore a .jsonl.gz archive into OpenSearch (bulk index)."""
    from opensearchpy import OpenSearch, helpers
    fp = os.path.join(settings.ARCHIVE_DIR, os.path.basename(name))
    if not os.path.isfile(fp):
        raise HTTPException(status_code=404, detail=f"Archive {name} not found")
    try:
        archiver = DataArchiver()
        client = archiver.os_client
        actions = []
        restored = 0
        sha = hashlib.sha256()
        opener = gzip.open if fp.endswith(".gz") else open
        with opener(fp, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                sha.update(line.encode("utf-8"))
                try:
                    doc = json.loads(line)
                except Exception:
                    continue
                actions.append({"_index": index, "_source": doc})
                restored += 1
                if len(actions) >= 500:
                    helpers.bulk(client, actions)
                    actions = []
        if actions:
            helpers.bulk(client, actions)
        # Staging verify: count docs now present in target index.
        verified = None
        try:
            resp = client.count(index=index)
            verified = resp.get("count") if isinstance(resp, dict) else None
        except Exception:
            verified = None
        return {"status": "restored", "archive": name, "target_index": index,
                "restored_count": restored, "sha256": sha.hexdigest(),
                "verified_count": verified}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Restore failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/backup/digest/{kind}", dependencies=[Depends(require_auth)])
async def run_digest_now(kind: str, options: dict = None):
    """Build (and optionally send) a SOC digest now. Body: {"send": true}.
    With send=false (default) returns a preview without touching SMTP."""
    from digest import run_digest, render_text
    if kind not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="kind must be daily|weekly")
    try:
        archiver = DataArchiver()
        result = run_digest(archiver.os_client, kind)
        if not (options or {}).get("send", False):
            result["delivery"] = {"sent": False, "reason": "preview only (send=false)"}
            result["preview"] = render_text(result["digest"], kind)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Digest failed")
        raise HTTPException(status_code=500, detail=str(e))
