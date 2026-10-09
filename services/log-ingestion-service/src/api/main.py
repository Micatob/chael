import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import logs
from .routers.analytics import router as analytics_router
from .routers.audit import router as audit_router
import requests
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from auth.middleware import AuthMiddleware
from metrics import setup_metrics

def get_client_ip(request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    forwarded = request.headers.get("X-Real-IP")
    if forwarded:
        return forwarded
    return get_remote_address(request)

limiter = Limiter(key_func=get_client_ip, default_limits=["200/second"])

logger = logging.getLogger(__name__)

_syslog_receiver = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    from storage.factory import get_storage_client
    global _syslog_receiver
    try:
        storage = get_storage_client()
        if hasattr(storage, "ensure_indices"):
            storage.ensure_indices()
            logger.info("OpenSearch indices verified")
    except Exception as e:
        logger.error("Storage initialization error: %s", e)

    from config import settings
    if settings.SYSLOG_ENABLED:
        try:
            from syslog_receiver.receiver import SyslogReceiver
            from .routers.logs import _handle_syslog_message

            _syslog_receiver = SyslogReceiver(
                udp_port=settings.SYSLOG_UDP_PORT,
                tcp_port=settings.SYSLOG_TCP_PORT,
                host=settings.API_HOST,
                callback=_handle_syslog_message,
            )
            asyncio.create_task(_syslog_receiver.start())
            logger.info(
                "Syslog receiver started: UDP=%s:%d TCP=%s:%d",
                settings.API_HOST, settings.SYSLOG_UDP_PORT,
                settings.API_HOST, settings.SYSLOG_TCP_PORT,
            )
        except Exception as e:
            logger.error("Failed to start syslog receiver: %s", e)

    yield

    if _syslog_receiver:
        try:
            await _syslog_receiver.stop()
            logger.info("Syslog receiver stopped")
        except Exception as e:
            logger.error("Error stopping syslog receiver: %s", e)


app = FastAPI(title="Log Ingestion Service", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(AuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "log-ingestion-service"}


@app.get("/")
async def root():
    return {"status": "ok", "service": "Log Ingestion Service"}


setup_metrics(app)

app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(analytics_router, prefix="/api", tags=["analytics"])
app.include_router(audit_router, prefix="/api/audit", tags=["audit"])
