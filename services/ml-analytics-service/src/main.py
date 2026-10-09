import asyncio
import json
import logging
import sys
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from config import settings
from ueba import UEBAEngine
from auth.middleware import AuthMiddleware
from metrics import setup_metrics


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "service": "ml-analytics",
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "correlation_id": getattr(record, "correlation_id", None),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry, default=str)


def get_client_ip(request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    forwarded = request.headers.get("X-Real-IP")
    if forwarded:
        return forwarded
    return get_remote_address(request)


limiter = Limiter(key_func=get_client_ip, default_limits=["60/second"])

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(StructuredFormatter())
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO), handlers=[handler])
logger = logging.getLogger("ml-analytics")

ueba_engine = UEBAEngine()

async def run_ueba_loop():
    logger.info("Starting UEBA background loop...")
    while True:
        try:
            ueba_engine.run_analysis()
        except Exception as e:
            logger.error("UEBA loop error: %s", e)
        await asyncio.sleep(settings.POLL_INTERVAL_MINUTES * 60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ML Analytics Service starting up")
    asyncio.create_task(run_ueba_loop())
    yield

app = FastAPI(title="ML Analytics Service", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(AuthMiddleware)

setup_metrics(app)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ml-analytics-service"}

@app.get("/api/ml/health")
async def ml_health():
    return {"status": "healthy", "service": "ml-analytics-service"}

@app.post("/api/ml/analyze")
async def trigger_analysis(background_tasks: BackgroundTasks):
    """Manually trigger a UEBA analysis cycle."""
    background_tasks.add_task(ueba_engine.run_analysis)
    return {"status": "analysis_triggered"}


@app.get("/api/ml/status")
async def ml_status():
    """Get the status of the last UEBA analysis cycle."""
    return {
        "service": "ml-analytics",
        "last_run": ueba_engine.last_run,
        "status": ueba_engine.last_status,
        "anomaly_count": ueba_engine.last_anomaly_count,
        "poll_interval_minutes": settings.POLL_INTERVAL_MINUTES,
    }


@app.get("/api/ml/anomalies")
async def ml_anomalies():
    """Get the anomalies detected in the last analysis cycle."""
    return {
        "anomalies": ueba_engine.last_anomalies,
        "count": ueba_engine.last_anomaly_count,
        "last_run": ueba_engine.last_run,
    }


if __name__ == "__main__":
    logger.info("Starting ML Analytics Service", extra={"correlation_id": None})
    uvicorn.run(app, host="0.0.0.0", port=settings.API_PORT, log_config=None)
