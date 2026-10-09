import logging
import asyncio
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import flows
from config import settings
from storage.opensearch_client import OpenSearchClient
from collector.netflow import NetFlowCollector
from detection.flow_correlation import FlowCorrelationEngine
from metrics import setup_metrics

logger = logging.getLogger(__name__)

_collector = None
_correlation_engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _collector, _correlation_engine
    storage = OpenSearchClient()
    try:
        storage.ensure_indices()
        logger.info("Flow indices verified")
    except Exception as e:
        logger.error("Storage initialization error: %s", e)

    _collector = NetFlowCollector(storage)
    thread = threading.Thread(target=_collector.start, daemon=True)
    thread.start()
    logger.info(f"NetFlow collector thread started on UDP port {settings.NETFLOW_PORT}")

    _correlation_engine = FlowCorrelationEngine(storage)

    async def periodic_correlation():
        while True:
            await asyncio.sleep(300)
            try:
                logger.info("Running flow correlation checks...")
                _correlation_engine.run_all_checks()
            except Exception as e:
                logger.error(f"Flow correlation error: {e}")

    asyncio.create_task(periodic_correlation())
    logger.info("Flow correlation background task started (interval: 300s)")

    yield

    if _collector:
        _collector.stop()
        logger.info("NetFlow collector stopped")


app = FastAPI(title="Flow Collector Service", lifespan=lifespan)

setup_metrics(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "flow-collector"}

@app.get("/")
async def root():
    return {"status": "ok", "service": "Flow Collector Service"}

app.include_router(flows.router, prefix="/api/flows", tags=["flows"])
