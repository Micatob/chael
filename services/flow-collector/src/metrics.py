import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_COUNT = Counter("http_requests_total", "Total HTTP requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency", ["method", "path"])
REQUESTS_IN_PROGRESS = Gauge("http_requests_in_progress", "Requests currently being processed", ["method"])
FLOW_INGESTED = Counter("flow_records_ingested_total", "Total flow records ingested")
NETFLOW_PACKETS = Counter("netflow_packets_received_total", "Total NetFlow datagrams received")

class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        REQUESTS_IN_PROGRESS.labels(method=request.method).inc()
        start = time.time()
        try:
            response = await call_next(request)
            duration = time.time() - start
            REQUEST_COUNT.labels(method=request.method, path=request.url.path, status=response.status_code).inc()
            REQUEST_LATENCY.labels(method=request.method, path=request.url.path).observe(duration)
            return response
        except Exception:
            duration = time.time() - start
            REQUEST_COUNT.labels(method=request.method, path=request.url.path, status=500).inc()
            REQUEST_LATENCY.labels(method=request.method, path=request.url.path).observe(duration)
            raise
        finally:
            REQUESTS_IN_PROGRESS.labels(method=request.method).dec()

def setup_metrics(app):
    app.add_middleware(MetricsMiddleware)

    @app.get("/metrics")
    async def metrics():
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
