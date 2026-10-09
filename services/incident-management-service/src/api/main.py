from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers.incidents import router as incidents_router
from .routers.analytics import router as analytics_router
from .routers.hunt import router as hunt_router
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

limiter = Limiter(key_func=get_client_ip, default_limits=["60/second"])

app = FastAPI(title="Incident Management Service")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(AuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "incident-management-service"}

@app.get("/")
async def root():
    return {"status": "ok", "service": "Incident Management Service"}

setup_metrics(app)

app.include_router(incidents_router, prefix="/api/incidents", tags=["incidents"])
app.include_router(analytics_router, prefix="/api/analytics", tags=["analytics"])
app.include_router(hunt_router, prefix="/api/incidents", tags=["hunt"])