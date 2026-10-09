from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers.enrich import router as enrich_router
from .routers.iocs import router as iocs_router
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

app = FastAPI(title="Threat Feed Service")
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


@app.get("/")
async def root():
    return {"status": "ok", "service": "Threat Feed Service"}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "threat-feed"}


setup_metrics(app)

app.include_router(enrich_router, prefix="/api/threat-feed", tags=["threat-feed"])
app.include_router(iocs_router, prefix="/api/threat-feed", tags=["iocs"])
