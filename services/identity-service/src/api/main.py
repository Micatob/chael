from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import auth, agents, tenants
from api.routers.agent_registration import router as agent_reg_router
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

limiter = Limiter(key_func=get_client_ip, default_limits=["10/second"])

@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio
    from storage.agent_store import AgentStore
    store = AgentStore()

    async def stale_agent_checker():
        while True:
            await asyncio.sleep(60)
            try:
                store.mark_stale_agents_offline(stale_seconds=120)
            except Exception:
                pass

    task = asyncio.create_task(stale_agent_checker())
    yield
    task.cancel()

app = FastAPI(title="Chael Identity Service", lifespan=lifespan)
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
    return {"status": "healthy", "service": "identity-service"}

setup_metrics(app)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(agents.router, prefix="/api/auth", tags=["agents"])
app.include_router(tenants.router, prefix="/api/auth", tags=["tenants"])
app.include_router(agent_reg_router, prefix="/api", tags=["agent-registration"])
