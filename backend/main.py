"""VerifyFirst Backend — Phase 0 Foundation"""

import os
import time
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.api.analyze import router as analyze_router
from contextlib import asynccontextmanager

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Production Logging Configuration
# SECURITY: Do NOT log request bodies containing URLs or messages
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Rate Limiter setup (using client IP for local/development or X-Forwarded-For in prod)
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

@asynccontextmanager
async def lifespan(app: FastAPI):
    from backend.api.analyze import intel_service
    await intel_service.start()
    yield
    await intel_service.stop()

app = FastAPI(
    title="VerifyFirst API",
    version="0.1.0",
    description="VerifyFirst backend API for website security analysis",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS Configuration
# Driven by environment variables for production flexibility
# Example: EXTENSION_ORIGINS="chrome-extension://abcdefg,chrome-extension://12345"
allowed_origins = os.getenv(
    "EXTENSION_ORIGINS", 
    "*"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request structural logging middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    
    # We deliberately do not log request.url.path query parameters or request body 
    # to prevent leaking private WhatsApp data into infrastructure logs.
    logger.info(f"Incoming request: {request.method} {request.url.path}")
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(f"Completed request: {request.method} {request.url.path} - Status: {response.status_code} - Latency: {process_time:.4f}s")
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"Failed request: {request.method} {request.url.path} - Exception: {str(e)} - Latency: {process_time:.4f}s")
        # Fail safe and avoid leaking backend traces to clients
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Safe fail open."}
        )

# Mount API routes
app.include_router(analyze_router, prefix="/api/v1")


@app.get("/health")
async def health():
    """Health check endpoint to verify the backend is running."""
    return {"status": "ok", "phase": "1A"}

