"""VerifyFirst Backend — Phase 0 Foundation"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.analyze import router as analyze_router

from contextlib import asynccontextmanager

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

# CORS Configuration
# VerifyFirst is currently designed for local individual deployment.
# We restrict CORS to explicit local development origins.
# If deploying publicly, tighten this further based on actual extension ID.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://web.whatsapp.com" # Required if content script fetches directly instead of using Service Worker
    ],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "Accept"],
)

# Mount API routes
app.include_router(analyze_router, prefix="/api/v1")


@app.get("/health")
async def health():
    """Health check endpoint to verify the backend is running."""
    return {"status": "ok", "phase": "1A"}

