from app.core.config import settings
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="AI-powered Cybersecurity Research Assistant",
)


@app.get("/")
def root():
    return {
        "status": "online",
        "project": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "debug": settings.DEBUG,
        "message": "Welcome to OnyxSec 🚀",
    }


@app.get("/health")
def health():
    return JSONResponse(
        content={
            "status": "healthy",
            "backend": "running",
            "ai": "offline",
            "database": "offline",
            "log_level": settings.LOG_LEVEL,
        }
    )