from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(
    title="OnyxSec API",
    description="AI-powered Cybersecurity Research Assistant",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "status": "online",
        "project": "OnyxSec",
        "version": "0.1.0",
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
        }
    )

