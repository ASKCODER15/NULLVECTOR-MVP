"""NullVector API.

Endpoints:
  GET  /health     service and model readiness
  POST /ask        ask the local model a question
  POST /scan/url   safe, single-request web security scan
  POST /scan/ai    prompt-injection scan against an AI target

Both scan routes require an explicit authorization flag: they make outbound
requests and consume model capacity on the operator's behalf.
"""

from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ai.scanner.engine.url_scanner import UnsafeUrlError, UrlConnectionError
from ai.scanner.targets.base import TargetUnavailable
from app.core.config import settings
from app.services.ai_scan_service import model_available, scan_ai
from app.services.llm_service import ask_llm
from app.services.url_scan_service import scan_url as run_url_scan

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="AI behavior and web application security testing",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# The UI is a static single page served from the same origin as the API, so no
# CORS is involved and there is no build step. Mounted under /app so the JSON
# status endpoint at / keeps working.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount(
        "/app",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="ui",
    )


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    authorized: bool


class AiScanRequest(BaseModel):
    authorized: bool
    target_name: str = Field(default=None, max_length=120)
    system_prompt: str = Field(default=None, min_length=1, max_length=8000)
    canary: str = Field(default=None, min_length=4, max_length=128)
    model: str = Field(default=None, max_length=200)


def _require_authorization(authorized: bool, target: str) -> None:
    if not authorized:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Authorization is required before scanning {target}. Only scan "
                "systems you own or are explicitly permitted to test."
            ),
        )


@app.get("/")
def root():
    return {
        "status": "online",
        "project": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "debug": settings.DEBUG,
        "message": "Welcome to NullVector",
        "ui": "/app/",
    }


@app.get("/health")
def health():
    ai_online = model_available()
    return JSONResponse(
        content={
            "status": "healthy" if ai_online else "degraded",
            "backend": "running",
            "ai": "online" if ai_online else "offline",
            "model": settings.LM_STUDIO_MODEL,
            "database": "not_configured",
            "log_level": settings.LOG_LEVEL,
        }
    )


@app.post("/ask")
def ask(request: PromptRequest):
    try:
        answer = ask_llm(request.prompt)
    except requests.exceptions.RequestException as exc:
        raise HTTPException(
            status_code=503,
            detail="The local model is unavailable.",
        ) from exc
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail="The local model returned an unreadable response.",
        ) from exc

    return {
        "question": request.prompt,
        "answer": answer,
    }


@app.post("/scan/url")
def scan_url(request: UrlScanRequest):
    _require_authorization(request.authorized, "a URL")

    try:
        return run_url_scan(request.url)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UrlConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/scan/ai")
def scan_ai_target(request: AiScanRequest):
    _require_authorization(request.authorized, "an AI target")

    try:
        return scan_ai(
            name=request.target_name,
            system_prompt=request.system_prompt,
            canary=request.canary,
            model=request.model,
        )
    except TargetUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
