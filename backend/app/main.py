from app.core.config import settings
from app.services.llm_service import ask_llm
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="AI-powered Cybersecurity Research Assistant",
)


class PromptRequest(BaseModel):
    prompt: str


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


@app.post("/ask")
def ask(request: PromptRequest):
    answer = ask_llm(request.prompt)

    return {
        "question": request.prompt,
        "answer": answer,
    }