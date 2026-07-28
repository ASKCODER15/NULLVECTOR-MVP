from fastapi import FastAPI

app = FastAPI(
    title="OnyxSec API",
    version="0.1.0",
    description="AI-powered Cybersecurity Research Assistant"
)


@app.get("/")
def root():
    return {
        "message": "Welcome to OnyxSec 🚀"
    }