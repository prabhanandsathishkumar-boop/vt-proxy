import os
import httpx
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow requests from Claude artifacts and any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


@app.get("/vt/{path:path}")
async def proxy_vt(path: str):
    """Proxy any VT API v3 GET request server-side to avoid CORS."""
    url = f"{VT_BASE}/{path}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(url, headers={"x-apikey": VT_API_KEY})
    return resp.json()


@app.get("/health")
async def health():
    return {"status": "ok"}
