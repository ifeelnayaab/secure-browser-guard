"""
Secure Browser Guard - FastAPI Backend
Uses VirusTotal API for AI-powered URL scanning.

Run with:
    uvicorn main:app --reload --port 8000
"""

import base64
import os
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Secure Browser Guard API", version="1.0.0")

# Allow requests from Chrome extension and dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Put your VirusTotal API key here (free at virustotal.com)
# -------------------------------------------------------------------
VT_API_KEY = "d9267627a4e36624d2bb0fd54a7865f1a44aea3800482906f0fa7b20ea4ec931"
VT_BASE    = "https://www.virustotal.com/api/v3"


class ScanRequest(BaseModel):
    url: str


class EngineResult(BaseModel):
    engine: str
    verdict: str       # "malicious" | "suspicious"
    category: str      # e.g. "phishing", "malware", "trojan", "XSS", etc.

class ScanResult(BaseModel):
    url: str
    is_phishing: bool
    threat_level: str          # "safe" | "suspicious" | "malicious"
    malicious_votes: int
    suspicious_votes: int
    total_engines: int
    confidence_percent: float
    summary: str
    flagging_engines: list[EngineResult]   # engines that flagged the URL
    threat_categories: list[str]           # deduplicated threat category labels


def encode_url(url: str) -> str:
    """VirusTotal requires URLs base64-encoded (no padding '=')."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


@app.get("/health")
def health():
    return {"status": "ok", "service": "Secure Browser Guard"}


@app.post("/scan", response_model=ScanResult)
async def scan_url(req: ScanRequest):
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Open backend/main.py and set VT_API_KEY."
        )

    url_id = encode_url(req.url)
    headers = {"x-apikey": VT_API_KEY}

    import asyncio

    async with httpx.AsyncClient(timeout=20) as client:
        # First try a GET (URL may already be cached by VirusTotal)
        resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)

        engine_results_raw: dict = {}

        if resp.status_code == 404:
            # Not cached — submit for scanning
            submit = await client.post(
                f"{VT_BASE}/urls",
                headers=headers,
                data={"url": req.url}
            )
            if submit.status_code not in (200, 201):
                raise HTTPException(status_code=502, detail="VirusTotal submission failed.")

            analysis_id = submit.json()["data"]["id"]

            # Poll until analysis is done (max 10s)
            for _ in range(5):
                await asyncio.sleep(2)
                poll = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
                poll_data = poll.json()
                attrs = poll_data.get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    stats = attrs["stats"]
                    engine_results_raw = attrs.get("results", {})
                    break
            else:
                stats = {"malicious": 0, "suspicious": 0, "undetected": 1, "harmless": 0}
        else:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            engine_results_raw = attrs.get("last_analysis_results", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected or 1

    confidence  = round((malicious / total) * 100, 1)

    # Build per-engine flagging list from the raw results map.
    # Each entry looks like: { "category": "phishing", "result": "malicious", "method": "...", "engine_name": "..." }
    flagging_engines: list[EngineResult] = []
    seen_categories: list[str] = []
    for engine_name, data in engine_results_raw.items():
        verdict = (data.get("result") or "").lower()
        category = (data.get("category") or "").lower()
        if verdict in ("malicious", "suspicious") or category in ("malicious", "suspicious", "phishing", "malware"):
            label = (data.get("result") or data.get("category") or "flagged").strip()
            cat = (data.get("category") or verdict or "unknown").strip()
            flagging_engines.append(EngineResult(engine=engine_name, verdict=verdict or "flagged", category=cat))
            if cat and cat not in seen_categories:
                seen_categories.append(cat)

    if malicious >= 3:
        threat_level = "malicious"
        is_phishing  = True
        summary      = f"⚠️ Flagged as malicious by {malicious} AI security engines."
    elif malicious >= 1 or suspicious >= 3:
        threat_level = "suspicious"
        is_phishing  = True
        summary      = f"⚠️ Flagged as suspicious by {malicious + suspicious} engines. Proceed with caution."
    else:
        threat_level = "safe"
        is_phishing  = False
        summary      = f"✅ Looks safe. {harmless} engines confirmed this URL as clean."

    return ScanResult(
        url=req.url,
        is_phishing=is_phishing,
        threat_level=threat_level,
        malicious_votes=malicious,
        suspicious_votes=suspicious,
        total_engines=total,
        confidence_percent=confidence,
        summary=summary,
        flagging_engines=flagging_engines,
        threat_categories=seen_categories,
    )
