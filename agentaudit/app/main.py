"""AgentAudit HTTP service.

Free, no login, no API key, nothing written to disk. Scanning is pure CPU, so a
launch-day spike costs bandwidth and nothing else.
"""

from __future__ import annotations

import html
import json
import os
import threading
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .card import render_card
from .models import ScanRequest
from .normalize import ToolParseError
from .scoring import AuditResult, audit
from .store import store

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
EXAMPLES_DIR = BASE_DIR.parent / "examples"

PUBLIC_HOST = os.environ.get("AGENTAUDIT_HOST", "agentaudit.dev")

#: Per-IP request budget. Generous for humans, enough to blunt a scripted flood.
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW = 60.0

app = FastAPI(
    title="AgentAudit",
    description="Score an AI agent's system prompt and tool schema for prompt-injection and privilege risk.",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


# --- rate limiting ---------------------------------------------------------

_buckets: dict[str, deque[float]] = {}
_buckets_lock = threading.Lock()


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(request: Request) -> bool:
    now = time.monotonic()
    key = _client_key(request)
    with _buckets_lock:
        bucket = _buckets.setdefault(key, deque())
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return True
        bucket.append(now)
        # Opportunistic cleanup so the dict cannot grow without bound.
        if len(_buckets) > 10_000:
            for stale in [k for k, v in _buckets.items() if not v or now - v[-1] > RATE_LIMIT_WINDOW]:
                _buckets.pop(stale, None)
    return False


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path.startswith(("/api/scan", "/api/card")) and _rate_limited(request):
        return JSONResponse(
            {"error": "Rate limit exceeded. Try again in a minute."},
            status_code=429,
        )
    return await call_next(request)


# --- helpers ---------------------------------------------------------------


def _run_audit(payload: ScanRequest) -> AuditResult:
    if payload.is_empty:
        raise HTTPException(
            status_code=400,
            detail="Paste a system prompt, a tool schema, or both — there is nothing to score.",
        )
    try:
        return audit(payload.system_prompt, payload.tools, payload.config)
    except ToolParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _load_example(slug: str) -> dict:
    path = (EXAMPLES_DIR / f"{slug}.json").resolve()
    if not path.is_file() or EXAMPLES_DIR.resolve() not in path.parents:
        raise HTTPException(status_code=404, detail="No such example.")
    return json.loads(path.read_text())


# --- routes ----------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "cached_results": len(store)}


@app.post("/api/scan")
async def scan(payload: ScanRequest) -> dict:
    result = _run_audit(payload)
    data = result.to_dict()
    # Keep only what a share link needs to re-render. The prompt is not stored.
    store.put(result.scan_id, data)
    data["share_path"] = f"/r/{result.scan_id}"
    data["card_path"] = f"/card/{result.scan_id}.png"
    return data


@app.post("/api/card")
async def card_from_body(payload: ScanRequest) -> Response:
    """Stateless card render, for CI jobs that want the PNG in one call."""
    result = _run_audit(payload)
    return Response(
        content=render_card(result, host=PUBLIC_HOST),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/card/{scan_id}.png")
async def card_by_id(scan_id: str) -> Response:
    data = store.get(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="That result has expired.")
    return Response(
        content=render_card(_rehydrate(data), host=PUBLIC_HOST),
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/r/{scan_id}", response_class=HTMLResponse)
async def share_page(scan_id: str) -> HTMLResponse:
    data = store.get(scan_id)
    if data is None:
        return HTMLResponse(
            (STATIC_DIR / "index.html").read_text().replace(
                "<!--BOOTSTRAP-->",
                "<script>window.__EXPIRED__=true;</script>",
            ),
            status_code=404,
        )

    title = f"Agent Security Score: {data['score']}/100 — {data['verdict']}"
    description = data["headline"]
    card_url = f"https://{PUBLIC_HOST}/card/{scan_id}.png"
    meta = (
        f'<meta property="og:title" content="{html.escape(title)}">'
        f'<meta property="og:description" content="{html.escape(description)}">'
        f'<meta property="og:image" content="{html.escape(card_url)}">'
        f'<meta name="twitter:card" content="summary_large_image">'
        f'<meta name="twitter:image" content="{html.escape(card_url)}">'
        f"<script>window.__RESULT__={json.dumps(data)};</script>"
    )
    page = (STATIC_DIR / "index.html").read_text().replace("<!--BOOTSTRAP-->", meta)
    return HTMLResponse(page)


@app.get("/api/examples")
async def list_examples() -> list[dict]:
    out = []
    for path in sorted(EXAMPLES_DIR.glob("*.json")):
        spec = json.loads(path.read_text())
        result = audit(spec.get("system_prompt", ""), spec.get("tools"), spec.get("config"))
        out.append(
            {
                "slug": path.stem,
                "name": spec.get("name", path.stem),
                "note": spec.get("note", ""),
                "score": result.score,
                "grade": result.grade,
            }
        )
    return out


@app.get("/api/examples/{slug}")
async def get_example(slug: str) -> dict:
    spec = _load_example(slug)
    return {
        "slug": slug,
        "name": spec.get("name", slug),
        "system_prompt": spec.get("system_prompt", ""),
        "tools": json.dumps(spec.get("tools", []), indent=2),
        "config": spec.get("config", {}),
    }


def _rehydrate(data: dict) -> AuditResult:
    """Rebuild just enough of an AuditResult for the card renderer.

    The card only reads scalars, axis scores, and the top finding, so we avoid
    keeping the original prompt around purely to re-render an image.
    """
    from .findings import Axis, Finding, Severity
    from .scoring import AxisScore

    axes = [
        AxisScore(axis=Axis(a["axis"]), score=a["score"], weight=a["weight"])
        for a in data["axes"]
    ]
    findings: list[Finding] = []
    top = data.get("top_risk")
    if top:
        findings.append(
            Finding(
                id=top["id"],
                axis=Axis(top["axis"]),
                severity=Severity(top["severity"]),
                title=top["title"],
                detail=top["detail"],
                fix=top["fix"],
                tool=top.get("tool"),
            )
        )
    return AuditResult(
        score=data["score"],
        grade=data["grade"],
        verdict=data["verdict"],
        axes=axes,
        findings=findings,
        probes=data["probes"],
        tools=[],
        scan_id=data["scan_id"],
        tool_count=data.get("tool_count", 0),
        severity_counts=data.get("severity_counts", {}),
    )
