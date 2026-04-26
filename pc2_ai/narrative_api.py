"""
PC2 narrative micro-API — Phase 3 polish.

Exposes one endpoint:
    GET /actions/narrative?id=<incident_id>

PC4 calls this to get a 2-sentence CISO-ready narrative derived from the
structured actions array on an incident. Avoids a schema change on PC1.

Run:
    python -m pc2_ai.narrative_api
Listens on 0.0.0.0:8002 (PC2 NetBird IP: 100.67.158.179:8002)
"""

import os
import re
import logging

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)

PC1_BASE     = os.environ.get("PC1_BASE_URL", "http://100.67.61.250:8000")
OLLAMA_BASE  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = "mistral:latest"
HTTP_TIMEOUT = 15.0

app = FastAPI(title="PC2 Narrative API", version="1.0")

_PROMPT_TEMPLATE = """\
You are writing an executive briefing for a bank CISO.
Given these structured incident response actions, write EXACTLY 2 sentences.
Cite the deadlines and responsible teams verbatim. Do not invent new ones.
Be direct and professional. No bullet points. No headers.

Incident actions:
{actions_text}
"""


def _format_actions(actions: list) -> str:
    """Turn the actions array into a readable text block for the prompt."""
    lines = []
    for i, action in enumerate(actions, 1):
        if isinstance(action, dict):
            parts = []
            if action.get("action"):
                parts.append(action["action"])
            if action.get("owner") or action.get("responsible"):
                owner = action.get("owner") or action.get("responsible")
                parts.append(f"Owner: {owner}")
            if action.get("deadline"):
                parts.append(f"Deadline: {action['deadline']}")
            if action.get("priority"):
                parts.append(f"Priority: {action['priority']}")
            lines.append(f"{i}. {' | '.join(parts)}")
        else:
            lines.append(f"{i}. {action}")
    return "\n".join(lines)


def _call_ollama(prompt: str) -> str:
    resp = httpx.post(
        f"{OLLAMA_BASE}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0.2},
        },
        timeout=60,
    )
    resp.raise_for_status()
    text = resp.json()["message"]["content"].strip()
    return re.sub(r"\*\*(.+?)\*\*", r"\1", text)


@app.get("/actions/narrative")
def actions_narrative(id: str):
    """
    Fetch /incidents/{id}/actions from PC1, generate a 2-sentence CISO narrative.
    Returns: {"incident_id": "...", "narrative": "..."}
    """
    # Fetch actions from PC1
    try:
        r = httpx.get(f"{PC1_BASE}/incidents/{id}/actions", timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Incident {id} not found on PC1")
        r.raise_for_status()
        data = r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"PC1 unreachable: {e}")

    actions = data if isinstance(data, list) else data.get("actions", [])
    narrative_field = data.get("narrative") if isinstance(data, dict) else None

    # If PC1 already populated narrative, return it directly
    if narrative_field:
        return JSONResponse({"incident_id": id, "narrative": narrative_field, "source": "pc1"})

    if not actions:
        raise HTTPException(status_code=404, detail="No actions found for this incident")

    actions_text = _format_actions(actions)
    prompt = _PROMPT_TEMPLATE.format(actions_text=actions_text)

    try:
        narrative = _call_ollama(prompt)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM unavailable: {e}")

    log.info(f"Generated actions narrative for incident {id[:8]}")
    return JSONResponse({"incident_id": id, "narrative": narrative, "source": "llm"})


@app.get("/health")
def health():
    return {"status": "ok", "model": OLLAMA_MODEL, "pc1": PC1_BASE}


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8002)
