"""
LLM-based IOC extractor — PC2, Stage 02, Phase 3.

Uses Ollama (Llama 3.2 3B, local) to extract IOCs from banking-sector threat text.
Prompts for strict JSON output including a financial_keywords field that regex misses.

DEMO HIGHLIGHT — side_by_side() shows the jury:
  regex extracted N IOCs
  LLM  extracted N+M IOCs  ← M extra ones regex missed
"""

import json
import logging
import re
from typing import Optional

from shared.schemas import IOC
from pc2_ai.ioc_extractor import extract_iocs as regex_extract_iocs
from datetime import datetime, timezone

log = logging.getLogger(__name__)

OLLAMA_MODEL   = "mistral:latest"
OLLAMA_BASE    = "http://localhost:11434"
OLLAMA_TIMEOUT = 60  # seconds — Mistral 7B is fast locally

_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in banking-sector threats. "
    "Extract all indicators of compromise (IOCs) from the provided text. "
    "Return ONLY a valid JSON object, no explanation, no markdown."
)

_USER_PROMPT_TEMPLATE = """\
Extract all IOCs from this banking-sector threat report.
Return ONLY this JSON structure (no other text):
{{
  "ips": ["list of IP addresses"],
  "domains": ["list of domains"],
  "urls": ["list of full URLs"],
  "hashes": ["list of MD5 or SHA256 hashes"],
  "cves": ["list of CVE identifiers"],
  "financial_keywords": ["SWIFT codes, BIC codes, account numbers, payment terms, banking-specific terms or identifiers found"]
}}

Text:
{text}
"""

# ── Ollama client ────────────────────────────────────────────────────────────

def _call_ollama(text: str) -> Optional[dict]:
    """
    Call local Ollama API and return parsed JSON dict, or None on failure.
    Prompts for strict JSON — parses defensively.
    """
    try:
        import httpx
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": _USER_PROMPT_TEMPLATE.format(text=text[:3000])},
            ],
            "stream": False,
            "options": {"temperature": 0.0},  # deterministic output
        }
        resp = httpx.post(
            f"{OLLAMA_BASE}/api/chat",
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()

        # Strip markdown code fences if model wraps output
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        return json.loads(raw)
    except httpx.ConnectError:
        log.warning("Ollama not running — LLM extraction skipped (regex fallback active)")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        log.warning(f"LLM returned invalid JSON: {e}")
        return None
    except Exception as e:
        log.warning(f"LLM extraction failed: {e}")
        return None


def _llm_result_to_iocs(llm_data: dict, source: str) -> list[IOC]:
    """Convert the LLM's JSON output into IOC objects."""
    now = datetime.now(timezone.utc)
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def _add(value: str, ioc_type: str, confidence: float) -> None:
        v = value.strip()
        if not v:
            return
        key = (v.lower(), ioc_type)
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(
            value=v,
            type=ioc_type,
            confidence=confidence,
            source=source,
            first_seen=now,
        ))

    for ip in llm_data.get("ips") or []:
        _add(ip, "ip", 0.78)
    for domain in llm_data.get("domains") or []:
        _add(domain, "domain", 0.72)
    for url in llm_data.get("urls") or []:
        _add(url, "url", 0.82)
    for h in llm_data.get("hashes") or []:
        ioc_type = "hash_sha256" if len(h.replace(" ", "")) == 64 else "hash_md5"
        _add(h, ioc_type, 0.88)
    for cve in llm_data.get("cves") or []:
        _add(cve.upper(), "cve", 0.96)
    # financial_keywords stored as domain type for pipeline compatibility
    for kw in llm_data.get("financial_keywords") or []:
        _add(kw, "domain", 0.60)

    return iocs


# ── Public API ───────────────────────────────────────────────────────────────

def extract_iocs_llm(text: str, source: str) -> list[IOC]:
    """
    Extract IOCs from text using the LLM.
    Falls back to empty list if Ollama is unavailable.
    """
    llm_data = _call_ollama(text)
    if llm_data is None:
        return []
    return _llm_result_to_iocs(llm_data, source)


def side_by_side(text: str, source: str = "demo") -> dict:
    """
    Run both regex and LLM extraction on the same text.
    Returns a comparison dict — used for the demo's side-by-side slide.

    Returns:
    {
      "regex_iocs":  [...],   # what regex found
      "llm_iocs":    [...],   # what LLM found
      "only_in_llm": [...],   # the M extra ones regex missed  ← demo highlight
      "only_in_regex": [...], # false positives regex added
      "llm_available": bool
    }
    """
    regex_iocs = regex_extract_iocs(text, source)
    llm_data   = _call_ollama(text)

    if llm_data is None:
        return {
            "regex_iocs":    regex_iocs,
            "llm_iocs":      [],
            "only_in_llm":   [],
            "only_in_regex": regex_iocs,
            "llm_available": False,
        }

    llm_iocs = _llm_result_to_iocs(llm_data, source)

    regex_values = {(i.value.lower(), i.type) for i in regex_iocs}
    llm_values   = {(i.value.lower(), i.type) for i in llm_iocs}

    only_in_llm   = [i for i in llm_iocs   if (i.value.lower(), i.type) not in regex_values]
    only_in_regex = [i for i in regex_iocs  if (i.value.lower(), i.type) not in llm_values]

    return {
        "regex_iocs":    regex_iocs,
        "llm_iocs":      llm_iocs,
        "only_in_llm":   only_in_llm,    # M extra — the demo highlight
        "only_in_regex": only_in_regex,
        "llm_available": True,
    }


if __name__ == "__main__":
    sample = """
    FIN7 campaign targeting Banque Atlas treasury systems via spear-phishing.
    Malicious IPs: 185.220.101.45, 91.108.4.0
    C2 domain: c2.lazarus-update.net
    SHA256: a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8
    Exploits CVE-2021-44228. Targets SWIFT MT103 payment messages.
    SWIFT BIC: ATLASDJTXXX. Unusual transactions on account FR76-ATLAS-001.
    """
    result = side_by_side(sample)
    print(f"Regex found  : {len(result['regex_iocs'])} IOCs")
    print(f"LLM found    : {len(result['llm_iocs'])} IOCs")
    print(f"LLM extras   : {len(result['only_in_llm'])} (regex missed these)")
    print()
    if result["only_in_llm"]:
        print("IOCs only the LLM caught:")
        for ioc in result["only_in_llm"]:
            print(f"  [{ioc.type}] {ioc.value}")
