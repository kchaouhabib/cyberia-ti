# PC2 — AI Pipeline Status

## What PC2 does

PC2 is the AI processing engine. It polls PC1 for raw threat records, runs them through a full AI chain, and pushes enriched IOCs + CISO summaries back to PC1.

---

## Completed Work

### Phase 1 — Regex IOC Extraction
- `pc2_ai/ioc_extractor.py`
- Extracts: IPs, domains, URLs, MD5/SHA256 hashes, CVEs
- Filters private/loopback IPs automatically
- Confidence: SHA256=0.90, CVE=0.95, URL=0.80, IP=0.75, domain=0.65, MD5=0.85

### Phase 2 — Full AI Chain
- `pc2_ai/classifier.py` — LogisticRegression, 5 classes: phishing / malware / c2 / exfiltration / lateral_movement
- `pc2_ai/deduplicator.py` — sentence-transformers (all-MiniLM-L6-v2), cosine similarity > 0.85 = duplicate
- `pc2_ai/confidence_scorer.py` — per-source false positive rates (malwarebazaar=0.03, otx=0.20, etc.)
- `pc2_ai/ner.py` — spaCy EntityRuler, detects: Lazarus, FIN7, Carbanak, Cobalt Group, Silence
- `pc2_ai/enrichment_caller.py` — calls PC1 /enrich → VT reputation + Shodan geolocation

### Phase 3 — LLM Layer (Ollama, Mistral 7B local)
- `pc2_ai/llm_extractor.py` — LLM extraction catches financial keywords regex misses (SWIFT codes, BIC, account numbers)
- `pc2_ai/llm_summarizer.py` — generates one CISO-ready paragraph per incident for the board
- `compare_models.py` — benchmark: Mistral vs llama-soc-cybersec (Mistral won)

### Pipeline
- `pc2_ai/pipeline.py` — full chain, polls PC1 every 10s
- Chain: regex extract → LLM extract → merge → dedup → classify → confidence score → NER → enrich → push to PC1

---

## Data Flow

```
PC1 GET /raw
  → regex extract (ioc_extractor.py)
  → LLM extract (llm_extractor.py, Mistral 7B)
  → merge + deduplicate
  → classify threat type
  → score confidence
  → NER APT attribution
  → call PC1 /enrich (VT + Shodan)
  → PC1 POST /iocs/enriched

PC2 also generates CISO summaries → PC1 POST /summaries  ← PENDING PC1 ENDPOINT
```

---

## Endpoints PC2 Calls on PC1

| Endpoint | Method | Status |
|---|---|---|
| /raw | GET | Working |
| /iocs/enriched | POST | Working |
| /enrich | POST | Working |
| /summaries | POST | WAITING FOR PC1 |

---

## What PC2 Needs from Other PCs

### PC1 — 2 new endpoints needed

**POST /summaries**
Receives this JSON from PC2:
```json
{
  "record_id": "string",
  "source": "string",
  "threat_type": "string",
  "apt_attribution": "string",
  "risk_score": 0,
  "severity": "string",
  "ioc_count": 0,
  "compliance_breaches": ["string"],
  "ciso_summary": "string"
}
```

**GET /summaries**
Returns list of all stored summaries so PC4 can display them.

### PC3 — 1 fix needed

PC3 is showing 0 CVEs. PC2 extracts CVEs with confidence=0.95 and pushes them to /iocs/enriched with `type="cve"`. PC3 must NOT filter out CVE-type IOCs in their correlator. Check: `GET /iocs/enriched` and filter `type == "cve"` to confirm they are present in PC1's DB.

### PC4 — nothing needed

PC4 reads from PC1. Once PC1 adds GET /summaries, PC4 can display CISO summaries directly. No action required from PC4 toward PC2.

---

## How to Run PC2

```bash
cd cyberia-ti
source venv/Scripts/activate        # Windows
python -m pc2_ai.pipeline           # starts polling loop
```

Override PC1 address:
```bash
PC1_BASE_URL=http://100.67.61.250:8000 python -m pc2_ai.pipeline
```

## Ollama (required for Phase 3)

Ollama must be running locally with Mistral:
```bash
ollama serve
ollama pull mistral:latest
```

If Ollama is down, the pipeline falls back to regex-only extraction and template summaries automatically.
