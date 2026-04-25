"""Build a small JSON lookup of banking-relevant MITRE ATT&CK techniques.

Reads the full Enterprise ATT&CK STIX bundle (data/mitre/enterprise-attack.json)
and writes data/mitre/financial_techniques.json containing only the seven
techniques most relevant to bank threat-intelligence work, per BATTLE_PLAN.md
Appendix E.

Run once during Phase 1 setup:

    python pc3_analysis/build_mitre_lookup.py

The output file is small (a few KB) and *is* committed to the repo so the rest
of the team can run mitre_mapper without downloading the full STIX bundle.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
STIX_PATH = REPO_ROOT / "data" / "mitre" / "enterprise-attack.json"
OUTPUT_PATH = REPO_ROOT / "data" / "mitre" / "financial_techniques.json"

# Techniques selected for banking focus (BATTLE_PLAN.md Appendix E).
# Maps technique ID -> one-line note explaining why this matters for banks.
BANKING_TECHNIQUES: dict[str, str] = {
    "T1566": "#1 entry vector for bank breaches (BCT/SWIFT impersonation phishing)",
    "T1078": "Compromised employee credentials -> SWIFT terminals, payment systems",
    "T1190": "Online banking portals, web app vulnerabilities",
    "T1539": "Banking session hijacking via stolen cookies",
    "T1041": "Customer-data theft, exfiltration over C2",
    "T1071": "C2 over HTTPS to evade SOC detection",
    "T1486": "Ransomware (Conti, LockBit, Royal hit banks regularly)",
}


def _technique_id(stix_obj: dict) -> str | None:
    """Return the ATT&CK technique ID (e.g. 'T1566') from a STIX attack-pattern."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _technique_url(stix_obj: dict) -> str | None:
    """Return the public ATT&CK URL for the technique."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def build_lookup() -> dict[str, dict]:
    """Read STIX bundle and emit the banking-techniques lookup dict."""
    if not STIX_PATH.exists():
        raise FileNotFoundError(
            f"STIX bundle not found at {STIX_PATH}. "
            "Download it first via the Phase 1 STIX download step."
        )

    logger.info("Loading STIX bundle from %s", STIX_PATH)
    with STIX_PATH.open(encoding="utf-8") as fh:
        bundle = json.load(fh)

    lookup: dict[str, dict] = {}
    seen_ids: set[str] = set()

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _technique_id(obj)
        if tid not in BANKING_TECHNIQUES or tid in seen_ids:
            continue

        seen_ids.add(tid)
        lookup[tid] = {
            "id": tid,
            "name": obj.get("name", ""),
            "description": obj.get("description", "").strip(),
            "kill_chain_phases": [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
            "platforms": obj.get("x_mitre_platforms", []),
            "url": _technique_url(obj),
            "banking_relevance": BANKING_TECHNIQUES[tid],
        }

    missing = set(BANKING_TECHNIQUES) - seen_ids
    if missing:
        logger.warning(
            "These banking techniques were not found in the STIX bundle: %s",
            sorted(missing),
        )

    return lookup


def main() -> int:
    """CLI entrypoint: build the lookup and write it to disk."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    lookup = build_lookup()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as fh:
        json.dump(lookup, fh, indent=2, ensure_ascii=False)

    logger.info(
        "Wrote %d banking technique(s) to %s",
        len(lookup),
        OUTPUT_PATH.relative_to(REPO_ROOT),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
