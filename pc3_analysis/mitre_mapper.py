"""Rule-based MITRE ATT&CK mapper, banking-focused.

Maps an :class:`Incident` (already correlated by ``correlator``) to the set of
banking-relevant ATT&CK techniques it exhibits, using simple deterministic
rules over each ``EnrichedIOC`` in the incident.

The candidate technique set is intentionally small (the seven techniques from
``data/mitre/financial_techniques.json``, BATTLE_PLAN Appendix E):

    T1566  Phishing
    T1078  Valid Accounts
    T1190  Exploit Public-Facing Application
    T1539  Steal Web Session Cookie
    T1041  Exfiltration over C2
    T1071  Application Layer Protocol (C2 over HTTPS)
    T1486  Data Encrypted for Impact (Ransomware)

The output is the sorted, deduplicated list of technique IDs, suitable for
direct assignment to ``Incident.mitre_techniques``.

Phase 3 may swap this for an ML classifier; the public API
``tag_incident(Incident) -> list[str]`` will stay stable.
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

from shared.schemas import EnrichedIOC, Incident

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOOKUP_PATH = REPO_ROOT / "data" / "mitre" / "financial_techniques.json"

# Ransomware family names + generic markers in IOC values (hash filenames,
# URLs, domain strings) that indicate Data Encrypted for Impact.
_RANSOMWARE_PATTERNS = re.compile(
    r"\b("
    r"conti|lockbit|royal|ryuk|revil|sodinokibi|darkside|maze|cl0p|clop|"
    r"blackcat|alphv|blackbasta|hive|akira|qilin|playcrypt|"
    r"ransom|encrypt|locker|\.locked|\.crypt|readme[_-]decrypt"
    r")\b",
    re.IGNORECASE,
)

# URL substrings that signal session/cookie hijacking attempts.
_SESSION_THEFT_PATTERNS = re.compile(
    r"(session|cookie|login|sign[-_]?in|auth|token|sso)",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def _load_lookup() -> dict[str, dict]:
    """Lazy-load the banking technique lookup once per process."""
    if not LOOKUP_PATH.exists():
        raise FileNotFoundError(
            f"financial_techniques.json not found at {LOOKUP_PATH}. "
            "Run pc3_analysis/build_mitre_lookup.py first."
        )
    with LOOKUP_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _ioc_techniques(ioc: EnrichedIOC) -> set[str]:
    """Return the set of technique IDs this single IOC suggests."""
    techniques: set[str] = set()

    threat = (ioc.threat_type or "").lower()
    value_lower = ioc.value.lower()

    if threat == "phishing":
        techniques.add("T1566")
    elif threat == "c2":
        techniques.add("T1071")
    elif threat == "exfiltration":
        techniques.add("T1041")
    elif threat == "lateral_movement":
        techniques.add("T1078")
    elif threat == "malware":
        if _RANSOMWARE_PATTERNS.search(value_lower):
            techniques.add("T1486")
        else:
            # Generic malware in banking is usually deployed after valid-account
            # abuse (Emotet/TrickBot/Dridex pattern). Default to T1078.
            techniques.add("T1078")

    # CVE reference -> public-facing app exploit (online banking, web portals).
    if ioc.type == "cve" or ioc.related_cves:
        techniques.add("T1190")

    # URL with session/auth keywords -> banking session hijacking.
    if ioc.type == "url" and _SESSION_THEFT_PATTERNS.search(value_lower):
        techniques.add("T1539")

    # APT attribution boost: financial APTs are textbook valid-account abusers
    # plus phishers - adding T1566 + T1078 is defensible regardless of IOC type.
    if (ioc.apt_attribution or "").lower() in {
        "fin7",
        "carbanak",
        "lazarus",
        "silence",
        "cobalt-group",
        "cobalt_group",
    }:
        techniques.add("T1566")
        techniques.add("T1078")

    return techniques


def tag_incident(incident: Incident) -> list[str]:
    """Return the sorted, deduplicated list of MITRE technique IDs for an Incident.

    Pure function: does not mutate ``incident``.

    Args:
        incident: an Incident produced by ``correlator``. Only ``incident.iocs``
            is consulted.

    Returns:
        Sorted list of technique IDs (e.g. ['T1041', 'T1566']). Always a subset
        of the seven banking-relevant techniques in ``financial_techniques.json``.
    """
    lookup = _load_lookup()
    valid_ids = set(lookup.keys())

    techniques: set[str] = set()
    for ioc in incident.iocs:
        techniques.update(_ioc_techniques(ioc))

    # Defensive: only emit techniques that exist in our committed lookup.
    techniques &= valid_ids

    result = sorted(techniques)
    logger.debug(
        "Incident %s tagged with %d MITRE technique(s): %s",
        incident.id,
        len(result),
        result,
    )
    return result


def apply(incident: Incident) -> Incident:
    """Return a copy of ``incident`` with ``mitre_techniques`` filled in.

    Convenience for the pipeline. Use ``tag_incident`` directly if you already
    hold the technique list (e.g. to feed it into the compliance mapper before
    constructing the final Incident).
    """
    techniques = tag_incident(incident)
    return incident.model_copy(update={"mitre_techniques": techniques})
