"""
Financial APT entity recognizer — PC2, Stage 02, Phase 2.

Uses spaCy EntityRuler (rule-based, no training needed) to detect known
financial threat actor names and banking-sector malware families in raw text.

Returns detected entity names + maps them to apt_attribution values
used by the EnrichedIOC schema field.
"""

from typing import List, Optional
import spacy
from spacy.language import Language

# Known financial APTs and their canonical schema values
_APT_PATTERNS = [
    # Carbanak / FIN7 ecosystem
    {"label": "THREAT_ACTOR", "pattern": "Carbanak",      "id": "carbanak"},
    {"label": "THREAT_ACTOR", "pattern": "CARBANAK",      "id": "carbanak"},
    {"label": "THREAT_ACTOR", "pattern": "FIN7",          "id": "fin7"},
    {"label": "THREAT_ACTOR", "pattern": "Fin7",          "id": "fin7"},
    {"label": "THREAT_ACTOR", "pattern": "Cobalt Group",  "id": "cobalt-group"},
    {"label": "THREAT_ACTOR", "pattern": "COBALT",        "id": "cobalt-group"},
    {"label": "THREAT_ACTOR", "pattern": "Cobalt Strike", "id": "cobalt-group"},
    # Lazarus Group (North Korea, bank heists)
    {"label": "THREAT_ACTOR", "pattern": "Lazarus",       "id": "lazarus"},
    {"label": "THREAT_ACTOR", "pattern": "Lazarus Group", "id": "lazarus"},
    {"label": "THREAT_ACTOR", "pattern": "LAZARUS",       "id": "lazarus"},
    {"label": "THREAT_ACTOR", "pattern": "Hidden Cobra",  "id": "lazarus"},
    # Silence Group
    {"label": "THREAT_ACTOR", "pattern": "Silence",       "id": "silence"},
    {"label": "THREAT_ACTOR", "pattern": "Silence Group", "id": "silence"},
    # Banking malware families
    {"label": "MALWARE",      "pattern": "Emotet",        "id": "emotet"},
    {"label": "MALWARE",      "pattern": "EMOTET",        "id": "emotet"},
    {"label": "MALWARE",      "pattern": "TrickBot",      "id": "trickbot"},
    {"label": "MALWARE",      "pattern": "Trickbot",      "id": "trickbot"},
    {"label": "MALWARE",      "pattern": "Dridex",        "id": "dridex"},
    {"label": "MALWARE",      "pattern": "DRIDEX",        "id": "dridex"},
    {"label": "MALWARE",      "pattern": "Bateleur",      "id": "fin7"},
    {"label": "MALWARE",      "pattern": "GRIFFON",       "id": "fin7"},
    {"label": "MALWARE",      "pattern": "Anunak",        "id": "carbanak"},
]

# Map entity ID → schema apt_attribution value
_ID_TO_ATTRIBUTION: dict[str, str] = {
    "carbanak":    "carbanak",
    "fin7":        "fin7",
    "cobalt-group":"cobalt-group",
    "lazarus":     "lazarus",
    "silence":     "silence",
    "emotet":      "carbanak",   # Emotet often used as loader by Carbanak ecosystem
    "trickbot":    "fin7",       # TrickBot tied to FIN7/Wizard Spider
    "dridex":      "fin7",       # Dridex tied to Evil Corp / FIN7-adjacent
}

_nlp: Optional[Language] = None


def _get_nlp() -> Language:
    """Lazily load spaCy model and add EntityRuler on first call."""
    global _nlp
    if _nlp is not None:
        return _nlp

    try:
        nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
    except OSError:
        # Fallback to blank model if en_core_web_sm not installed
        nlp = spacy.blank("en")

    ruler = nlp.add_pipe("entity_ruler", before="ner" if "ner" in nlp.pipe_names else None)
    ruler.add_patterns(_APT_PATTERNS)

    _nlp = nlp
    return _nlp


def extract_apt_entities(text: str) -> List[dict]:
    """
    Extract financial APT / malware entities from raw text.

    Returns a list of dicts:
      {"text": str, "label": str, "attribution": str}
    """
    nlp = _get_nlp()
    doc = nlp(text)
    results = []
    seen = set()
    for ent in doc.ents:
        if ent.label_ in ("THREAT_ACTOR", "MALWARE"):
            attr = _ID_TO_ATTRIBUTION.get(ent.ent_id_, ent.text.lower())
            key  = (ent.text.lower(), attr)
            if key not in seen:
                seen.add(key)
                results.append({
                    "text":        ent.text,
                    "label":       ent.label_,
                    "attribution": attr,
                })
    return results


def get_apt_attribution(text: str) -> Optional[str]:
    """
    Return the single most prominent APT attribution found in text, or None.
    Used to set EnrichedIOC.apt_attribution.
    Priority order: lazarus > carbanak > fin7 > cobalt-group > silence.
    """
    entities = extract_apt_entities(text)
    if not entities:
        return None

    priority = ["lazarus", "carbanak", "fin7", "cobalt-group", "silence"]
    found = {e["attribution"] for e in entities}
    for p in priority:
        if p in found:
            return p
    return entities[0]["attribution"]
