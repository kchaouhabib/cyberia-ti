"""
IOC deduplicator — PC2, Stage 02, Phase 2.

Uses sentence-transformers embeddings + cosine similarity to detect near-duplicate IOCs.
Two IOCs are considered duplicates if:
  - Same type AND cosine similarity of their values > SIMILARITY_THRESHOLD (0.85)
When a duplicate is found, we keep the one with the higher confidence score.

Model loaded lazily on first call (sentence-transformers/all-MiniLM-L6-v2).
"""

from typing import List, Optional, Tuple

import numpy as np

from shared.schemas import IOC

SIMILARITY_THRESHOLD = 0.85
_EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

_embed_model = None


def _get_model():
    """Lazily load the sentence-transformers model."""
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer(_EMBED_MODEL_NAME)
    return _embed_model


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two vectors."""
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def deduplicate(iocs: List[IOC]) -> Tuple[List[IOC], int]:
    """
    Remove near-duplicate IOCs from a list.

    Groups by IOC type first (an IP can never be a duplicate of a domain),
    then uses embedding similarity within each type group.
    Keeps the IOC with the highest confidence when a duplicate is found.

    Returns (deduplicated_list, n_duplicates_removed).
    """
    if len(iocs) <= 1:
        return iocs, 0

    model = _get_model()

    # Group by type
    by_type: dict[str, List[IOC]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc.type, []).append(ioc)

    kept: List[IOC] = []
    n_removed = 0

    for ioc_type, group in by_type.items():
        if len(group) == 1:
            kept.append(group[0])
            continue

        # Embed all values in this type group
        values = [ioc.value for ioc in group]
        embeddings = model.encode(values, show_progress_bar=False)

        # Greedy deduplication: mark duplicates
        is_duplicate = [False] * len(group)
        for i in range(len(group)):
            if is_duplicate[i]:
                continue
            for j in range(i + 1, len(group)):
                if is_duplicate[j]:
                    continue
                sim = _cosine_similarity(embeddings[i], embeddings[j])
                if sim >= SIMILARITY_THRESHOLD:
                    # Keep whichever has higher confidence
                    if group[j].confidence > group[i].confidence:
                        is_duplicate[i] = True
                        break
                    else:
                        is_duplicate[j] = True

        for i, ioc in enumerate(group):
            if not is_duplicate[i]:
                kept.append(ioc)
            else:
                n_removed += 1

    return kept, n_removed


def is_duplicate_of_existing(new_ioc: IOC, existing_iocs: List[IOC]) -> bool:
    """
    Check if a single new IOC is a near-duplicate of any IOC in an existing list.
    Used for incremental deduplication during the pipeline loop.
    """
    if not existing_iocs:
        return False

    same_type = [ioc for ioc in existing_iocs if ioc.type == new_ioc.type]
    if not same_type:
        return False

    model = _get_model()
    new_emb = model.encode([new_ioc.value], show_progress_bar=False)[0]
    existing_embs = model.encode([ioc.value for ioc in same_type], show_progress_bar=False)

    for emb in existing_embs:
        if _cosine_similarity(new_emb, emb) >= SIMILARITY_THRESHOLD:
            return True
    return False
