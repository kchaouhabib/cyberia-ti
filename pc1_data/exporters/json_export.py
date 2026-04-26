"""JSON exporter — wraps a list of Incident models into a download-ready blob.

Used by GET /export/json. The output is a single JSON object:

    {
      "exported_at": "<ISO-8601 UTC>",
      "count": <int>,
      "incidents": [<Incident>, ...]
    }

The `incidents` array is the full Pydantic dump (so PC4 or any external
analyst can re-hydrate the locked schema with `Incident.model_validate`).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from shared.schemas import Incident


def render(incidents: List[Incident]) -> bytes:
    """Serialize incidents to a JSON byte-string ready to stream as a download."""
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(incidents),
        "incidents": [json.loads(inc.model_dump_json()) for inc in incidents],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
