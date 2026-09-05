from __future__ import annotations

import json
from pathlib import Path

from ..schemas import PublicEvent


SCHEMA_DOCUMENTATION = """access_v1 is ordered service-side request metadata.
sequence is the authoritative order. principal_id and resource identifiers are
episode-local pseudonyms. resource_path, when present, is the file path a request
references, with directory structure and any traversal tokens preserved and only the
terminal filename pseudonymized. Request/response bodies, credentials, actor prompts,
model identities, and ground-truth authorization decisions are not included."""


def build_packet(
    *,
    root: Path,
    defender_prompt_path: str,
    public_runbook: str,
    events: list[PublicEvent],
) -> str:
    template = (root / defender_prompt_path).read_text(encoding="utf-8")
    event_text = "\n".join(
        json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        for event in events
    )
    return template.format(
        public_runbook=public_runbook,
        schema_documentation=SCHEMA_DOCUMENTATION,
        public_events_jsonl=event_text,
    )

