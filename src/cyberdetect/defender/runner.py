from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from ..config import data_root, load_config
from ..schemas import DefenderOutput, PredictionRecord, PublicEvent, Verdict
from ..utils import atomic_write_json, read_jsonl, sha256_file, sha256_text, utc_now
from .parser import parse_output


def _authorized_mapping(packet: str) -> tuple[str | None, str | None]:
    match = re.search(r"AUTHORIZED_MAPPING\s+(usr_[a-f0-9]+)\s+->\s+(res_[a-f0-9]+)", packet)
    return match.groups() if match else (None, None)


def _mock_completion(defender_id: str, packet: str, events: list[PublicEvent]) -> str:
    error_events = [event for event in events if event.status >= 400]
    authorized_user, authorized_resource = _authorized_mapping(packet)
    unauthorized = []
    for event in events:
        match = re.match(r"/api/resources/(res_[a-f0-9]+)$", event.path)
        if not match or event.status >= 400:
            continue
        if authorized_user and authorized_resource:
            if event.principal_id == authorized_user and match.group(1) != authorized_resource:
                unauthorized.append(event)

    if defender_id == "small_mock":
        suspicious = error_events
        probability = 0.82 if suspicious else 0.12
        tactic = "enumeration" if suspicious else "none"
        rationale = "A failed resource lookup suggests probing." if suspicious else "No coarse error-rate indicator is present."
    elif defender_id == "medium_mock":
        suspicious = unauthorized or error_events
        probability = 0.86 if unauthorized else (0.68 if error_events else 0.10)
        tactic = "authorization_abuse" if unauthorized else ("enumeration" if error_events else "none")
        rationale = "A successful resource read falls outside the declared ownership mapping." if unauthorized else "No ownership-policy violation is visible."
    else:
        suspicious = unauthorized
        probability = 0.97 if unauthorized else 0.03
        tactic = "authorization_abuse" if unauthorized else "none"
        rationale = "The authenticated principal successfully retrieved a resource not assigned to it." if unauthorized else "Observed resource access matches the supplied policy mapping."

    output = DefenderOutput(
        verdict=Verdict.ATTACK if probability >= 0.5 else Verdict.BENIGN,
        attack_probability=probability,
        first_suspicious_event_id=suspicious[0].event_id if suspicious else None,
        evidence_event_ids=[event.event_id for event in suspicious[:5]],
        suspected_tactic=tactic,
        rationale=rationale,
    )
    return json.dumps(output.model_dump(mode="json"), sort_keys=True)


def run_mock_defenders(config_path: str | Path) -> list[Path]:
    config, _, root = load_config(config_path)
    data = data_root(config, root)
    created: list[Path] = []
    for episode_dir in sorted((data / "episodes").glob("ep_*")):
        manifest = json.loads((episode_dir / "manifest.json").read_text(encoding="utf-8"))
        if manifest["experiment_id"] != config.experiment["id"]:
            continue
        packet_path = episode_dir / "defender_packet.txt"
        packet = packet_path.read_text(encoding="utf-8")
        events = [PublicEvent.model_validate(value) for value in read_jsonl(episode_dir / "public_events.jsonl")]
        valid_ids = [event.event_id for event in events]
        for defender_id in config.defender_models:
            destination = data / "predictions" / defender_id / f"{episode_dir.name}.json"
            if destination.exists():
                previous = json.loads(destination.read_text(encoding="utf-8"))
                if previous.get("input_sha256") == sha256_file(packet_path):
                    created.append(destination)
                    continue
                raise RuntimeError(f"prediction input changed for immutable artifact: {destination}")
            started = time.monotonic()
            raw = _mock_completion(defender_id, packet, events)
            parsed, failed = parse_output(raw, valid_ids)
            record = PredictionRecord(
                experiment_id=str(config.experiment["id"]),
                episode_id=episode_dir.name,
                defender_id=defender_id,
                defender_model_revision="phase0",
                prompt_sha256=sha256_file(root / config.prompts["defender"]),
                input_sha256=sha256_file(packet_path),
                raw_output=raw,
                parsed_output=parsed,
                parse_failure=failed,
                latency_ms=max(0, round((time.monotonic() - started) * 1000)),
                input_tokens=max(1, len(packet) // 4),
                output_tokens=max(1, len(raw) // 4),
                created_at_utc=utc_now(),
            )
            atomic_write_json(destination, record)
            created.append(destination)
    return created

