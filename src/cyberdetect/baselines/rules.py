from __future__ import annotations

import json
from pathlib import Path

from ..config import data_root, load_config
from ..schemas import DefenderOutput, PredictionRecord, PublicEvent, Verdict
from ..utils import atomic_write_json, read_jsonl, sha256_file, utc_now


def run_baselines(config_path: str | Path) -> list[Path]:
    config, _, root = load_config(config_path)
    data = data_root(config, root)
    destinations: list[Path] = []
    for episode_dir in sorted((data / "episodes").glob("ep_*")):
        manifest = json.loads((episode_dir / "manifest.json").read_text(encoding="utf-8"))
        if manifest["experiment_id"] != config.experiment["id"]:
            continue
        packet_path = episode_dir / "defender_packet.txt"
        events = [PublicEvent.model_validate(value) for value in read_jsonl(episode_dir / "public_events.jsonl")]
        for baseline in ("always_benign", "always_attack", "frozen_rules"):
            destination = data / "predictions" / baseline / f"{episode_dir.name}.json"
            if destination.exists():
                destinations.append(destination)
                continue
            if baseline == "always_benign":
                probability, suspicious, rationale = 0.0, [], "Constant benign baseline."
            elif baseline == "always_attack":
                probability, suspicious, rationale = 1.0, [], "Constant attack baseline."
            else:
                suspicious = [event for event in events if event.status >= 400]
                probability = 0.8 if suspicious else 0.1
                rationale = "Frozen rule: one or more HTTP error responses." if suspicious else "Frozen rule did not fire."
            parsed = DefenderOutput(
                verdict=Verdict.ATTACK if probability >= 0.5 else Verdict.BENIGN,
                attack_probability=probability,
                first_suspicious_event_id=suspicious[0].event_id if suspicious else None,
                evidence_event_ids=[event.event_id for event in suspicious[:5]],
                suspected_tactic="enumeration" if suspicious else "none",
                rationale=rationale,
            )
            raw = json.dumps(parsed.model_dump(mode="json"), sort_keys=True)
            record = PredictionRecord(
                experiment_id=str(config.experiment["id"]),
                episode_id=episode_dir.name,
                defender_id=baseline,
                defender_model_revision="phase0",
                prompt_sha256="not_applicable",
                input_sha256=sha256_file(packet_path),
                raw_output=raw,
                parsed_output=parsed,
                parse_failure=False,
                latency_ms=0,
                input_tokens=0,
                output_tokens=0,
                created_at_utc=utc_now(),
            )
            atomic_write_json(destination, record)
            destinations.append(destination)
    return destinations

