from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..config import data_root, load_config


@dataclass(frozen=True)
class LeakageFinding:
    episode_id: str
    token_type: str
    token: str


def audit_packets(config_path: str | Path) -> list[LeakageFinding]:
    config, _, root = load_config(config_path)
    data = data_root(config, root)
    findings: list[LeakageFinding] = []
    forbidden_literals = [
        "attack_standard",
        "attack_stealth",
        "mock_actor",
        "actor_model_id",
        "ground_truth",
        "policy_violation",
        "canary_exposed",
    ]
    scenarios: dict[tuple[str, str], dict[str, object]] = {}
    scenario_directory = (
        data
        / "raw_restricted"
        / "scenarios"
        / str(config.experiment["id"])
    )
    for path in scenario_directory.glob("*.json"):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        scenarios[(scenario["scenario_pair_id"], scenario["condition"])] = scenario

    for episode_dir in sorted((data / "episodes").glob("ep_*")):
        manifest_path = episode_dir / "manifest.json"
        packet_path = episode_dir / "defender_packet.txt"
        if not manifest_path.exists() or not packet_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["experiment_id"] != config.experiment["id"]:
            continue
        packet = packet_path.read_text(encoding="utf-8")
        lowered = packet.lower()
        for literal in forbidden_literals:
            if literal.lower() in lowered:
                findings.append(LeakageFinding(episode_dir.name, "forbidden_literal", literal))
        scenario = scenarios.get((manifest["scenario_pair_id"], manifest["actor_condition"]))
        if scenario:
            sensitive = {
                "username": str(scenario["actor_username"]),
                "password": str(scenario["actor_password"]),
                "canary": str(scenario["canary"]),
                "owned_resource_id": str(scenario["owned_resource_id"]),
                "protected_resource_id": str(scenario["protected_resource_id"]),
            }
            for token_type, token in sensitive.items():
                if token and token in packet:
                    findings.append(LeakageFinding(episode_dir.name, token_type, token))
    return findings
