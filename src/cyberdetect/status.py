from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import data_root, load_config


def experiment_status(config_path: str | Path) -> dict[str, Any]:
    config, _, root = load_config(config_path)
    data = data_root(config, root)
    episodes = []
    for path in sorted((data / "episodes").glob("ep_*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["experiment_id"] == config.experiment["id"]:
            episodes.append(manifest)
    prediction_counts: dict[str, int] = {}
    for directory in sorted((data / "predictions").glob("*")):
        if directory.is_dir():
            prediction_counts[directory.name] = sum(
                json.loads(path.read_text(encoding="utf-8")).get("experiment_id") == config.experiment["id"]
                for path in directory.glob("*.json")
            )
    return {
        "experiment_id": config.experiment["id"],
        "episodes": len(episodes),
        "conditions": sorted({manifest["actor_condition"] for manifest in episodes}),
        "predictions": prediction_counts,
        "metrics_ready": (data / "reports" / "metrics.json").exists(),
    }

