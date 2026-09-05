from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .schemas import ExperimentConfig
from .utils import project_root


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a mapping in {path}")
    return value


def load_config(path: str | Path) -> tuple[ExperimentConfig, Path, Path]:
    root = project_root()
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = root / config_path
    config_path = config_path.resolve()
    config = ExperimentConfig.model_validate(load_yaml(config_path))
    return config, config_path, root


def data_root(config: ExperimentConfig, root: Path) -> Path:
    value = Path(str(config.experiment.get("data_root", "data")))
    return value if value.is_absolute() else root / value

