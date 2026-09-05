"""Model registry and credential resolution for real (non-mock) runs.

Model identities live in ``configs/models.yaml`` (copied from
``configs/models.example.yaml``). Endpoint URLs and API keys are NEVER stored in the
registry: each real model names the environment variables that hold them, and the
credentials are read from the host environment at run time only.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .config import load_yaml
from .utils import project_root


class ModelSpec(BaseModel):
    # Extra keys (serving metadata such as quantization, tensor_parallel, chat_template)
    # are permitted and recorded, but the run only depends on the fields below.
    model_config = ConfigDict(extra="allow")

    id: str
    provider: str  # "mock" | "openai_compatible"
    model: str
    revision: str
    base_url_env: str | None = None
    api_key_env: str | None = None
    total_parameters: str | None = None
    active_parameters: str | None = None
    max_context_tokens: int | None = None


class ResolvedEndpoint(BaseModel):
    base_url: str
    api_key: str


def models_path(root: Path | None = None) -> Path:
    return (root or project_root()) / "configs" / "models.yaml"


def load_models(root: Path | None = None) -> dict[str, ModelSpec]:
    path = models_path(root)
    if not path.exists():
        raise FileNotFoundError(
            "configs/models.yaml not found. Copy configs/models.example.yaml to "
            "configs/models.yaml and fill in the real model IDs and revisions. "
            "Never put endpoint URLs or API keys in that file; use the *_env references."
        )
    raw = load_yaml(path)
    entries = raw.get("models")
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"{path} must contain a non-empty 'models' mapping")
    specs: dict[str, ModelSpec] = {}
    for key, value in entries.items():
        if not isinstance(value, dict):
            raise ValueError(f"model '{key}' must be a mapping")
        specs[key] = ModelSpec(id=key, **value)
    return specs


def get_model(model_id: str, root: Path | None = None) -> ModelSpec:
    specs = load_models(root)
    if model_id not in specs:
        raise KeyError(f"model '{model_id}' is not defined in configs/models.yaml")
    return specs[model_id]


def resolve_endpoint(spec: ModelSpec) -> ResolvedEndpoint:
    """Read the endpoint URL and API key for an openai_compatible model from the env.

    Raises with an actionable message when a variable is unset, and never echoes the
    secret value.
    """
    if spec.provider != "openai_compatible":
        raise ValueError(f"model '{spec.id}' has provider '{spec.provider}', not openai_compatible")
    if not spec.base_url_env or not spec.api_key_env:
        raise ValueError(f"model '{spec.id}' must declare base_url_env and api_key_env")
    base_url = os.environ.get(spec.base_url_env)
    api_key = os.environ.get(spec.api_key_env)
    missing = [
        name
        for name, value in ((spec.base_url_env, base_url), (spec.api_key_env, api_key))
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"model '{spec.id}' needs these environment variables set: {', '.join(missing)}. "
            "Export them in the host shell; do not write them to files."
        )
    assert base_url and api_key
    return ResolvedEndpoint(base_url=base_url, api_key=api_key)
