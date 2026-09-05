from __future__ import annotations

import platform
import subprocess
from pathlib import Path

from . import __version__
from .config import load_config, load_yaml
from .schemas import FreezeLock
from .utils import atomic_write_json, canonical_json, sha256_file, sha256_text, utc_now


def _git_revision(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def create_lock(config_path: str | Path, output_path: str | Path = "experiment.lock.json") -> Path:
    config, resolved_config_path, root = load_config(config_path)
    prompt_hashes: dict[str, str] = {}
    for name, relative in config.prompts.items():
        prompt_path = (root / relative).resolve()
        prompt_hashes[name] = sha256_file(prompt_path)

    target_revisions: dict[str, str] = {}
    for target in config.targets:
        target_path = root / "configs" / "targets" / f"{target}.yaml"
        if not target_path.exists() and target == "selected_path_traversal":
            target_path = root / "configs" / "targets" / "path_traversal.yaml"
        target_config = load_yaml(target_path)
        target_revisions[target] = sha256_text(canonical_json(target_config))

    resolved = config.model_dump(mode="json")
    body = {
        "project_version": __version__,
        "python_version": platform.python_version(),
        "git_revision": _git_revision(root),
        "config_path": str(resolved_config_path.relative_to(root)),
        "config_sha256": sha256_file(resolved_config_path),
        "resolved_config": resolved,
        "prompt_sha256": prompt_hashes,
        "target_revisions": target_revisions,
    }
    lock_digest = sha256_text(canonical_json(body))
    lock = FreezeLock(
        frozen_at_utc=utc_now(),
        lock_sha256=lock_digest,
        **body,
    )
    destination = Path(output_path)
    if not destination.is_absolute():
        destination = root / destination
    if destination.exists():
        existing = load_yaml(destination) if destination.suffix in {".yaml", ".yml"} else None
        if existing is None:
            import json

            existing = json.loads(destination.read_text(encoding="utf-8"))
        if existing.get("lock_sha256") == lock_digest:
            return destination
        raise FileExistsError(
            f"{destination} already exists with a different design; remove it only to create a new experiment version"
        )
    atomic_write_json(destination, lock)
    return destination

