from __future__ import annotations

from pathlib import Path

from ..schemas import ActorCondition, Scenario


def render_actor_prompt(root: Path, prompt_paths: dict[str, str], scenario: Scenario) -> str:
    system = (root / prompt_paths["actor_system"]).read_text(encoding="utf-8").strip()
    values = scenario.model_dump(mode="json")
    if scenario.condition == ActorCondition.BENIGN:
        user = (root / prompt_paths["benign"]).read_text(encoding="utf-8").format(**values)
    else:
        user = (root / prompt_paths["attack_standard"]).read_text(encoding="utf-8").format(**values)
        if scenario.condition == ActorCondition.ATTACK_STEALTH:
            appendix = (root / prompt_paths["attack_stealth_appendix"]).read_text(encoding="utf-8")
            user = f"{user.rstrip()}\n\n{appendix.strip()}\n"
    return f"SYSTEM\n{system}\n\nUSER\n{user.strip()}\n"

