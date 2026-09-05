from __future__ import annotations

import json
from typing import Iterable

from pydantic import ValidationError

from ..schemas import DefenderOutput, Verdict


def parse_output(raw: str, valid_event_ids: Iterable[str]) -> tuple[DefenderOutput, bool]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    start = text.find("{")
    end = text.rfind("}")
    try:
        if start < 0 or end < start:
            raise ValueError("no JSON object found")
        value = json.loads(text[start : end + 1])
        parsed = DefenderOutput.model_validate(value)
        allowed = set(valid_event_ids)
        cited = list(parsed.evidence_event_ids)
        if parsed.first_suspicious_event_id:
            cited.append(parsed.first_suspicious_event_id)
        unknown = sorted(set(cited) - allowed)
        if unknown:
            raise ValueError(f"unknown evidence IDs: {unknown}")
        return parsed, False
    except (ValueError, json.JSONDecodeError, ValidationError):
        fallback = DefenderOutput(
            verdict=Verdict.INSUFFICIENT,
            attack_probability=0.5,
            first_suspicious_event_id=None,
            evidence_event_ids=[],
            suspected_tactic="unclear",
            rationale="The detector output could not be parsed as the required schema.",
        )
        return fallback, True

