from __future__ import annotations

from typing import Protocol

from ...schemas import Scenario


class RunningTarget(Protocol):
    origin: str

    def stop(self) -> None: ...


class TargetAdapter(Protocol):
    id: str

    def start(self, scenario: Scenario) -> RunningTarget: ...

