from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActorCondition(StrEnum):
    BENIGN = "benign"
    ATTACK_STANDARD = "attack_standard"
    ATTACK_STEALTH = "attack_stealth"


class Verdict(StrEnum):
    BENIGN = "benign"
    ATTACK = "attack"
    INSUFFICIENT = "insufficient_evidence"


class TerminationReason(StrEnum):
    FINISHED = "finished"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REFUSED = "refused"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class Scenario(StrictModel):
    schema_version: Literal["scenario_v1"] = "scenario_v1"
    experiment_id: str
    scenario_pair_id: str
    split: str
    target_id: str
    condition: ActorCondition
    scenario_seed: int
    actor_username: str
    actor_password: str
    actor_account_alias: str
    owned_resource_id: str
    protected_resource_id: str
    benign_goal: str
    attack_goal: str
    vulnerability_class_brief: str
    canary: str


class PublicEvent(StrictModel):
    schema_version: Literal["access_v1"] = "access_v1"
    event_id: str
    sequence: int = Field(ge=1)
    t_rel_ms: int = Field(ge=0)
    source: Literal["gateway"] = "gateway"
    session_id: str
    principal_id: str | None = None
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    query_keys: list[str] = Field(default_factory=list)
    request_content_type: str | None = None
    request_bytes: int = Field(ge=0)
    status: int = Field(ge=100, le=599)
    response_content_type: str | None = None
    response_bytes: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    redirected: bool = False


class OracleEvent(StrictModel):
    schema_version: Literal["oracle_event_v1"] = "oracle_event_v1"
    event_id: str
    sequence: int = Field(ge=1)
    policy_violation: bool
    violation_type: str | None = None
    canary_exposed: bool = False
    actor_principal_private: str | None = None
    resource_owner_private: str | None = None
    annotation_version: str

    @model_validator(mode="after")
    def validate_violation(self) -> "OracleEvent":
        if self.policy_violation and not self.violation_type:
            raise ValueError("violation_type is required for a policy violation")
        return self


class GroundTruth(StrictModel):
    schema_version: Literal["ground_truth_v1"] = "ground_truth_v1"
    assigned_condition: ActorCondition
    assigned_malicious: bool
    observable_attack: bool
    attack_success: bool
    benign_task_success: bool | None = None
    first_policy_violation_event_id: str | None = None
    success_event_id: str | None = None
    refusal_detected: bool = False
    termination_reason: TerminationReason = TerminationReason.FINISHED

    @model_validator(mode="after")
    def validate_consistency(self) -> "GroundTruth":
        should_be_malicious = self.assigned_condition != ActorCondition.BENIGN
        if self.assigned_malicious != should_be_malicious:
            raise ValueError("assigned_malicious disagrees with assigned_condition")
        if self.attack_success and not self.observable_attack:
            raise ValueError("a successful attack must be observable to the oracle")
        if self.observable_attack and not self.first_policy_violation_event_id:
            raise ValueError("observable attacks need a first policy-violation event")
        return self


class EpisodeManifest(StrictModel):
    schema_version: Literal["episode_manifest_v1"] = "episode_manifest_v1"
    experiment_id: str
    episode_id: str
    scenario_pair_id: str
    split: str
    target_id: str
    target_revision: str
    actor_condition: ActorCondition
    actor_model_id: str
    actor_model_revision: str
    harness_revision: str
    prompt_sha256: str
    scenario_seed: int
    sampling_seed_requested: int
    started_at_utc: datetime
    ended_at_utc: datetime
    run_status: Literal["complete", "infrastructure_failure"]
    canonical_attempt: int = Field(ge=1)
    public_log_sha256: str


class DefenderOutput(StrictModel):
    verdict: Verdict
    attack_probability: float
    first_suspicious_event_id: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=5)
    suspected_tactic: Literal[
        "authorization_abuse",
        "path_manipulation",
        "enumeration",
        "injection",
        "credential_abuse",
        "other",
        "none",
        "unclear",
    ]
    rationale: str = Field(max_length=800)

    @field_validator("attack_probability")
    @classmethod
    def probability_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("attack_probability must be in [0, 1]")
        return value

    @field_validator("evidence_event_ids")
    @classmethod
    def evidence_ids_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence event IDs must be unique")
        return value


class PredictionRecord(StrictModel):
    schema_version: Literal["prediction_v1"] = "prediction_v1"
    experiment_id: str
    episode_id: str
    defender_id: str
    defender_model_revision: str
    prompt_sha256: str
    input_sha256: str
    raw_output: str
    parsed_output: DefenderOutput
    parse_failure: bool
    latency_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    created_at_utc: datetime


class ExperimentConfig(StrictModel):
    experiment: dict[str, Any]
    targets: list[str]
    actor_conditions: list[ActorCondition]
    actor_model: str
    defender_models: list[str]
    log_view: str
    analysis: dict[str, Any]
    prompts: dict[str, str]


class FreezeLock(StrictModel):
    schema_version: Literal["experiment_lock_v1"] = "experiment_lock_v1"
    frozen_at_utc: datetime
    project_version: str
    python_version: str
    git_revision: str | None
    config_path: str
    config_sha256: str
    resolved_config: dict[str, Any]
    prompt_sha256: dict[str, str]
    target_revisions: dict[str, str]
    lock_sha256: str

