"""Base-rate economics and transfer analysis for the adaptive-evasion study (spec v2).

Pure, side-effect-free numeric cores so they can be unit-tested without any run data:

- FPR / recall estimation at a fixed threshold;
- precision and alert-volume at an arbitrary prevalence (the analytic sweep);
- the transfer fraction tau = eval_effect / proxy_effect (idiosyncratic vs fundamental);
- a token/cost ledger.

Top-level orchestration that reads the v2 episode/prediction layout lives with the adaptive
runner once that data format is frozen; these functions are what it will call.
"""

from __future__ import annotations

from typing import Sequence


def rate_at_threshold(scores: Sequence[float], threshold: float) -> float | None:
    """Fraction of sessions with score >= threshold (FPR on benign, recall on attacks)."""
    scores = list(scores)
    if not scores:
        return None
    return sum(1 for s in scores if s >= threshold) / len(scores)


def precision_at_prevalence(recall: float | None, fpr: float | None, prevalence: float) -> float | None:
    """Precision at attack prevalence p: recall*p / (recall*p + fpr*(1-p)).

    Returns None if inputs are missing; returns 0.0 when there are no positive alerts
    (recall or prevalence is zero) but the denominator is otherwise defined.
    """
    if recall is None or fpr is None:
        return None
    if not (0.0 <= prevalence <= 1.0):
        raise ValueError("prevalence must be in [0, 1]")
    tp = recall * prevalence
    fp = fpr * (1.0 - prevalence)
    denom = tp + fp
    if denom == 0.0:
        return None  # no alerts at all at this operating point
    return tp / denom


def alerts_per_n(recall: float | None, fpr: float | None, prevalence: float, n: int = 100_000) -> dict[str, float] | None:
    """Expected alert counts per n sessions at a prevalence: total / true / false."""
    if recall is None or fpr is None:
        return None
    true_alerts = recall * prevalence * n
    false_alerts = fpr * (1.0 - prevalence) * n
    return {"total": true_alerts + false_alerts, "true": true_alerts, "false": false_alerts}


def prevalence_sweep(
    recall: float | None,
    fpr: float | None,
    prevalences: Sequence[float] = (1 / 50, 1 / 100, 1 / 1000, 1 / 10000),
    n: int = 100_000,
) -> list[dict[str, float | None]]:
    rows: list[dict[str, float | None]] = []
    for p in prevalences:
        counts = alerts_per_n(recall, fpr, p, n)
        rows.append(
            {
                "prevalence": p,
                "precision": precision_at_prevalence(recall, fpr, p),
                "alerts_per_n": None if counts is None else counts["total"],
                "false_alerts_per_n": None if counts is None else counts["false"],
                "n": n,
            }
        )
    return rows


def transfer_fraction(
    proxy_baseline: float,
    proxy_evasive: float,
    eval_baseline: float,
    eval_evasive: float,
    *,
    min_proxy_effect: float = 0.05,
) -> float | None:
    """tau = eval_effect / proxy_effect for one (defender, scenario).

    proxy_effect is how much the attacker lowered its OWN model's attack probability;
    eval_effect is the same drop on a held-out detector. tau ~ 0 => idiosyncratic evasion,
    tau ~ 1 => fully transferred (fundamental). Undefined (None) when the attacker barely
    moved its own proxy (proxy_effect below a floor), since the ratio is then unstable.
    """
    proxy_effect = proxy_baseline - proxy_evasive
    if proxy_effect < min_proxy_effect:
        return None
    eval_effect = eval_baseline - eval_evasive
    return eval_effect / proxy_effect


def cost_ledger(
    *,
    attack_input_tokens: int,
    attack_output_tokens: int,
    input_price_per_m: float,
    output_price_per_m: float,
    successful_attacks: int,
    screened_sessions: int,
    screen_input_tokens: int,
    screen_output_tokens: int,
    screen_input_price_per_m: float,
    screen_output_price_per_m: float,
) -> dict[str, float | None]:
    """USD per successful attack (offense side, incl. adaptation rounds) vs per screened
    session (defense side). All token counts are totals over the counted episodes."""
    attack_usd = (attack_input_tokens * input_price_per_m + attack_output_tokens * output_price_per_m) / 1_000_000
    screen_usd = (screen_input_tokens * screen_input_price_per_m + screen_output_tokens * screen_output_price_per_m) / 1_000_000
    return {
        "offense_usd_total": round(attack_usd, 4),
        "offense_usd_per_successful_attack": round(attack_usd / successful_attacks, 4) if successful_attacks else None,
        "defense_usd_total": round(screen_usd, 4),
        "defense_usd_per_screened_session": round(screen_usd / screened_sessions, 6) if screened_sessions else None,
    }
