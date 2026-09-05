"""Cluster bootstrap for detector AUROC and paired defender differences.

The experimental unit is a scenario pair, not an episode: matched actor conditions and the
paired defender predictions for a pair must move together under resampling. These helpers
resample ``scenario_pair_id`` clusters with replacement and report percentile intervals,
using only the standard library so they stay part of the core package.
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Sequence

from .metrics import auroc


def _clusters(cluster_ids: Sequence[str]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, cluster in enumerate(cluster_ids):
        groups[cluster].append(index)
    return dict(groups)


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        raise ValueError("no values")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = q * (len(sorted_values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    frac = position - lower
    return sorted_values[lower] * (1 - frac) + sorted_values[upper] * frac


def cluster_bootstrap_auroc(
    labels: Sequence[int],
    scores: Sequence[float],
    cluster_ids: Sequence[str],
    *,
    replicates: int = 10000,
    seed: int = 20260904,
) -> dict[str, float | int | None]:
    point = auroc(labels, scores)
    groups = _clusters(cluster_ids)
    keys = list(groups)
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(replicates):
        chosen = [rng.choice(keys) for _ in keys]
        idx = [i for key in chosen for i in groups[key]]
        value = auroc([labels[i] for i in idx], [scores[i] for i in idx])
        if value is not None:
            values.append(value)
    values.sort()
    if not values:
        return {"point": point, "ci_low": None, "ci_high": None, "replicates": 0}
    return {
        "point": point,
        "ci_low": _percentile(values, 0.025),
        "ci_high": _percentile(values, 0.975),
        "replicates": len(values),
    }


def paired_auroc_difference(
    labels: Sequence[int],
    cluster_ids: Sequence[str],
    scores_a: Sequence[float],
    scores_b: Sequence[float],
    *,
    replicates: int = 10000,
    seed: int = 20260904,
) -> dict[str, float | int | None]:
    """95% CI for AUROC(b) - AUROC(a) on the same episodes, resampling pair clusters.

    Positive values mean defender B ranks attacks above benign better than defender A
    (H2 uses B = largest defender, A = smallest).
    """
    point_a = auroc(labels, scores_a)
    point_b = auroc(labels, scores_b)
    point = None if point_a is None or point_b is None else point_b - point_a
    groups = _clusters(cluster_ids)
    keys = list(groups)
    rng = random.Random(seed)
    diffs: list[float] = []
    for _ in range(replicates):
        chosen = [rng.choice(keys) for _ in keys]
        idx = [i for key in chosen for i in groups[key]]
        sub_labels = [labels[i] for i in idx]
        a = auroc(sub_labels, [scores_a[i] for i in idx])
        b = auroc(sub_labels, [scores_b[i] for i in idx])
        if a is not None and b is not None:
            diffs.append(b - a)
    diffs.sort()
    if not diffs:
        return {"point": point, "ci_low": None, "ci_high": None, "replicates": 0, "p_b_gt_a": None}
    # One-sided bootstrap evidence that B > A.
    p_b_gt_a = sum(1 for d in diffs if d <= 0) / len(diffs)
    return {
        "point": point,
        "ci_low": _percentile(diffs, 0.025),
        "ci_high": _percentile(diffs, 0.975),
        "replicates": len(diffs),
        "p_b_gt_a": p_b_gt_a,
    }
