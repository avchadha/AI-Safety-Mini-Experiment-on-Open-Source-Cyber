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


def _target_macro_auroc(entries: Sequence[tuple[str, str, int, float]]) -> float | None:
    """Mean of per-target AUROCs (equal target weight). entries: (target, pair, label, score)."""
    by_target: dict[str, tuple[list[int], list[float]]] = {}
    for target, _pair, label, score in entries:
        labels, scores = by_target.setdefault(target, ([], []))
        labels.append(label)
        scores.append(score)
    per_target = [auroc(labels, scores) for labels, scores in by_target.values()]
    valid = [v for v in per_target if v is not None]
    return sum(valid) / len(valid) if valid else None


def cluster_bootstrap_macro_auroc(
    entries: Sequence[tuple[str, str, int, float]],
    *,
    replicates: int = 10000,
    seed: int = 20260904,
) -> dict[str, Any]:
    """Target-macro AUROC point + CI, resampling scenario-pair clusters within each target."""
    point = _target_macro_auroc(entries)
    # index entries by (target, pair)
    clusters: dict[tuple[str, str], list[tuple[str, str, int, float]]] = {}
    targets: dict[str, list[tuple[str, str]]] = {}
    for entry in entries:
        key = (entry[0], entry[1])
        clusters.setdefault(key, []).append(entry)
        targets.setdefault(entry[0], [])
        if key not in targets[entry[0]]:
            targets[entry[0]].append(key)
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(replicates):
        sample: list[tuple[str, str, int, float]] = []
        for _target, keys in targets.items():
            chosen = [rng.choice(keys) for _ in keys]
            for key in chosen:
                sample.extend(clusters[key])
        value = _target_macro_auroc(sample)
        if value is not None:
            values.append(value)
    values.sort()
    if not values:
        return {"point": point, "ci_low": None, "ci_high": None, "replicates": 0}
    return {"point": point, "ci_low": _percentile(values, 0.025), "ci_high": _percentile(values, 0.975), "replicates": len(values)}


def select_threshold(labels: Sequence[int], scores: Sequence[float], *, fpr_target: float = 0.10) -> float:
    """Calibration threshold: highest TPR with FPR <= fpr_target; ties -> higher threshold."""
    negatives = [s for s, y in zip(scores, labels) if y == 0]
    positives = [s for s, y in zip(scores, labels) if y == 1]
    if not negatives or not positives:
        return 1.0
    candidates = sorted({*scores, 1.0}, reverse=True)
    best: tuple[float, float] | None = None  # (tpr, threshold)
    for thr in candidates:
        fpr = sum(1 for s in negatives if s >= thr) / len(negatives)
        if fpr <= fpr_target:
            tpr = sum(1 for s in positives if s >= thr) / len(positives)
            if best is None or tpr > best[0] or (tpr == best[0] and thr > best[1]):
                best = (tpr, thr)
    return best[1] if best is not None else 1.0


def paired_macro_auroc_difference(
    entries_a: Sequence[tuple[str, str, int, float]],
    entries_b: Sequence[tuple[str, str, int, float]],
    *,
    replicates: int = 10000,
    seed: int = 20260904,
) -> dict[str, Any]:
    """CI for macro AUROC(b) - macro AUROC(a) on shared (target, pair, label) episodes.

    entries_a and entries_b must be aligned by (target, pair, episode); only the score differs.
    """
    point_a = _target_macro_auroc(entries_a)
    point_b = _target_macro_auroc(entries_b)
    point = None if point_a is None or point_b is None else point_b - point_a
    # index by (target, pair) -> list of (label, score_a, score_b)
    by_key: dict[tuple[str, str], list[tuple[int, float, float]]] = {}
    a_lookup = {(t, p, i): (lab, sc) for i, (t, p, lab, sc) in enumerate(entries_a)}
    # align by position (callers build aligned lists)
    targets: dict[str, list[tuple[str, str]]] = {}
    for (t, p, lab, sa), (_t, _p, _lab, sb) in zip(entries_a, entries_b):
        key = (t, p)
        by_key.setdefault(key, []).append((lab, sa, sb))
        targets.setdefault(t, [])
        if key not in targets[t]:
            targets[t].append(key)
    rng = random.Random(seed)
    diffs: list[float] = []
    for _ in range(replicates):
        a_entries: list[tuple[str, str, int, float]] = []
        b_entries: list[tuple[str, str, int, float]] = []
        for t, keys in targets.items():
            for key in (rng.choice(keys) for _ in keys):
                for lab, sa, sb in by_key[key]:
                    a_entries.append((t, key[1], lab, sa))
                    b_entries.append((t, key[1], lab, sb))
        ma = _target_macro_auroc(a_entries)
        mb = _target_macro_auroc(b_entries)
        if ma is not None and mb is not None:
            diffs.append(mb - ma)
    diffs.sort()
    if not diffs:
        return {"point": point, "ci_low": None, "ci_high": None, "replicates": 0, "p_b_gt_a": None}
    return {
        "point": point,
        "ci_low": _percentile(diffs, 0.025),
        "ci_high": _percentile(diffs, 0.975),
        "replicates": len(diffs),
        "p_b_gt_a": sum(1 for d in diffs if d <= 0) / len(diffs),
    }
