from __future__ import annotations

from math import sqrt
from typing import Iterable


def _validate(labels: Iterable[int], scores: Iterable[float]) -> tuple[list[int], list[float]]:
    y = list(labels)
    p = list(scores)
    if len(y) != len(p):
        raise ValueError("labels and scores must have equal length")
    if any(label not in {0, 1} for label in y):
        raise ValueError("labels must be binary")
    if any(not 0 <= score <= 1 for score in p):
        raise ValueError("scores must be in [0, 1]")
    return y, p


def auroc(labels: Iterable[int], scores: Iterable[float]) -> float | None:
    y, p = _validate(labels, scores)
    positive = [score for label, score in zip(y, p, strict=True) if label == 1]
    negative = [score for label, score in zip(y, p, strict=True) if label == 0]
    if not positive or not negative:
        return None
    favorable = 0.0
    for pos in positive:
        for neg in negative:
            favorable += 1.0 if pos > neg else (0.5 if pos == neg else 0.0)
    return favorable / (len(positive) * len(negative))


def average_precision(labels: Iterable[int], scores: Iterable[float]) -> float | None:
    y, p = _validate(labels, scores)
    positives = sum(y)
    if positives == 0:
        return None
    total = 0.0
    previous_recall = 0.0
    for threshold in sorted(set(p), reverse=True):
        selected = [index for index, score in enumerate(p) if score >= threshold]
        true_positives = sum(y[index] for index in selected)
        precision = true_positives / len(selected)
        recall = true_positives / positives
        total += (recall - previous_recall) * precision
        previous_recall = recall
    return total


def brier_score(labels: Iterable[int], scores: Iterable[float]) -> float | None:
    y, p = _validate(labels, scores)
    return sum((score - label) ** 2 for label, score in zip(y, p, strict=True)) / len(y) if y else None


def confusion(labels: Iterable[int], scores: Iterable[float], threshold: float) -> dict[str, int | float | None]:
    y, p = _validate(labels, scores)
    predicted = [int(score >= threshold) for score in p]
    tp = sum(label == 1 and pred == 1 for label, pred in zip(y, predicted, strict=True))
    tn = sum(label == 0 and pred == 0 for label, pred in zip(y, predicted, strict=True))
    fp = sum(label == 0 and pred == 1 for label, pred in zip(y, predicted, strict=True))
    fn = sum(label == 1 and pred == 0 for label, pred in zip(y, predicted, strict=True))
    tpr = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    precision = tp / (tp + fp) if tp + fp else None
    specificity = tn / (tn + fp) if tn + fp else None
    balanced = (tpr + specificity) / 2 if tpr is not None and specificity is not None else None
    f1 = 2 * precision * tpr / (precision + tpr) if precision and tpr else 0.0
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tpr": tpr,
        "fpr": fpr,
        "precision": precision,
        "specificity": specificity,
        "balanced_accuracy": balanced,
        "f1": f1,
    }


def standard_error_proportion(successes: int, total: int) -> float | None:
    if total == 0:
        return None
    probability = successes / total
    return sqrt(probability * (1 - probability) / total)
