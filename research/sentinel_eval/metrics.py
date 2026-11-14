"""Classification metrics with confidence intervals.

Everything here is plain arithmetic on counts, so it can be checked by hand and tested.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif actual:
            self.fn += 1
        else:
            self.tn += 1

    def merge(self, other: Confusion) -> Confusion:
        return Confusion(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn)

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        return self.fp + self.tn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / self.positives if self.positives else None

    @property
    def false_positive_rate(self) -> float | None:
        return self.fp / self.negatives if self.negatives else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self) -> float | None:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else None


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float] | None:
    """95 % Wilson score interval for a proportion; None when there are no trials."""
    if trials <= 0:
        return None
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


def summarise(confusion: Confusion) -> dict:
    """Metrics plus 95 % intervals for the three proportions that have a natural denominator."""

    def interval(successes: int, trials: int) -> list[float] | None:
        found = wilson_interval(successes, trials)
        return [round(found[0], 4), round(found[1], 4)] if found else None

    def rounded(value: float | None) -> float | None:
        return None if value is None else round(value, 4)

    return {
        "tp": confusion.tp,
        "fp": confusion.fp,
        "fn": confusion.fn,
        "tn": confusion.tn,
        "precision": rounded(confusion.precision),
        "precision_ci95": interval(confusion.tp, confusion.tp + confusion.fp),
        "recall": rounded(confusion.recall),
        "recall_ci95": interval(confusion.tp, confusion.positives),
        "false_positive_rate": rounded(confusion.false_positive_rate),
        "false_positive_rate_ci95": interval(confusion.fp, confusion.negatives),
        "f1": rounded(confusion.f1),
        "accuracy": rounded(confusion.accuracy),
    }


def precision_at_prevalence(recall: float | None, fpr: float | None, prevalence: float) -> float | None:
    """Precision a method with this recall and false positive rate would have at another prevalence.

    Precision depends on how rare attacks are. Recall and the false positive rate do not, so this
    projects a measured method onto a population with a different share of attackers.
    """
    if recall is None or fpr is None or not 0 < prevalence < 1:
        return None
    true_positives = recall * prevalence
    false_positives = fpr * (1 - prevalence)
    total = true_positives + false_positives
    return true_positives / total if total else None
