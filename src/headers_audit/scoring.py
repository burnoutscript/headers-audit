"""Pontuação de 0 a 100 e nota de A+ a F."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from .model import Finding, Severity

PENALTIES = {Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 5, Severity.INFO: 0}
# dez cookies sem SameSite não deixam o site dez vezes mais exposto que um
RULE_CAP = 25
GRADES: tuple[tuple[str, int], ...] = (
    ("A+", 95),
    ("A", 85),
    ("B", 70),
    ("C", 55),
    ("D", 40),
    ("F", 0),
)
GRADE_ORDER = [grade for grade, _ in reversed(GRADES)]


def penalties_by_rule(findings: Sequence[Finding]) -> dict[str, int]:
    """Desconto de cada verificação, já com o teto aplicado."""
    totals: dict[str, int] = defaultdict(int)
    for finding in findings:
        totals[finding.rule_id] += PENALTIES[finding.severity]
    return {rule_id: min(total, RULE_CAP) for rule_id, total in sorted(totals.items()) if total}


def score(findings: Sequence[Finding]) -> int:
    return max(0, 100 - sum(penalties_by_rule(findings).values()))


def grade_for(points: int) -> str:
    for grade, minimum in GRADES:
        if points >= minimum:
            return grade
    return "F"


def meets(grade: str, minimum: str) -> bool:
    """Se a nota é igual ou melhor que a mínima."""
    return GRADE_ORDER.index(grade) >= GRADE_ORDER.index(minimum)
