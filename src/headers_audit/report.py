"""Formatação do resultado: terminal, JSON e Markdown."""

from __future__ import annotations

import json
import textwrap
from collections import Counter
from collections.abc import Sequence

from .model import Finding, Response, Severity
from .scoring import grade_for, penalties_by_rule, score

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
COLORS = {
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
LABELS = {
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MÉDIO",
    Severity.LOW: "BAIXO",
    Severity.INFO: "INFO",
}
GRADE_COLORS = {"A+": "\033[32m", "A": "\033[32m", "B": "\033[32m", "C": "\033[33m"}


def summarize(response: Response, findings: Sequence[Finding]) -> dict:
    """Nota, pontuação e contagens."""
    points = score(findings)
    return {
        "grade": grade_for(points),
        "score": points,
        "penalties": penalties_by_rule(findings),
        "findings": len(findings),
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "headers": len(response.headers),
    }


def _wrap(text: str, indent: str = "  ") -> list[str]:
    return textwrap.wrap(text, width=90, initial_indent=indent, subsequent_indent=indent)


def to_terminal(
    response: Response, findings: Sequence[Finding], source: str, color: bool = True
) -> str:
    """Relatório colorido para leitura direta no terminal."""

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    stats = summarize(response, findings)
    grade = stats["grade"]
    lines = [
        "",
        paint("  headers-audit · headers de segurança HTTP", BOLD),
        f"  {source} · status {response.status} · {stats['headers']} headers",
        "",
        f"  Nota {paint(f' {grade} ', BOLD + GRADE_COLORS.get(grade, COLORS[Severity.HIGH]))}"
        f"  {stats['score']}/100 · {stats['findings']} achado(s)",
        "  " + "─" * 66,
    ]
    if len(response.chain) > 1:
        lines.insert(3, paint(f"  redirecionamentos: {' → '.join(response.chain)}", DIM))

    if not findings:
        lines += ["", paint("  Nenhum problema encontrado nas verificações ativas.", GREEN)]

    for finding in findings:
        badge = paint(f" {LABELS[finding.severity]} ", COLORS[finding.severity])
        lines += [
            "",
            f"  {badge} {paint(finding.title, BOLD)}  {paint(finding.rule_id, DIM)}",
            f"  {finding.target}",
            "",
            *_wrap(finding.description),
            "",
            *(paint(line, DIM) for line in _wrap(f"→ {finding.recommendation}")),
        ]

    if response.notes:
        lines += ["", "  " + "─" * 66]
        for note in response.notes:
            lines += [paint(line, DIM) for line in _wrap(f"nota: {note}")]

    lines.append("")
    return "\n".join(lines)


def to_json(response: Response, findings: Sequence[Finding], source: str) -> str:
    """Saída legível por máquina, para pipeline de CI."""
    return json.dumps(
        {
            "source": source,
            "url": response.url,
            "status": response.status,
            "redirect_chain": response.chain,
            "http_to_https": response.http_to_https,
            "summary": summarize(response, findings),
            "findings": [f.to_dict() for f in findings],
            "notes": response.notes,
        },
        indent=2,
        ensure_ascii=False,
    )


def to_markdown(response: Response, findings: Sequence[Finding], source: str) -> str:
    """Relatório para anexar em pull request ou issue."""
    stats = summarize(response, findings)
    lines = [
        "# Auditoria de headers de segurança",
        "",
        f"- **Origem:** `{source}`",
        f"- **Status:** {response.status}",
        f"- **Nota:** {stats['grade']} ({stats['score']}/100)",
        f"- **Achados:** {stats['findings']}",
    ]
    if not findings:
        lines += ["", "Nenhum problema encontrado nas verificações ativas."]
    else:
        lines += [
            "",
            "## Achados",
            "",
            "| Severidade | Regra | Título | Alvo |",
            "|---|---|---|---|",
        ]
        for f in findings:
            lines.append(f"| {LABELS[f.severity]} | {f.rule_id} | {f.title} | `{f.target}` |")
        lines += ["", "## Detalhamento", ""]
        for f in findings:
            lines += [
                f"### {LABELS[f.severity]} · {f.title} (`{f.rule_id}`)",
                "",
                f"**Alvo:** `{f.target}`",
                "",
                f.description,
                "",
                f"**Ação recomendada:** {f.recommendation}",
                "",
            ]
    if response.notes:
        lines += ["", "## Notas", ""]
        lines += [f"- {note}" for note in response.notes]
    return "\n".join(lines)
