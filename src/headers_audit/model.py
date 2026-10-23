"""Modelo da resposta HTTP auditada e dos achados."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severidade de um achado, do menos para o mais grave."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH].index(self)


class Headers:
    """Headers de uma resposta, com busca sem diferenciar maiúsculas."""

    def __init__(self, items: Iterable[tuple[str, str]] = ()) -> None:
        self.items = [(name.strip(), value.strip()) for name, value in items]

    def get_all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.items if key.lower() == wanted]

    def get(self, name: str) -> str | None:
        """Valor do header; repetições viram uma lista separada por vírgula, como na RFC 9110."""
        values = self.get_all(name)
        return ", ".join(values) if values else None

    def __contains__(self, name: str) -> bool:
        return bool(self.get_all(name))

    def __len__(self) -> int:
        return len(self.items)


@dataclass
class Response:
    """A resposta final de uma URL, mais o que se sabe do caminho até ela."""

    headers: Headers
    status: int = 200
    url: str | None = None
    chain: list[str] = field(default_factory=list)
    http_to_https: bool | None = None
    cors_probe: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_https(self) -> bool:
        # sem URL (dump sem --url) assumimos HTTPS, que é o caso de quem roda a auditoria
        return self.url is None or self.url.lower().startswith("https://")


@dataclass
class Finding:
    """Um problema encontrado nos headers."""

    rule_id: str
    title: str
    severity: Severity
    target: str
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "target": self.target,
            "description": self.description,
            "recommendation": self.recommendation,
        }
