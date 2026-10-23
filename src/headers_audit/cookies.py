"""Parser de Set-Cookie."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SESSION_NAME = re.compile(
    r"sess|^sid$|_sid$|^sid_|auth|token|jwt|login|remember|^connect\.sid$", re.IGNORECASE
)
# token de CSRF no padrão double-submit precisa ser lido pelo JavaScript
READABLE_BY_DESIGN = re.compile(r"csrf|xsrf", re.IGNORECASE)


@dataclass
class Cookie:
    name: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)

    def has(self, attribute: str) -> bool:
        return attribute.lower() in self.attributes

    def attr(self, attribute: str) -> str | None:
        return self.attributes.get(attribute.lower())

    @property
    def secure(self) -> bool:
        return self.has("secure")

    @property
    def http_only(self) -> bool:
        return self.has("httponly")

    @property
    def same_site(self) -> str | None:
        value = self.attr("samesite")
        return value.lower() if value is not None else None

    @property
    def looks_like_session(self) -> bool:
        return bool(SESSION_NAME.search(self.name)) and not READABLE_BY_DESIGN.search(self.name)

    @property
    def is_deletion(self) -> bool:
        """Cookie sendo apagado (Max-Age <= 0) não carrega dado nenhum."""
        max_age = self.attr("max-age")
        if max_age is None:
            return False
        try:
            return int(max_age) <= 0
        except ValueError:
            return False


def parse_set_cookie(value: str) -> Cookie | None:
    """Um header Set-Cookie. Devolve None se não houver nome=valor."""
    parts = value.split(";")
    name, sep, cookie_value = parts[0].partition("=")
    name = name.strip()
    if not sep or not name:
        return None
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, attr_value = part.partition("=")
        key = key.strip().lower()
        if key:
            attributes[key] = attr_value.strip()
    return Cookie(name, cookie_value.strip(), attributes)


def parse_cookies(values: list[str]) -> list[Cookie]:
    """Todos os Set-Cookie da resposta (cada um vem num header próprio)."""
    return [c for c in (parse_set_cookie(v) for v in values) if c is not None]
