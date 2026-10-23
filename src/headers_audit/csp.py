"""Parser de Content-Security-Policy."""

from __future__ import annotations

Policy = dict[str, list[str]]

# diretivas de fetch que caem no default-src quando ausentes
FETCH_DIRECTIVES = frozenset(
    {
        "child-src",
        "connect-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "script-src",
        "style-src",
        "worker-src",
    }
)


def parse_policy(value: str) -> Policy:
    """Uma política: diretivas em minúsculas, keywords entre aspas normalizadas."""
    policy: Policy = {}
    for chunk in value.split(";"):
        tokens = chunk.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # a especificação manda ignorar a diretiva repetida, vale a primeira
        if name in policy:
            continue
        policy[name] = [_normalize(token) for token in tokens[1:]]
    return policy


def parse_csp(value: str | None) -> list[Policy]:
    """Header completo; vírgula separa políticas independentes (header repetido)."""
    if not value:
        return []
    return [p for p in (parse_policy(part) for part in value.split(",")) if p]


def _normalize(token: str) -> str:
    if token.startswith("'") and token.endswith("'"):
        inner = token[1:-1]
        # nonce e hash são sensíveis a maiúsculas no valor, só o prefixo é normalizado
        prefix, sep, rest = inner.partition("-")
        if sep and prefix.lower() in {"nonce", "sha256", "sha384", "sha512"}:
            return f"'{prefix.lower()}-{rest}'"
        return f"'{inner.lower()}'"
    return token.lower() if token.endswith(":") or token == "*" else token


def sources(policy: Policy, directive: str) -> list[str] | None:
    """Fontes efetivas da diretiva, com fallback para default-src; None se nada restringe."""
    if directive in policy:
        return policy[directive]
    if directive == "script-src-elem" or directive == "script-src-attr":
        return sources(policy, "script-src")
    if directive in FETCH_DIRECTIVES and "default-src" in policy:
        return policy["default-src"]
    return None


def has_nonce_or_hash(values: list[str]) -> bool:
    return any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in values)


def inline_neutralized(values: list[str]) -> bool:
    """Em navegadores CSP2+, nonce, hash ou strict-dynamic fazem o 'unsafe-inline' ser ignorado."""
    return has_nonce_or_hash(values) or "'strict-dynamic'" in values


def broad_sources(values: list[str]) -> list[str]:
    """Fontes que liberam script de qualquer host."""
    if "'strict-dynamic'" in values:
        # strict-dynamic faz o navegador ignorar host e esquema; vale a confiança do nonce
        return []
    return [v for v in values if v in {"*", "https:", "http:", "data:", "blob:"}]
