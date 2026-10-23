"""Obtém a resposta: pela rede (urllib) ou de um dump de headers."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import __version__
from .model import Headers, Response

USER_AGENT = f"headers-audit/{__version__} (+https://github.com/burnoutscript/headers-audit)"
# origem inventada (.invalid nunca resolve); se voltar no Access-Control-Allow-Origin, é reflexo
PROBE_ORIGIN = "https://headers-audit-probe.invalid"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 10


class FetchError(Exception):
    """Falha ao buscar a URL."""


@dataclass
class Hop:
    url: str
    status: int
    headers: Headers

    @property
    def next_url(self) -> str | None:
        location = self.headers.get_all("location")
        if self.status in REDIRECT_CODES and location:
            return urljoin(self.url, location[0])
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # cada salto precisa ser visto: é nele que se descobre se http vai para https
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url: str, timeout: float = 10.0, user_agent: str = USER_AGENT) -> Hop:
    """Um GET sem seguir redirecionamento."""
    req = urllib.request.Request(
        url, headers={"User-Agent": user_agent, "Origin": PROBE_ORIGIN, "Accept": "*/*"}
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return Hop(url, resp.status, Headers(resp.headers.items()))
    except urllib.error.HTTPError as exc:
        # 3xx, 4xx e 5xx chegam aqui, mas ainda são respostas com headers a auditar
        with exc:
            return Hop(url, exc.code, Headers(exc.headers.items()))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"não foi possível acessar {url}: {reason}") from exc


def follow(
    url: str,
    timeout: float = 10.0,
    user_agent: str = USER_AGENT,
    stop_at_https: bool = False,
) -> list[Hop]:
    """Segue os redirecionamentos e devolve cada salto, o último é a resposta final."""
    hops: list[Hop] = []
    current = url
    while True:
        if stop_at_https and hops and current.lower().startswith("https://"):
            return hops
        hop = request(current, timeout, user_agent)
        hops.append(hop)
        nxt = hop.next_url
        if nxt is None:
            return hops
        if len(hops) > MAX_REDIRECTS:
            raise FetchError(f"mais de {MAX_REDIRECTS} redirecionamentos a partir de {url}")
        current = nxt


def redirects_to_https(
    http_url: str, timeout: float = 10.0, user_agent: str = USER_AGENT
) -> bool:
    """Se a versão http da URL acaba levando para https."""
    hops = follow(http_url, timeout, user_agent, stop_at_https=True)
    last = hops[-1].next_url
    return last is not None and last.lower().startswith("https://")


def normalize_url(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"URL inválida: {url}")
    return urlunsplit(parts._replace(path=parts.path or "/"))


def fetch(url: str, timeout: float = 10.0, user_agent: str = USER_AGENT) -> Response:
    """Busca a URL e monta a resposta final com o resultado do teste http -> https."""
    url = normalize_url(url)
    hops = follow(url, timeout, user_agent)
    final = hops[-1]
    response = Response(
        headers=final.headers,
        status=final.status,
        url=final.url,
        chain=[h.url for h in hops],
        cors_probe=PROBE_ORIGIN,
    )
    if not url.lower().startswith("https://"):
        response.http_to_https = response.is_https
        return response

    http_url = urlunsplit(urlsplit(url)._replace(scheme="http"))
    try:
        response.http_to_https = redirects_to_https(http_url, timeout, user_agent)
    except FetchError:
        response.notes.append(
            "A versão http do site não respondeu, então o redirecionamento não foi testado. "
            "Porta 80 fechada também protege."
        )
    return response


def parse_dump(text: str, url: str | None = None) -> Response:
    """Lê um dump de headers (curl -sI, curl -sIL ou copiado do DevTools).

    Com vários blocos HTTP/, cada um é um salto e o último é a resposta final.
    """
    blocks: list[tuple[int, list[tuple[str, str]]]] = []
    current: list[tuple[str, str]] | None = None
    in_body = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 200
            current = []
            blocks.append((status, current))
            in_body = False
            continue
        if not line:
            if current:
                in_body = True
            continue
        if in_body or line.startswith("#"):
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip() or " " in name.strip():
            continue
        if current is None:
            current = []
            blocks.append((200, current))
        current.append((name, value))

    blocks = [(status, items) for status, items in blocks if items]
    if not blocks:
        raise ValueError("nenhum header encontrado no arquivo")

    chain: list[str] = []
    location = url
    for status, items in blocks:
        if location is None:
            break
        chain.append(location)
        hop = Hop(location, status, Headers(items))
        location = hop.next_url

    status, items = blocks[-1]
    final_url = chain[-1] if len(chain) == len(blocks) else None
    response = Response(headers=Headers(items), status=status, url=final_url, chain=chain)
    if url and url.lower().startswith("http://") and final_url:
        response.http_to_https = final_url.lower().startswith("https://")
    else:
        response.notes.append(
            "Redirecionamento http -> https não testado: o dump não começa numa URL http:// "
            "(informe com --url)."
        )
    if "access-control-allow-origin" in response.headers:
        response.notes.append(
            "CORS: um dump não mostra se o servidor reflete o Origin recebido. Isso só é "
            "testável contra a URL ao vivo."
        )
    return response
