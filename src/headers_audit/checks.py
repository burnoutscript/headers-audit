"""Verificações de headers. Cada uma recebe a resposta e devolve achados."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from . import csp
from .cookies import parse_cookies
from .model import Finding, Response, Severity

SIX_MONTHS = 15_552_000
ONE_YEAR = 31_536_000
VERSION = re.compile(r"\d+\.\d+")

Check = Callable[[Response], list[Finding]]


def _hsts(response: Response) -> tuple[int | None, set[str]]:
    value = response.headers.get_all("strict-transport-security")
    if not value:
        return None, set()
    # com header repetido o navegador usa só o primeiro
    max_age: int | None = None
    flags: set[str] = set()
    for part in value[0].split(";"):
        key, _, val = part.strip().partition("=")
        key = key.strip().lower()
        if key == "max-age":
            try:
                max_age = int(val.strip().strip('"'))
            except ValueError:
                max_age = None
        elif key:
            flags.add(key)
    return max_age, flags


def ha001_hsts_missing(response: Response) -> list[Finding]:
    if not response.is_https or "strict-transport-security" in response.headers:
        return []
    return [
        Finding(
            "HA001",
            "HSTS ausente",
            Severity.HIGH,
            "Strict-Transport-Security",
            "Sem HSTS, o primeiro acesso por http:// (link antigo, digitação sem https) pode ser "
            "interceptado numa rede hostil antes do redirecionamento, e o atacante segura a "
            "vítima em HTTP (SSL stripping).",
            "Enviar Strict-Transport-Security: max-age=31536000; includeSubDomains nas respostas "
            "HTTPS.",
        )
    ]


def ha002_hsts_weak(response: Response) -> list[Finding]:
    if not response.is_https or "strict-transport-security" not in response.headers:
        return []
    max_age, flags = _hsts(response)
    target = "Strict-Transport-Security"
    findings: list[Finding] = []
    if max_age is None or max_age < SIX_MONTHS:
        shown = "ausente ou inválido" if max_age is None else f"{max_age}s"
        findings.append(
            Finding(
                "HA002",
                "HSTS com max-age curto",
                Severity.MEDIUM,
                target,
                f"max-age {shown}. Abaixo de seis meses a proteção expira entre visitas e o "
                "navegador volta a aceitar HTTP. max-age=0 apaga o HSTS.",
                "Usar max-age de pelo menos 15552000 (seis meses), de preferência 31536000.",
            )
        )
    if "includesubdomains" not in flags:
        findings.append(
            Finding(
                "HA002",
                "HSTS sem includeSubDomains",
                Severity.LOW,
                target,
                "Subdomínios ficam fora da proteção. Um subdomínio em HTTP pode receber cookies "
                "do domínio principal ou servir de ponto de ataque.",
                "Adicionar includeSubDomains depois de confirmar que todo subdomínio tem HTTPS.",
            )
        )
    if "preload" in flags and (
        max_age is None or max_age < ONE_YEAR or "includesubdomains" not in flags
    ):
        findings.append(
            Finding(
                "HA002",
                "HSTS com preload que não se qualifica",
                Severity.INFO,
                target,
                "A diretiva preload está presente, mas a lista de preload exige max-age de um "
                "ano e includeSubDomains. Como está, o domínio não entra na lista.",
                "Completar o header (max-age=31536000; includeSubDomains; preload) ou tirar o "
                "preload.",
            )
        )
    return findings


def _enforced_policies(response: Response) -> list[csp.Policy]:
    return csp.parse_csp(response.headers.get("content-security-policy"))


def ha003_csp_missing(response: Response) -> list[Finding]:
    if _enforced_policies(response):
        return []
    report_only = "content-security-policy-report-only" in response.headers
    extra = (
        " Existe uma Content-Security-Policy-Report-Only, que só registra violações e não "
        "bloqueia nada."
        if report_only
        else ""
    )
    return [
        Finding(
            "HA003",
            "CSP ausente",
            Severity.HIGH,
            "Content-Security-Policy",
            "Sem CSP, um XSS executa qualquer script, de qualquer origem. A CSP é a segunda "
            "barreira quando a validação de entrada falha." + extra,
            "Começar com default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self' em modo Report-Only, ajustar e depois aplicar.",
        )
    ]


def _all(policies: list[csp.Policy], predicate: Callable[[csp.Policy], bool]) -> bool:
    # várias políticas valem ao mesmo tempo: só é fraqueza se todas permitirem
    return all(predicate(p) for p in policies)


def ha004_csp_weak(response: Response) -> list[Finding]:
    policies = _enforced_policies(response)
    if not policies:
        return []
    target = "Content-Security-Policy"
    findings: list[Finding] = []

    def script(p: csp.Policy) -> list[str] | None:
        return csp.sources(p, "script-src")

    if _all(policies, lambda p: script(p) is None):
        findings.append(
            Finding(
                "HA004",
                "CSP não restringe scripts",
                Severity.HIGH,
                target,
                "A política não tem script-src nem default-src, então scripts de qualquer origem "
                "continuam permitidos.",
                "Adicionar default-src 'self' ou um script-src explícito.",
            )
        )
    else:
        if _all(
            policies,
            lambda p: script(p) is not None
            and "'unsafe-inline'" in script(p)
            and not csp.inline_neutralized(script(p)),
        ):
            findings.append(
                Finding(
                    "HA004",
                    "CSP permite script inline",
                    Severity.HIGH,
                    target,
                    "script-src tem 'unsafe-inline' sem nonce nem hash. Um XSS refletido como "
                    "<script>...</script> executa normalmente, e a CSP perde quase todo o "
                    "efeito contra XSS.",
                    "Trocar 'unsafe-inline' por nonce ('nonce-...') ou hash ('sha256-...'). "
                    "Com nonce presente, navegadores CSP2+ ignoram o 'unsafe-inline'.",
                )
            )
        if _all(policies, lambda p: script(p) is not None and "'unsafe-eval'" in script(p)):
            findings.append(
                Finding(
                    "HA004",
                    "CSP permite eval",
                    Severity.MEDIUM,
                    target,
                    "script-src tem 'unsafe-eval': eval(), new Function() e setTimeout com "
                    "string funcionam. Nonce e hash não neutralizam isso.",
                    "Remover 'unsafe-eval'. Se uma biblioteca exigir, avaliar "
                    "'wasm-unsafe-eval' ou trocar a biblioteca.",
                )
            )
        broad = [csp.broad_sources(script(p) or []) for p in policies]
        if all(broad):
            findings.append(
                Finding(
                    "HA004",
                    "CSP aceita script de qualquer host",
                    Severity.MEDIUM,
                    target,
                    f"script-src contém {', '.join(sorted(set(broad[0])))}. Qualquer arquivo "
                    "hospedado em qualquer domínio (inclusive de quem ataca) pode ser carregado.",
                    "Listar os hosts necessários ou usar nonce com 'strict-dynamic'.",
                )
            )

    if _all(policies, lambda p: csp.sources(p, "object-src") != ["'none'"]):
        findings.append(
            Finding(
                "HA004",
                "CSP sem object-src 'none'",
                Severity.MEDIUM,
                target,
                "object-src não é 'none' (nem herdado de default-src). <object> e <embed> "
                "servem para contornar script-src em vários bypasses conhecidos.",
                "Adicionar object-src 'none'.",
            )
        )
    if _all(policies, lambda p: "base-uri" not in p):
        findings.append(
            Finding(
                "HA004",
                "CSP sem base-uri",
                Severity.LOW,
                target,
                "base-uri não herda de default-src. Uma tag <base> injetada redireciona todos "
                "os scripts com caminho relativo para outro host, inclusive os que têm nonce.",
                "Adicionar base-uri 'self' (ou 'none').",
            )
        )
    has_xfo = _xfo_protects(response)
    if has_xfo and _all(policies, lambda p: "frame-ancestors" not in p):
        findings.append(
            Finding(
                "HA004",
                "CSP sem frame-ancestors",
                Severity.INFO,
                target,
                "A proteção contra clickjacking vem só do X-Frame-Options, que funciona, mas "
                "frame-ancestors é o substituto padronizado e permite listar origens.",
                "Adicionar frame-ancestors 'self' (ou 'none') na CSP.",
            )
        )
    return findings


def _xfo_protects(response: Response) -> bool:
    value = (response.headers.get_all("x-frame-options") or [""])[0].strip().lower()
    return value in {"deny", "sameorigin"}


def ha005_clickjacking(response: Response) -> list[Finding]:
    if _xfo_protects(response):
        return []
    if any("frame-ancestors" in p for p in _enforced_policies(response)):
        return []
    xfo = response.headers.get("x-frame-options")
    detail = (
        f" X-Frame-Options: {xfo} não é reconhecido pelos navegadores atuais (ALLOW-FROM foi "
        "abandonado)."
        if xfo
        else ""
    )
    return [
        Finding(
            "HA005",
            "Página pode ser embutida em iframe",
            Severity.MEDIUM,
            "X-Frame-Options",
            "Nem X-Frame-Options nem CSP frame-ancestors. Outro site pode carregar a página num "
            "iframe invisível e induzir cliques (clickjacking)." + detail,
            "Enviar X-Frame-Options: DENY (ou SAMEORIGIN) e frame-ancestors na CSP.",
        )
    ]


def ha006_nosniff(response: Response) -> list[Finding]:
    value = response.headers.get("x-content-type-options")
    if value and value.split(",")[0].strip().lower() == "nosniff":
        return []
    return [
        Finding(
            "HA006",
            "X-Content-Type-Options ausente",
            Severity.MEDIUM,
            "X-Content-Type-Options",
            "Sem nosniff o navegador pode adivinhar o tipo do conteúdo e executar como script "
            "um arquivo enviado por usuário que foi servido como texto ou imagem.",
            "Enviar X-Content-Type-Options: nosniff.",
        )
    ]


REFERRER_TOKENS = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def ha007_referrer_policy(response: Response) -> list[Finding]:
    value = response.headers.get("referrer-policy")
    target = "Referrer-Policy"
    if not value:
        return [
            Finding(
                "HA007",
                "Referrer-Policy ausente",
                Severity.LOW,
                target,
                "Sem o header vale o padrão do navegador. Os atuais usam "
                "strict-origin-when-cross-origin, mas navegadores antigos mandam a URL inteira "
                "(com tokens e IDs da query string) para outros sites.",
                "Enviar Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer).",
            )
        ]
    # com vários valores vale o último que o navegador reconhece
    known = [t.strip().lower() for t in value.split(",") if t.strip().lower() in REFERRER_TOKENS]
    policy = known[-1] if known else None
    if policy == "unsafe-url":
        return [
            Finding(
                "HA007",
                "Referrer-Policy unsafe-url",
                Severity.MEDIUM,
                target,
                "unsafe-url envia a URL completa, com caminho e query string, para qualquer "
                "site, inclusive de HTTPS para HTTP.",
                "Trocar por strict-origin-when-cross-origin.",
            )
        ]
    if policy == "no-referrer-when-downgrade":
        return [
            Finding(
                "HA007",
                "Referrer-Policy vaza URL para outros sites",
                Severity.LOW,
                target,
                "no-referrer-when-downgrade envia a URL completa para qualquer site HTTPS de "
                "terceiros.",
                "Trocar por strict-origin-when-cross-origin.",
            )
        ]
    return []


def ha008_permissions_policy(response: Response) -> list[Finding]:
    if "permissions-policy" in response.headers:
        return []
    return [
        Finding(
            "HA008",
            "Permissions-Policy ausente",
            Severity.LOW,
            "Permissions-Policy",
            "Sem a política, qualquer iframe ou script de terceiro carregado na página pode "
            "pedir câmera, microfone, geolocalização e outras APIs do navegador.",
            "Desligar o que o site não usa, por exemplo: Permissions-Policy: camera=(), "
            "microphone=(), geolocation=().",
        )
    ]


def ha009_coop(response: Response) -> list[Finding]:
    value = (response.headers.get("cross-origin-opener-policy") or "").lower()
    if value.startswith(("same-origin", "noopener-allow-popups")):
        return []
    return [
        Finding(
            "HA009",
            "Cross-Origin-Opener-Policy ausente",
            Severity.LOW,
            "Cross-Origin-Opener-Policy",
            "Uma janela aberta por outro site mantém referência a esta (window.opener) e "
            "compartilha o processo, o que abre espaço para ataques XS-Leaks.",
            "Enviar Cross-Origin-Opener-Policy: same-origin (ou same-origin-allow-popups se "
            "o site depende de popups de login).",
        )
    ]


def ha010_cookies(response: Response) -> list[Finding]:
    findings: list[Finding] = []

    def add(severity: Severity, name: str, title: str, description: str, fix: str) -> None:
        findings.append(Finding("HA010", title, severity, f"cookie {name}", description, fix))

    for cookie in parse_cookies(response.headers.get_all("set-cookie")):
        if cookie.is_deletion:
            continue
        name = cookie.name
        if name.startswith("__Host-") and (
            not cookie.secure or cookie.attr("path") != "/" or cookie.has("domain")
        ):
            add(
                Severity.MEDIUM,
                name,
                "Cookie __Host- fora das regras do prefixo",
                "O prefixo __Host- exige Secure, Path=/ e nenhum Domain. O navegador rejeita "
                "o cookie, então ele não chega a ser gravado.",
                "Definir Secure; Path=/ e remover o atributo Domain.",
            )
            continue
        if name.startswith("__Secure-") and not cookie.secure:
            add(
                Severity.MEDIUM,
                name,
                "Cookie __Secure- sem Secure",
                "O prefixo __Secure- exige o atributo Secure, e o navegador rejeita o cookie.",
                "Adicionar Secure.",
            )
            continue
        if not cookie.secure:
            add(
                Severity.MEDIUM,
                name,
                "Cookie sem Secure",
                "O cookie também é enviado em requisições HTTP, em texto puro, e pode ser lido "
                "por quem estiver no meio da conexão.",
                "Adicionar o atributo Secure.",
            )
        if cookie.looks_like_session and not cookie.http_only:
            add(
                Severity.MEDIUM,
                name,
                "Cookie de sessão sem HttpOnly",
                "O nome indica sessão ou autenticação e o cookie pode ser lido por "
                "document.cookie. Um XSS rouba a sessão.",
                "Adicionar HttpOnly.",
            )
        same_site = cookie.same_site
        if same_site is None:
            add(
                Severity.LOW,
                name,
                "Cookie sem SameSite",
                "Sem SameSite o comportamento depende do navegador (Lax nos atuais, nenhum nos "
                "antigos), e a proteção contra CSRF fica implícita.",
                "Definir SameSite=Lax (ou Strict para cookies de sessão).",
            )
        elif same_site == "none" and not cookie.secure:
            add(
                Severity.MEDIUM,
                name,
                "Cookie SameSite=None sem Secure",
                "Navegadores atuais rejeitam SameSite=None sem Secure; os antigos aceitam e "
                "enviam o cookie em toda requisição cross-site.",
                "Adicionar Secure, ou usar SameSite=Lax se o cookie não precisa ir cross-site.",
            )
    return findings


def ha011_cors(response: Response) -> list[Finding]:
    origin = (response.headers.get_all("access-control-allow-origin") or [""])[0].strip()
    if not origin:
        return []
    credentials = (response.headers.get("access-control-allow-credentials") or "").lower()
    with_credentials = credentials.strip() == "true"
    target = "Access-Control-Allow-Origin"
    if response.cors_probe and origin == response.cors_probe:
        return [
            Finding(
                "HA011",
                "CORS reflete qualquer origem",
                Severity.HIGH if with_credentials else Severity.LOW,
                target,
                f"A requisição foi enviada com Origin: {response.cors_probe} e o servidor "
                "devolveu essa origem no Access-Control-Allow-Origin."
                + (
                    " Com Allow-Credentials: true, qualquer site lê as respostas autenticadas "
                    "do usuário logado."
                    if with_credentials
                    else " Sem credenciais o efeito é o mesmo de '*'."
                ),
                "Comparar o Origin com uma lista fixa de origens permitidas antes de devolvê-lo.",
            )
        ]
    if origin == "*" and with_credentials:
        return [
            Finding(
                "HA011",
                "CORS com '*' e credenciais",
                Severity.MEDIUM,
                target,
                "Access-Control-Allow-Origin: * junto com Allow-Credentials: true. O navegador "
                "recusa essa combinação, então a intenção era liberar credenciais para todos. "
                "É comum o próximo passo ser refletir o Origin, que funciona e expõe tudo.",
                "Listar as origens confiáveis e só então ligar Allow-Credentials.",
            )
        ]
    if origin.lower() == "null":
        return [
            Finding(
                "HA011",
                "CORS libera a origem null",
                Severity.MEDIUM,
                target,
                "A origem null é a de iframes com sandbox e arquivos locais, e qualquer site "
                "consegue gerá-la.",
                "Remover null da lista de origens permitidas.",
            )
        ]
    return []


DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def ha012_disclosure(response: Response) -> list[Finding]:
    findings = []
    for name in DISCLOSURE_HEADERS:
        for value in response.headers.get_all(name):
            if name.startswith("x-aspnet") or VERSION.search(value):
                findings.append(
                    Finding(
                        "HA012",
                        "Versão do software exposta",
                        Severity.LOW,
                        name.title(),
                        f"{name.title()}: {value}. A versão exata facilita cruzar com CVEs "
                        "conhecidas sem precisar sondar o servidor.",
                        "Remover a versão (server_tokens off no nginx, ServerTokens Prod no "
                        "Apache, app.disable('x-powered-by') no Express).",
                    )
                )
    return findings


def ha013_xss_protection(response: Response) -> list[Finding]:
    value = response.headers.get("x-xss-protection")
    if not value or not value.strip().startswith("1"):
        return []
    return [
        Finding(
            "HA013",
            "X-XSS-Protection ligado",
            Severity.INFO,
            "X-XSS-Protection",
            f"X-XSS-Protection: {value}. O filtro XSS foi removido dos navegadores atuais e, "
            "nos antigos, já foi usado para apagar scripts legítimos da página e vazar dados.",
            "Remover o header ou enviar X-XSS-Protection: 0, e confiar na CSP.",
        )
    ]


def ha014_https_redirect(response: Response) -> list[Finding]:
    if response.url and not response.is_https:
        return [
            Finding(
                "HA014",
                "Site servido sem HTTPS",
                Severity.HIGH,
                response.url,
                "A resposta final veio por HTTP. Tudo, inclusive cookies e senhas, trafega em "
                "texto puro, e nenhum header de segurança é confiável porque pode ser alterado "
                "no caminho.",
                "Servir o site por HTTPS e redirecionar todo acesso http:// com 301.",
            )
        ]
    if response.http_to_https is False:
        return [
            Finding(
                "HA014",
                "HTTP não redireciona para HTTPS",
                Severity.HIGH,
                "http://",
                "A versão http:// do site responde sem levar para https://. Quem digita o "
                "endereço sem https fica em texto puro.",
                "Responder toda requisição http:// com 301 para a mesma URL em https://.",
            )
        ]
    return []


ALL_CHECKS: tuple[tuple[str, Check], ...] = (
    ("HA001", ha001_hsts_missing),
    ("HA002", ha002_hsts_weak),
    ("HA003", ha003_csp_missing),
    ("HA004", ha004_csp_weak),
    ("HA005", ha005_clickjacking),
    ("HA006", ha006_nosniff),
    ("HA007", ha007_referrer_policy),
    ("HA008", ha008_permissions_policy),
    ("HA009", ha009_coop),
    ("HA010", ha010_cookies),
    ("HA011", ha011_cors),
    ("HA012", ha012_disclosure),
    ("HA013", ha013_xss_protection),
    ("HA014", ha014_https_redirect),
)
CHECK_IDS = frozenset(rule_id for rule_id, _ in ALL_CHECKS)


def run_checks(response: Response, ignore: Iterable[str] = ()) -> list[Finding]:
    """Roda as verificações, mais grave primeiro."""
    skipped = {rule_id.upper() for rule_id in ignore}
    findings: list[Finding] = []
    for rule_id, check in ALL_CHECKS:
        if rule_id not in skipped:
            findings.extend(check(response))
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.target))
