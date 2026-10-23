from headers_audit.checks import run_checks
from headers_audit.model import Headers, Response, Severity

STRONG_CSP = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
    "frame-ancestors 'none'"
)
BASE = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": STRONG_CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def response(extra=None, drop=(), cookies=(), **kwargs) -> Response:
    pairs = list(extra.items()) if isinstance(extra, dict) else list(extra or [])
    replaced = {name for name, _ in pairs} | set(drop)
    items = [(k, v) for k, v in BASE.items() if k not in replaced] + pairs
    items += [("Set-Cookie", c) for c in cookies]
    return Response(Headers(items), **kwargs)


def found(resp: Response, rule_id: str):
    return [f for f in run_checks(resp) if f.rule_id == rule_id]


def titles(resp: Response, rule_id: str) -> set[str]:
    return {f.title for f in found(resp, rule_id)}


def test_base_nao_tem_achados():
    assert run_checks(response()) == []


class TestHsts:
    def test_ausente(self):
        assert found(response(drop=["Strict-Transport-Security"]), "HA001")

    def test_ausente_em_http_nao_conta(self):
        # HSTS por HTTP é ignorado pelo navegador; quem aponta é a HA014
        resp = response(drop=["Strict-Transport-Security"], url="http://a.test/")
        assert not found(resp, "HA001")
        assert found(resp, "HA014")

    def test_max_age_curto(self):
        resp = response({"Strict-Transport-Security": "max-age=86400; includeSubDomains"})
        assert titles(resp, "HA002") == {"HSTS com max-age curto"}

    def test_max_age_zero_e_invalido(self):
        for value in ("max-age=0", "max-age=abc", "includeSubDomains"):
            resp = response({"Strict-Transport-Security": value})
            assert "HSTS com max-age curto" in titles(resp, "HA002"), value

    def test_seis_meses_passa(self):
        resp = response({"Strict-Transport-Security": 'max-age="15552000"; includeSubDomains'})
        assert not found(resp, "HA002")

    def test_sem_include_subdomains(self):
        resp = response({"Strict-Transport-Security": "max-age=31536000"})
        assert titles(resp, "HA002") == {"HSTS sem includeSubDomains"}

    def test_preload_inelegivel_e_info(self):
        resp = response({"Strict-Transport-Security": "max-age=31536000; preload"})
        preload = [f for f in found(resp, "HA002") if "preload" in f.title]
        assert preload and preload[0].severity is Severity.INFO

    def test_preload_completo_nao_dispara(self):
        value = "max-age=63072000; includeSubDomains; preload"
        assert not found(response({"Strict-Transport-Security": value}), "HA002")


class TestCsp:
    def test_ausente(self):
        assert found(response(drop=["Content-Security-Policy"]), "HA003")

    def test_report_only_conta_como_ausente(self):
        resp = response(
            {"Content-Security-Policy-Report-Only": STRONG_CSP}, drop=["Content-Security-Policy"]
        )
        [finding] = found(resp, "HA003")
        assert "Report-Only" in finding.description

    def test_unsafe_inline(self):
        csp = STRONG_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")
        resp = response({"Content-Security-Policy": csp})
        assert "CSP permite script inline" in titles(resp, "HA004")

    def test_unsafe_inline_herdado_do_default_src(self):
        csp = "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
        resp = response({"Content-Security-Policy": csp})
        assert "CSP permite script inline" in titles(resp, "HA004")

    def test_unsafe_inline_com_nonce_nao_dispara(self):
        csp = STRONG_CSP.replace("script-src 'self'", "script-src 'nonce-abc' 'unsafe-inline'")
        assert not found(response({"Content-Security-Policy": csp}), "HA004")

    def test_unsafe_inline_com_hash_nao_dispara(self):
        csp = STRONG_CSP.replace("script-src 'self'", "script-src 'sha256-xyz=' 'unsafe-inline'")
        assert not found(response({"Content-Security-Policy": csp}), "HA004")

    def test_unsafe_eval_nao_e_neutralizado_por_nonce(self):
        csp = STRONG_CSP.replace("script-src 'self'", "script-src 'nonce-abc' 'unsafe-eval'")
        assert titles(response({"Content-Security-Policy": csp}), "HA004") == {"CSP permite eval"}

    def test_curinga_e_esquema(self):
        for source in ("*", "https:", "data:"):
            csp = STRONG_CSP.replace("script-src 'self'", f"script-src 'self' {source}")
            resp = response({"Content-Security-Policy": csp})
            assert "CSP aceita script de qualquer host" in titles(resp, "HA004"), source

    def test_host_especifico_nao_e_curinga(self):
        csp = STRONG_CSP.replace("script-src 'self'", "script-src 'self' https://cdn.example.com")
        assert not found(response({"Content-Security-Policy": csp}), "HA004")

    def test_strict_dynamic_ignora_https(self):
        csp = STRONG_CSP.replace(
            "script-src 'self'", "script-src 'nonce-a' 'strict-dynamic' https: 'unsafe-inline'"
        )
        assert not found(response({"Content-Security-Policy": csp}), "HA004")

    def test_sem_script_src_nem_default_src(self):
        csp = "img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        assert titles(response({"Content-Security-Policy": csp}), "HA004") == {
            "CSP não restringe scripts"
        }

    def test_object_src_ausente(self):
        csp = "script-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        assert titles(response({"Content-Security-Policy": csp}), "HA004") == {
            "CSP sem object-src 'none'"
        }

    def test_object_src_herdado_de_default_none(self):
        csp = "default-src 'none'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        assert not found(response({"Content-Security-Policy": csp}), "HA004")

    def test_base_uri_ausente(self):
        csp = STRONG_CSP.replace("base-uri 'self'; ", "")
        assert titles(response({"Content-Security-Policy": csp}), "HA004") == {"CSP sem base-uri"}

    def test_frame_ancestors_ausente_com_xfo_e_info(self):
        csp = STRONG_CSP.replace("; frame-ancestors 'none'", "")
        [finding] = found(response({"Content-Security-Policy": csp}), "HA004")
        assert finding.severity is Severity.INFO

    def test_duas_politicas_basta_uma_restringir(self):
        resp = response(
            [
                ("Content-Security-Policy", STRONG_CSP.replace("'self'", "'self' 'unsafe-inline'")),
                ("Content-Security-Policy", "script-src 'self'"),
            ],
            drop=["Content-Security-Policy"],
        )
        assert "CSP permite script inline" not in titles(resp, "HA004")


class TestClickjacking:
    def test_sem_protecao(self):
        csp = STRONG_CSP.replace("; frame-ancestors 'none'", "")
        resp = response({"Content-Security-Policy": csp}, drop=["X-Frame-Options"])
        assert found(resp, "HA005")

    def test_frame_ancestors_basta(self):
        assert not found(response(drop=["X-Frame-Options"]), "HA005")

    def test_xfo_basta(self):
        resp = response({"Content-Security-Policy": "default-src 'self'"})
        assert not found(resp, "HA005")

    def test_allow_from_nao_protege(self):
        resp = response(
            {"X-Frame-Options": "ALLOW-FROM https://a.test", "Content-Security-Policy": "x 'y'"}
        )
        [finding] = found(resp, "HA005")
        assert "ALLOW-FROM" in finding.description


class TestHeadersSimples:
    def test_nosniff_ausente_ou_errado(self):
        assert found(response(drop=["X-Content-Type-Options"]), "HA006")
        assert found(response({"X-Content-Type-Options": "sniff"}), "HA006")

    def test_nosniff_maiusculo_passa(self):
        assert not found(response({"X-Content-Type-Options": "NoSniff"}), "HA006")

    def test_referrer_ausente_e_baixo(self):
        [finding] = found(response(drop=["Referrer-Policy"]), "HA007")
        assert finding.severity is Severity.LOW

    def test_referrer_unsafe_url_e_medio(self):
        [finding] = found(response({"Referrer-Policy": "unsafe-url"}), "HA007")
        assert finding.severity is Severity.MEDIUM

    def test_referrer_vale_o_ultimo_reconhecido(self):
        assert not found(response({"Referrer-Policy": "unsafe-url, no-referrer"}), "HA007")
        assert found(response({"Referrer-Policy": "no-referrer, unsafe-url"}), "HA007")

    def test_permissions_policy(self):
        assert found(response(drop=["Permissions-Policy"]), "HA008")
        assert not found(response(), "HA008")

    def test_coop(self):
        assert found(response(drop=["Cross-Origin-Opener-Policy"]), "HA009")
        assert found(response({"Cross-Origin-Opener-Policy": "unsafe-none"}), "HA009")
        assert not found(
            response({"Cross-Origin-Opener-Policy": "same-origin-allow-popups"}), "HA009"
        )


class TestCookies:
    def test_cookie_completo_nao_dispara(self):
        cookie = "sessao=1; Secure; HttpOnly; SameSite=Lax; Path=/"
        assert not found(response(cookies=[cookie]), "HA010")

    def test_sem_secure(self):
        assert titles(response(cookies=["tema=1; SameSite=Lax"]), "HA010") == {"Cookie sem Secure"}

    def test_sessao_sem_httponly(self):
        resp = response(cookies=["JSESSIONID=1; Secure; SameSite=Lax"])
        assert titles(resp, "HA010") == {"Cookie de sessão sem HttpOnly"}

    def test_cookie_comum_sem_httponly_nao_dispara(self):
        assert not found(response(cookies=["idioma=pt; Secure; SameSite=Lax"]), "HA010")

    def test_csrf_sem_httponly_nao_dispara(self):
        assert not found(response(cookies=["csrftoken=1; Secure; SameSite=Strict"]), "HA010")

    def test_sem_samesite(self):
        resp = response(cookies=["tema=1; Secure"])
        assert titles(resp, "HA010") == {"Cookie sem SameSite"}

    def test_samesite_none_sem_secure(self):
        resp = response(cookies=["tema=1; SameSite=None"])
        assert "Cookie SameSite=None sem Secure" in titles(resp, "HA010")

    def test_samesite_none_com_secure_passa(self):
        assert not found(response(cookies=["tema=1; Secure; SameSite=None"]), "HA010")

    def test_prefixo_host(self):
        bad = [
            "__Host-a=1; Secure; Path=/app; SameSite=Lax",
            "__Host-b=1; Secure; Path=/; Domain=a.test",
        ]
        assert len(found(response(cookies=bad), "HA010")) == 2
        good = "__Host-c=1; Secure; Path=/; SameSite=Lax"
        assert not found(response(cookies=[good]), "HA010")

    def test_prefixo_secure(self):
        resp = response(cookies=["__Secure-a=1; SameSite=Lax"])
        assert titles(resp, "HA010") == {"Cookie __Secure- sem Secure"}

    def test_cookie_sendo_apagado_e_ignorado(self):
        assert not found(response(cookies=["sessao=; Max-Age=0"]), "HA010")

    def test_varios_cookies_geram_achados_separados(self):
        resp = response(cookies=["a=1; Secure", "b=2; Secure"])
        assert {f.target for f in found(resp, "HA010")} == {"cookie a", "cookie b"}


class TestCors:
    def test_curinga_com_credenciais(self):
        resp = response(
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        )
        assert found(resp, "HA011")

    def test_curinga_sem_credenciais_nao_dispara(self):
        assert not found(response({"Access-Control-Allow-Origin": "*"}), "HA011")

    def test_origem_refletida_com_credenciais_e_alta(self):
        probe = "https://probe.invalid"
        resp = response(
            {"Access-Control-Allow-Origin": probe, "Access-Control-Allow-Credentials": "true"},
            cors_probe=probe,
        )
        [finding] = found(resp, "HA011")
        assert finding.severity is Severity.HIGH

    def test_origem_fixa_nao_dispara(self):
        resp = response(
            {"Access-Control-Allow-Origin": "https://app.test"}, cors_probe="https://probe.invalid"
        )
        assert not found(resp, "HA011")

    def test_origem_null(self):
        assert found(response({"Access-Control-Allow-Origin": "null"}), "HA011")


class TestOutros:
    def test_versao_exposta(self):
        resp = response({"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "Express"})
        assert [f.target for f in found(resp, "HA012")] == ["Server"]

    def test_servidor_sem_versao_nao_dispara(self):
        assert not found(response({"Server": "cloudflare"}), "HA012")

    def test_x_xss_protection_1_e_info(self):
        [finding] = found(response({"X-XSS-Protection": "1; mode=block"}), "HA013")
        assert finding.severity is Severity.INFO

    def test_x_xss_protection_0_nao_dispara(self):
        assert not found(response({"X-XSS-Protection": "0"}), "HA013")

    def test_http_sem_redirect(self):
        assert found(response(http_to_https=False), "HA014")

    def test_redirect_ok_ou_desconhecido_nao_dispara(self):
        assert not found(response(http_to_https=True), "HA014")
        assert not found(response(http_to_https=None), "HA014")

    def test_ignore(self):
        resp = response(drop=["Permissions-Policy", "Cross-Origin-Opener-Policy"])
        assert {f.rule_id for f in run_checks(resp, ignore=["ha008"])} == {"HA009"}
