import pytest

from headers_audit.cookies import parse_cookies, parse_set_cookie
from headers_audit.csp import broad_sources, inline_neutralized, parse_csp, parse_policy, sources
from headers_audit.fetch import parse_dump
from headers_audit.model import Headers


class TestCspParser:
    def test_diretivas_e_fontes(self):
        policy = parse_policy("default-src 'self'; img-src * data:")
        assert policy == {"default-src": ["'self'"], "img-src": ["*", "data:"]}

    def test_maiusculas_espacos_e_ponto_e_virgula_sobrando(self):
        policy = parse_policy("  SCRIPT-SRC   'SELF'  'Unsafe-Inline' ;; ;")
        assert policy == {"script-src": ["'self'", "'unsafe-inline'"]}

    def test_diretiva_repetida_vale_a_primeira(self):
        assert parse_policy("script-src 'self'; script-src *")["script-src"] == ["'self'"]

    def test_valor_do_nonce_preserva_maiusculas(self):
        assert parse_policy("script-src 'NONCE-AbC'")["script-src"] == ["'nonce-AbC'"]

    def test_diretiva_sem_valor(self):
        assert parse_policy("upgrade-insecure-requests")["upgrade-insecure-requests"] == []

    def test_virgula_separa_politicas(self):
        assert len(parse_csp("default-src 'self', script-src 'none'")) == 2
        assert parse_csp("") == [] and parse_csp(None) == []

    def test_fallback_para_default_src(self):
        policy = parse_policy("default-src 'none'; script-src 'self'")
        assert sources(policy, "object-src") == ["'none'"]
        assert sources(policy, "script-src") == ["'self'"]
        assert sources(policy, "base-uri") is None

    def test_neutralizacao_e_fontes_amplas(self):
        assert inline_neutralized(["'sha384-x'", "'unsafe-inline'"])
        assert not inline_neutralized(["'self'", "'unsafe-inline'"])
        assert broad_sources(["'self'", "https:", "*"]) == ["https:", "*"]
        assert broad_sources(["'strict-dynamic'", "https:"]) == []


class TestCookieParser:
    def test_atributos(self):
        cookie = parse_set_cookie("id=a=b; Path=/; HttpOnly; SameSite=Strict; secure")
        assert cookie.name == "id" and cookie.value == "a=b"
        assert cookie.http_only and cookie.secure and cookie.same_site == "strict"
        assert cookie.attr("path") == "/"

    def test_sem_nome_e_ignorado(self):
        assert parse_set_cookie("semigual") is None
        assert parse_set_cookie("=valor") is None

    def test_varios_set_cookie(self):
        headers = Headers(
            [("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"), ("set-cookie", "b=2")]
        )
        cookies = parse_cookies(headers.get_all("Set-Cookie"))
        assert [c.name for c in cookies] == ["a", "b"]
        assert cookies[0].attr("expires") == "Wed, 21 Oct 2026 07:28:00 GMT"

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("PHPSESSID", True),
            ("connect.sid", True),
            ("auth_token", True),
            ("sid", True),
            ("XSRF-TOKEN", False),
            ("tema", False),
            ("considerar", False),
        ],
    )
    def test_nome_de_sessao(self, name, expected):
        assert parse_set_cookie(f"{name}=1").looks_like_session is expected


class TestDump:
    def test_curl_com_varios_saltos(self):
        text = (
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://a.test/\r\n\r\n"
            "HTTP/2 200\r\nx-frame-options: DENY\r\n\r\n"
        )
        resp = parse_dump(text, url="http://a.test/")
        assert resp.status == 200
        assert resp.chain == ["http://a.test/", "https://a.test/"]
        assert resp.http_to_https is True
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_http_sem_redirect(self):
        resp = parse_dump("HTTP/1.1 200 OK\nServer: x\n", url="http://a.test/")
        assert resp.http_to_https is False and not resp.is_https

    def test_sem_url_assume_https_e_avisa(self):
        resp = parse_dump("HTTP/1.1 200 OK\nServer: x\n")
        assert resp.is_https and resp.http_to_https is None
        assert any("--url" in note for note in resp.notes)

    def test_sem_linha_de_status_e_com_corpo(self):
        resp = parse_dump("Server: x\nX-A: 1\n\n<html>Title: oi</html>\n")
        assert len(resp.headers) == 2 and resp.headers.get("title") is None

    def test_pseudo_headers_do_http2_sao_ignorados(self):
        resp = parse_dump(":status: 200\nserver: x\n")
        assert [name for name, _ in resp.headers.items] == ["server"]

    def test_header_repetido_vira_lista(self):
        resp = parse_dump("HTTP/1.1 200 OK\nVary: a\nVary: b\n")
        assert resp.headers.get("vary") == "a, b"

    def test_vazio_e_erro(self):
        with pytest.raises(ValueError):
            parse_dump("\n\n<html></html>")

    def test_nota_de_cors_offline(self):
        resp = parse_dump("Access-Control-Allow-Origin: https://a.test\n")
        assert any("CORS" in note for note in resp.notes)
