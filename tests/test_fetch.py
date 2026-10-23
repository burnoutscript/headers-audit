import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headers_audit.checks import run_checks
from headers_audit.fetch import (
    PROBE_ORIGIN,
    FetchError,
    fetch,
    follow,
    normalize_url,
    redirects_to_https,
)

ROUTES = {
    "/": (200, [("X-Frame-Options", "DENY")]),
    "/antigo": (301, [("Location", "/meio")]),
    "/meio": (302, [("Location", "/")]),
    "/loop": (302, [("Location", "/loop")]),
    "/seguro": (301, [("Location", "https://127.0.0.1:1/seguro")]),
    "/proibido": (403, [("X-Powered-By", "PHP/8.1.2")]),
    "/cors": (200, [("Access-Control-Allow-Credentials", "true")]),
}


class Handler(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def do_GET(self):
        Handler.seen.append(dict(self.headers))
        status, headers = ROUTES.get(self.path, (404, []))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if self.path == "/cors":
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        self.send_header("Set-Cookie", "a=1; Secure; SameSite=Lax")
        self.send_header("Set-Cookie", "b=2; Secure; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_segue_cadeia_de_redirecionamento(server):
    hops = follow(f"{server}/antigo", timeout=5)
    assert [h.status for h in hops] == [301, 302, 200]
    assert hops[-1].url == f"{server}/"
    assert hops[-1].headers.get("x-frame-options") == "DENY"


def test_varios_set_cookie_chegam_separados(server):
    hops = follow(f"{server}/", timeout=5)
    assert hops[-1].headers.get_all("set-cookie") == [
        "a=1; Secure; SameSite=Lax",
        "b=2; Secure; SameSite=Lax",
    ]


def test_loop_de_redirecionamento_e_erro(server):
    with pytest.raises(FetchError):
        follow(f"{server}/loop", timeout=5)


def test_resposta_de_erro_ainda_e_auditada(server):
    hops = follow(f"{server}/proibido", timeout=5)
    assert hops[-1].status == 403
    assert hops[-1].headers.get("x-powered-by") == "PHP/8.1.2"


def test_http_que_leva_para_https(server):
    # para no primeiro Location https, sem tentar conectar na porta 1
    assert redirects_to_https(f"{server}/seguro", timeout=5) is True


def test_http_que_fica_em_http(server):
    assert redirects_to_https(f"{server}/antigo", timeout=5) is False


def test_envia_user_agent_e_origin(server):
    Handler.seen.clear()
    follow(f"{server}/", timeout=5, user_agent="teste/1.0")
    assert Handler.seen[0]["User-Agent"] == "teste/1.0"
    assert Handler.seen[0]["Origin"] == PROBE_ORIGIN


def test_fetch_em_http_aponta_site_sem_https(server):
    response = fetch(f"{server}/antigo", timeout=5)
    assert response.http_to_https is False
    assert response.chain[0].endswith("/antigo")
    assert "HA014" in {f.rule_id for f in run_checks(response)}


def test_cors_refletido_e_detectado(server):
    response = fetch(f"{server}/cors", timeout=5)
    [finding] = [f for f in run_checks(response) if f.rule_id == "HA011"]
    assert finding.title == "CORS reflete qualquer origem"


def test_porta_fechada_e_erro():
    with pytest.raises(FetchError):
        follow("http://127.0.0.1:1/", timeout=2)


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com/"
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
