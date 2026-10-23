import json
from pathlib import Path

import pytest

from headers_audit.checks import run_checks
from headers_audit.cli import EXIT_BELOW, EXIT_ERROR, EXIT_OK, main
from headers_audit.fetch import parse_dump
from headers_audit.model import Finding, Severity
from headers_audit.report import to_markdown, to_terminal
from headers_audit.scoring import grade_for, meets, penalties_by_rule, score

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
WEAK = str(SAMPLES / "site_fraco.txt")
HARDENED = str(SAMPLES / "site_blindado.txt")


def finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(rule_id, "t", severity, "x", "d", "r")


class TestPontuacao:
    def test_pesos_por_severidade(self):
        findings = [
            finding("HA001", Severity.HIGH),
            finding("HA006", Severity.MEDIUM),
            finding("HA008", Severity.LOW),
            finding("HA013", Severity.INFO),
        ]
        assert score(findings) == 100 - 20 - 10 - 5

    def test_teto_por_verificacao(self):
        findings = [finding("HA010", Severity.MEDIUM)] * 6
        assert penalties_by_rule(findings) == {"HA010": 25}
        assert score(findings) == 75

    def test_nunca_negativo(self):
        findings = [finding(f"HA0{i:02d}", Severity.HIGH) for i in range(1, 10)]
        assert score(findings) == 0

    @pytest.mark.parametrize(
        "points,grade",
        [(100, "A+"), (95, "A+"), (94, "A"), (85, "A"), (70, "B"), (69, "C"), (40, "D"), (39, "F")],
    )
    def test_faixas(self, points, grade):
        assert grade_for(points) == grade

    def test_comparacao_de_notas(self):
        assert meets("A+", "B") and meets("B", "B")
        assert not meets("C", "B") and not meets("A", "A+")


class TestExemplos:
    def test_fraco_tira_f_e_sai_com_1(self, capsys):
        assert main(["--from-file", WEAK, "--format", "json"]) == EXIT_BELOW
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["grade"] == "F"
        rules = {f["rule_id"] for f in payload["findings"]}
        assert {"HA002", "HA004", "HA005", "HA010", "HA011", "HA012", "HA013"} <= rules

    def test_blindado_tira_a_mais(self, capsys):
        args = ["--from-file", HARDENED, "--url", "http://app.example.com/", "--no-color"]
        assert main(args) == EXIT_OK
        out = capsys.readouterr().out
        assert "A+" in out and "Nenhum problema" in out


class TestCli:
    def test_min_grade(self):
        assert main(["--from-file", WEAK, "--min-grade", "F"]) == EXIT_OK

    def test_ignore_muda_a_nota(self, tmp_path, capsys):
        dump = tmp_path / "d.txt"
        dump.write_text(
            (SAMPLES / "site_blindado.txt").read_text(encoding="utf-8").replace(
                "x-frame-options: DENY\n", ""
            ).replace("frame-ancestors 'none'; ", ""),
            encoding="utf-8",
        )
        assert main(["--from-file", str(dump), "--min-grade", "A+"]) == EXIT_BELOW
        assert main(["--from-file", str(dump), "--min-grade", "A+", "--ignore", "HA005"]) == EXIT_OK

    def test_ignore_desconhecido_e_erro(self):
        assert main(["--from-file", HARDENED, "--ignore", "HA999"]) == EXIT_ERROR

    def test_arquivo_inexistente_e_erro(self):
        assert main(["--from-file", "nao_existe.txt"]) == EXIT_ERROR

    def test_sem_url_nem_arquivo_e_erro(self):
        assert main([]) == EXIT_ERROR

    def test_url_e_arquivo_juntos_e_erro(self):
        assert main(["https://a.test", "--from-file", HARDENED]) == EXIT_ERROR

    def test_dump_vazio_e_erro(self, tmp_path):
        empty = tmp_path / "vazio.txt"
        empty.write_text("\n", encoding="utf-8")
        assert main(["--from-file", str(empty)]) == EXIT_ERROR

    def test_url_inacessivel_e_erro(self):
        assert main(["http://127.0.0.1:1/", "--timeout", "2"]) == EXIT_ERROR

    def test_grava_em_arquivo(self, tmp_path):
        out = tmp_path / "relatorio.md"
        main(["--from-file", WEAK, "--format", "markdown", "-o", str(out)])
        assert out.read_text(encoding="utf-8").startswith("# Auditoria de headers")


class TestRelatorio:
    def setup_method(self):
        self.response = parse_dump((SAMPLES / "site_fraco.txt").read_text(encoding="utf-8"))
        self.findings = run_checks(self.response)

    def test_terminal_sem_cor_nao_tem_escape_ansi(self):
        assert "\033[" not in to_terminal(self.response, self.findings, "x", color=False)

    def test_notas_aparecem(self):
        out = to_terminal(self.response, self.findings, "x", color=False)
        assert "CORS" in out and "--url" in out

    def test_markdown_tem_tabela_e_nota(self):
        md = to_markdown(self.response, self.findings, "x")
        assert "| Severidade | Regra |" in md
        assert "**Nota:** F (0/100)" in md
