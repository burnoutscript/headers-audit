"""Interface de linha de comando do headers-audit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import CHECK_IDS, run_checks
from .fetch import USER_AGENT, FetchError, fetch, parse_dump
from .model import Response
from .report import to_json, to_markdown, to_terminal
from .scoring import GRADE_ORDER, grade_for, meets, score

EXIT_OK = 0
EXIT_BELOW = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers-audit",
        description="Audita headers de segurança HTTP e cookies de uma URL e dá uma nota.",
        epilog="Exemplo: headers-audit https://meusite.com.br --min-grade A",
    )
    parser.add_argument("url", nargs="?", help="URL a auditar (sem esquema, assume https://)")
    parser.add_argument(
        "--from-file",
        type=Path,
        metavar="ARQUIVO",
        help="lê um dump de headers (curl -sIL) em vez de acessar a rede ('-' para stdin)",
    )
    parser.add_argument(
        "--url",
        dest="dump_url",
        metavar="URL",
        help="com --from-file: URL de onde veio o dump, para avaliar o redirecionamento",
    )
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "markdown"),
        default="terminal",
        help="formato da saída (padrão: terminal)",
    )
    parser.add_argument("-o", "--output", type=Path, help="grava o relatório em arquivo")
    parser.add_argument(
        "--min-grade",
        choices=list(reversed(GRADE_ORDER)),
        default="B",
        help="nota mínima para sair com código 0 (padrão: B)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        help="verificações a ignorar, separadas por vírgula ou repetindo (ex.: HA008,HA009)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="timeout por requisição em segundos"
    )
    parser.add_argument("--user-agent", default=USER_AGENT, help="User-Agent enviado")
    parser.add_argument("--no-color", action="store_true", help="desliga cores no terminal")
    parser.add_argument("--version", action="version", version=f"headers-audit {__version__}")
    return parser


def load_response(args: argparse.Namespace) -> tuple[Response, str]:
    if args.from_file and args.url:
        raise ValueError("use a URL ou --from-file, não os dois")
    if args.from_file:
        if str(args.from_file) == "-":
            text = sys.stdin.read()
        elif not args.from_file.exists():
            raise FileNotFoundError(f"arquivo não encontrado: {args.from_file}")
        else:
            text = args.from_file.read_text(encoding="utf-8", errors="replace")
        return parse_dump(text, args.dump_url), str(args.from_file)
    if not args.url:
        raise ValueError("informe uma URL ou --from-file")
    response = fetch(args.url, timeout=args.timeout, user_agent=args.user_agent)
    return response, response.chain[0]


def main(argv: list[str] | None = None) -> int:
    # console do Windows usa cp1252 e quebra os acentos
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    ignore = [r.strip().upper() for item in args.ignore for r in item.split(",") if r.strip()]

    unknown = set(ignore) - CHECK_IDS
    if unknown:
        print(
            f"erro: verificação desconhecida em --ignore: {', '.join(sorted(unknown))}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        response, source = load_response(args)
    except (FileNotFoundError, PermissionError, ValueError, FetchError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = run_checks(response, ignore)

    if args.format == "json":
        output = to_json(response, findings, source)
    elif args.format == "markdown":
        output = to_markdown(response, findings, source)
    else:
        output = to_terminal(response, findings, source, color=not args.no_color)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Relatório gravado em {args.output}")
    else:
        print(output)

    return EXIT_OK if meets(grade_for(score(findings)), args.min_grade) else EXIT_BELOW


if __name__ == "__main__":
    raise SystemExit(main())
