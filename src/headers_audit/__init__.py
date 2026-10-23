"""headers-audit: auditoria de headers de segurança HTTP e cookies."""

__version__ = "0.1.0"

from .checks import ALL_CHECKS, run_checks  # noqa: E402
from .fetch import fetch, parse_dump  # noqa: E402
from .model import Finding, Headers, Response, Severity  # noqa: E402
from .scoring import grade_for, score  # noqa: E402

__all__ = [
    "ALL_CHECKS",
    "fetch",
    "Finding",
    "grade_for",
    "Headers",
    "parse_dump",
    "Response",
    "run_checks",
    "score",
    "Severity",
    "__version__",
]
