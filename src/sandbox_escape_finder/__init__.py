"""SandboxEscapeFinder: static + dynamic detection of Python sandbox escapes.

Public API (matches the task specification)::

    from sandbox_escape_finder import StaticAnalyzer, DynamicProber

    analyzer = StaticAnalyzer(config)
    findings = analyzer.scan(source_code)

    prober = DynamicProber(sandbox_exec, oracle, config)
    report = prober.run(payload_corpus)
"""

from .config import KNOWN_TECHNIQUES, Config
from .dynamic_prober import DynamicProber
from .oracle import CanaryOracle
from .payloads import BUILTIN_CORPUS, build_corpus
from .sandbox import SandboxResult, make_restricted_exec
from .static_analyzer import StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
    "DynamicProber",
    "CanaryOracle",
    "make_restricted_exec",
    "SandboxResult",
    "Config",
    "KNOWN_TECHNIQUES",
    "build_corpus",
    "BUILTIN_CORPUS",
]

__version__ = "0.1.0"
