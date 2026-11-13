"""Static (no-execution) detection of Python sandbox-escape techniques.

We parse the source into an Abstract Syntax Tree (AST) and walk every node,
looking for the structural fingerprints of known escape techniques. This is
deliberately AST-based, not a regex over the raw text: a regex cannot tell the
difference between the string ``"__class__"`` in a comment and a real attribute
access ``obj.__class__``, and it is blind to how expressions nest. The AST
knows exactly what each piece of code *is*.
"""

from __future__ import annotations

import ast
from typing import Any

from .config import Config

# Attribute names that, when accessed, indicate a particular technique.
# We map each suspicious dunder/name to the technique it belongs to.
_ATTR_SIGNATURES: dict[str, str] = {
    "__class__": "subclasses_traversal",
    "__bases__": "subclasses_traversal",
    "__mro__": "subclasses_traversal",
    "__subclasses__": "subclasses_traversal",
    "__subclasshook__": "subclasses_traversal",
    "__globals__": "globals_closure_access",
    "__closure__": "globals_closure_access",
    "cell_contents": "globals_closure_access",
    "__builtins__": "builtins_restoration",
    "__import__": "builtins_restoration",
    "__code__": "frame_introspection",
    "gi_frame": "frame_introspection",
    "f_back": "frame_introspection",
    "f_globals": "frame_introspection",
    "f_locals": "frame_introspection",
    "f_builtins": "frame_introspection",
    "gi_code": "frame_introspection",
}

# Bare names (not attribute access) that signal a technique on their own.
_NAME_SIGNATURES: dict[str, str] = {
    "__import__": "builtins_restoration",
    "__builtins__": "builtins_restoration",
    "eval": "builtins_restoration",
    "exec": "builtins_restoration",
}


class StaticAnalyzer(ast.NodeVisitor):
    """Scans Python source and returns a list of suspected-escape findings.

    Usage::

        analyzer = StaticAnalyzer(config)
        findings = analyzer.scan(source_code)

    Each finding is a dict with: ``technique``, ``node`` (the AST node type),
    ``lineno``/``col_offset`` (source location), ``snippet`` (the offending
    source text) and ``confidence`` (0..1).
    """

    def __init__(self, config: Config | dict | None = None) -> None:
        # Accept either an already-built Config or a raw dict, for convenience.
        self.config = config if isinstance(config, Config) else Config.from_dict(config)
        self._findings: list[dict[str, Any]] = []
        self._source: str = ""

    # -- public API --------------------------------------------------------

    def scan(self, source_code: str) -> list[dict[str, Any]]:
        """Parse ``source_code`` and return the list of findings."""
        self._findings = []
        self._source = source_code
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            # Unparseable source is itself suspicious (some payloads are
            # intentionally weird). Report it rather than crashing.
            self._add("syntax_error", exc, confidence=0.3,
                      extra={"message": str(exc)})
            return self._filter(self._findings)

        self.visit(tree)  # walks the whole tree, calling our visit_* methods
        return self._filter(self._findings)

    # -- AST visitor hooks -------------------------------------------------

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Called for every ``something.attr`` in the code."""
        technique = _ATTR_SIGNATURES.get(node.attr)
        if technique:
            # A dunder attribute access is a strong signal.
            self._add(technique, node, confidence=0.8)
        self.generic_visit(node)  # keep descending into child nodes

    def visit_Name(self, node: ast.Name) -> None:
        """Called for every bare identifier, e.g. ``eval`` or ``x``."""
        technique = _NAME_SIGNATURES.get(node.id)
        if technique:
            self._add(technique, node, confidence=0.6)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Called for ``import os`` style statements."""
        self._add("import_usage", node, confidence=0.9,
                  extra={"names": [a.name for a in node.names]})
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Called for ``from os import system`` style statements."""
        self._add("import_usage", node, confidence=0.9,
                  extra={"module": node.module})
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Called for every function call ``f(...)``.

        We special-case two things here:
        * ``getattr(obj, "__class__")`` -- escapes often use getattr to fetch a
          dunder by string, sidestepping a literal ``.`` attribute access.
        * ``"...{0.__class__}...".format(...)`` -- the format-string technique,
          where the attribute walk hides inside a format spec string.
        """
        func = node.func

        # getattr(x, "<dunder>")
        if isinstance(func, ast.Name) and func.id == "getattr" and node.args:
            second = node.args[1] if len(node.args) > 1 else None
            if isinstance(second, ast.Constant) and isinstance(second.value, str):
                technique = _ATTR_SIGNATURES.get(second.value)
                if technique:
                    self._add(technique, node, confidence=0.7,
                              extra={"via": "getattr"})

        # "<fmt>".format(...) where <fmt> reaches an attribute
        if isinstance(func, ast.Attribute) and func.attr == "format":
            if isinstance(func.value, ast.Constant) and isinstance(func.value.value, str):
                if self._format_reaches_attribute(func.value.value):
                    self._add("format_string_attribute", node, confidence=0.75)

        self.generic_visit(node)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _format_reaches_attribute(fmt: str) -> bool:
        """True if a format string contains a field like ``{0.__class__}``.

        We reuse the standard library's own format parser so we match Python's
        real rules rather than guessing with string search.
        """
        import string

        try:
            fields = list(string.Formatter().parse(fmt))
        except ValueError:
            return False
        for _literal, field_name, _spec, _conv in fields:
            # field_name is e.g. "0.__class__" -> attribute access present.
            if field_name and "." in field_name:
                return True
        return False

    def _add(self, technique: str, node: Any, confidence: float,
             extra: dict | None = None) -> None:
        """Record one finding, honouring the enabled-technique filter."""
        if technique not in self.config.enabled_techniques and technique != "syntax_error":
            return
        lineno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        finding = {
            "technique": technique,
            "node": type(node).__name__,
            "lineno": lineno,
            "col_offset": col,
            "snippet": self._snippet_for(node),
            "confidence": round(confidence, 3),
        }
        if extra:
            finding.update(extra)
        self._findings.append(finding)

    def _snippet_for(self, node: Any) -> str:
        """Best-effort source text for a node, for human-readable findings."""
        try:
            return ast.get_source_segment(self._source, node) or ""
        except Exception:
            return ""

    def _filter(self, findings: list[dict]) -> list[dict]:
        """Drop findings under the configured confidence floor."""
        return [f for f in findings if f["confidence"] >= self.config.min_confidence]
