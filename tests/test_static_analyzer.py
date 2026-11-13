"""Unit tests for the static analyzer.

The task requires "AST-detector unit tests with known positive/negative
snippets". For every technique class we assert a positive snippet is flagged
with the right technique name, and we assert benign code is NOT flagged. We
also test the finding metadata (location, confidence) and the config switches.
"""

import pytest

from sandbox_escape_finder import StaticAnalyzer


# (source snippet, expected technique) -- one clear positive per class.
POSITIVE_CASES = [
    ("().__class__.__bases__[0].__subclasses__()", "subclasses_traversal"),
    ("(lambda: 0).__globals__", "globals_closure_access"),
    ("f.__closure__[0].cell_contents", "globals_closure_access"),
    ("__builtins__['open']", "builtins_restoration"),
    ("sys._getframe(0).f_globals", "frame_introspection"),
    ("'{0.__class__}'.format(())", "format_string_attribute"),
    ("import os", "import_usage"),
    ("from os import system", "import_usage"),
    ("getattr((), '__class__')", "subclasses_traversal"),
]

# Benign snippets that must produce ZERO findings (no false alarms).
NEGATIVE_CASES = [
    "x = 1 + 2",
    "def add(a, b):\n    return a + b",
    "result = [i * i for i in range(10)]",
    "name = 'hello world'",
    "total = sum([1, 2, 3])",
    # The word __class__ only inside a STRING/comment must not fire:
    "msg = 'the __class__ attribute'  # talking about __class__",
]


@pytest.mark.parametrize("source, technique", POSITIVE_CASES)
def test_positive_snippets_are_flagged(source, technique):
    """Each known escape snippet is flagged with the expected technique."""
    findings = StaticAnalyzer().scan(source)
    techniques = {f["technique"] for f in findings}
    assert technique in techniques, f"{source!r} should flag {technique}"


@pytest.mark.parametrize("source", NEGATIVE_CASES)
def test_benign_snippets_are_not_flagged(source):
    """Benign code (and dunders inside strings/comments) must NOT be flagged.

    This is the whole reason for using an AST instead of a regex: a text search
    for '__class__' would wrongly flag the last case.
    """
    findings = StaticAnalyzer().scan(source)
    assert findings == [], f"{source!r} wrongly flagged: {findings}"


def test_finding_has_location_and_confidence():
    """Every finding must cite a source location and a confidence (req #1)."""
    findings = StaticAnalyzer().scan("().__class__")
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f["lineno"] == 1
    assert isinstance(f["col_offset"], int)
    assert 0.0 <= f["confidence"] <= 1.0
    assert f["snippet"]  # the offending source text is captured


def test_nested_access_is_fully_walked():
    """A chain of dunder accesses yields a finding for each hop."""
    findings = StaticAnalyzer().scan("().__class__.__bases__")
    # Both __class__ and __bases__ belong to subclasses_traversal.
    assert len(findings) >= 2


def test_config_can_disable_a_technique():
    """Disabling a technique in config suppresses its findings."""
    cfg = {"enabled_techniques": ["globals_closure_access"]}
    findings = StaticAnalyzer(cfg).scan("().__class__.__subclasses__()")
    # subclasses_traversal is disabled, so nothing should come back.
    assert findings == []


def test_min_confidence_filters_findings():
    """Findings below the configured confidence floor are dropped."""
    # 'eval' alone is a 0.6-confidence name signal; floor it out at 0.7.
    low = StaticAnalyzer({"min_confidence": 0.0}).scan("eval")
    high = StaticAnalyzer({"min_confidence": 0.7}).scan("eval")
    assert low and not high


def test_unknown_technique_in_config_raises():
    """A typo'd technique name in config is a configuration error."""
    with pytest.raises(ValueError):
        StaticAnalyzer({"enabled_techniques": ["not_a_real_technique"]})


def test_syntax_error_is_reported_not_crashed():
    """Unparseable source is reported, not raised as an exception."""
    findings = StaticAnalyzer().scan("def (:::")
    assert any(f["technique"] == "syntax_error" for f in findings)
