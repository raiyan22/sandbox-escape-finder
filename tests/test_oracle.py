"""Oracle-correctness tests.

The task requires "an oracle-correctness test using an intentionally-broken toy
sandbox fixture that must be caught". The danger with a safety oracle is that it
silently always returns False -- then every sandbox looks perfect. These tests
prove the oracle fires on a genuine escape and stays quiet otherwise.
"""

import os

import pytest

from sandbox_escape_finder import CanaryOracle, make_restricted_exec
from sandbox_escape_finder.sandbox import SandboxResult


@pytest.fixture
def canary(tmp_path):
    """A disposable canary path inside pytest's per-test temp dir."""
    return str(tmp_path / "canary.txt")


def test_oracle_catches_escape_in_broken_toy_sandbox(canary):
    """A deliberately-broken sandbox that leaks real open() must be caught.

    We build a toy sandbox with the real ``open`` wrongly left in scope. A
    payload that writes the canary then genuinely 'escapes', and the oracle,
    seeing the canary appear, must return True.
    """
    broken = make_restricted_exec(extra_globals={"open": open, "CANARY": canary})
    oracle = CanaryOracle(canary)

    pre = oracle.snapshot()
    result = broken("open(CANARY, 'w').write('pwned')")
    post = oracle.snapshot()

    assert result.executed, f"toy payload should run: {result.error}"
    assert oracle(pre, result, post) is True


def test_oracle_silent_on_harmless_run(canary):
    """A harmless computation in the real sandbox must NOT be flagged."""
    run = make_restricted_exec()
    oracle = CanaryOracle(canary)

    pre = oracle.snapshot()
    result = run("result = 1 + 2")
    post = oracle.snapshot()

    assert oracle(pre, result, post) is False


def test_oracle_catches_leaked_module(canary):
    """Even with no filesystem effect, leaking a forbidden object is an escape."""
    oracle = CanaryOracle(canary)
    # Simulate a payload that returned the os module itself.
    leaked = SandboxResult(compiled=True, executed=True, value=os)
    pre = {"exists": False, "mtime": None, "sha256": None}
    post = {"exists": False, "mtime": None, "sha256": None}
    assert oracle(pre, leaked, post) is True


def test_oracle_catches_leaked_builtin_open(canary):
    """Recovering the real open() builtin counts as a leak."""
    oracle = CanaryOracle(canary)
    leaked = SandboxResult(compiled=True, executed=True, value=open)
    empty = {"exists": False, "mtime": None, "sha256": None}
    assert oracle(empty, leaked, empty) is True


def test_snapshot_detects_modification(canary):
    """snapshot() distinguishes an unchanged file from a modified one."""
    oracle = CanaryOracle(canary)
    with open(canary, "w") as fh:
        fh.write("before")
    pre = oracle.snapshot()
    with open(canary, "w") as fh:
        fh.write("after is different")
    post = oracle.snapshot()
    # Content hash changed -> oracle treats it as an escape-style write.
    assert oracle(pre, SandboxResult(), post) is True
