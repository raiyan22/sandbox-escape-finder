"""A thin, faithful wrapper around RestrictedPython's documented setup.

This module does exactly one thing: take a string of Python source, compile it
with RestrictedPython's ``compile_restricted`` and run it inside the
restricted namespace that RestrictedPython's own documentation prescribes.

We deliberately do **not** add our own protections on top. The task is to
evaluate *RestrictedPython as it ships*, so the wrapper must be an honest
mirror of the library's recommended usage -- nothing more, nothing less.
Anything stricter would make the sandbox look safer than it really is;
anything looser would blame RestrictedPython for a hole we opened ourselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
from RestrictedPython.Guards import (
    full_write_guard,
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
    safer_getattr,
)
from RestrictedPython.PrintCollector import PrintCollector


@dataclass
class SandboxResult:
    """Outcome of trying to compile+run one payload in the sandbox.

    We keep *every* stage separate instead of returning a bare value, because
    the dynamic prober and the oracle need to tell these cases apart:
      * blocked at compile time (RestrictedPython refused the syntax),
      * blocked at run time (raised inside the cage),
      * ran cleanly (and then: what did it produce?).
    """

    compiled: bool = False          # did compile_restricted accept the source?
    executed: bool = False          # did exec run without raising?
    error: str | None = None        # the compile/runtime error text, if any
    value: Any = None               # the payload's `result` variable, if set
    namespace: dict = field(default_factory=dict)  # the restricted locals


def _build_restricted_globals(extra_globals: dict | None = None) -> dict:
    """Assemble the globals dict RestrictedPython's docs tell you to use.

    ``safe_globals`` on its own only supplies a locked-down ``__builtins__``.
    To run anything beyond trivial expressions you must also install the
    guard hooks that RestrictedPython injects calls to during compilation
    (``_getattr_``, ``_getitem_``, ``_write_`` ...). Each guard is the exact
    one named in the RestrictedPython documentation.
    """
    g: dict[str, Any] = dict(safe_globals)              # start from the safe base
    g["_getattr_"] = safer_getattr                      # attribute reads
    g["_getitem_"] = default_guarded_getitem            # x[i] reads
    g["_getiter_"] = default_guarded_getiter            # for-loop iteration
    g["_write_"] = full_write_guard                     # attribute/item writes
    g["_print_"] = PrintCollector                       # print() capture
    g["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence
    g["_unpack_sequence_"] = guarded_unpack_sequence
    if extra_globals:
        # Used ONLY by tests to build an intentionally-broken toy sandbox.
        # Never used for the real RestrictedPython evaluation.
        g.update(extra_globals)
    return g


def make_restricted_exec(extra_globals: dict | None = None):
    """Return a ``sandbox_exec(code: str) -> SandboxResult`` callable.

    This matches the ``sandbox_exec`` parameter in the task's public API. We
    return a *closure* so the globals are built once and reused for every
    payload in a run, which is both faster and keeps all payloads on an
    identical footing.
    """
    restricted_globals = _build_restricted_globals(extra_globals)

    def sandbox_exec(code: str) -> SandboxResult:
        result = SandboxResult()

        # --- Stage 1: compile under RestrictedPython's rules ---------------
        try:
            byte_code = compile_restricted(code, filename="<sandbox>", mode="exec")
            result.compiled = True
        except SyntaxError as exc:
            # RestrictedPython refused the source (e.g. an underscore
            # attribute name). This is the sandbox doing its job.
            result.error = f"compile-blocked: {exc}"
            return result

        # --- Stage 2: execute inside the restricted namespace --------------
        # Fresh globals copy + empty locals per call, so one payload cannot
        # leave state behind that helps the next one.
        run_globals = dict(restricted_globals)
        local_ns: dict[str, Any] = {}
        try:
            exec(byte_code, run_globals, local_ns)
            result.executed = True
        except BaseException as exc:  # noqa: BLE001 - we must catch everything
            # A payload may raise anything (including odd errors). The sandbox
            # containing the blast is exactly what we want to observe, so we
            # record it rather than letting it propagate.
            result.error = f"runtime-blocked: {type(exc).__name__}: {exc}"
            return result

        # --- Stage 3: surface whatever the payload produced ----------------
        # Convention: payloads store what they recovered in a `result` name,
        # so the oracle can inspect it for leaked forbidden objects.
        result.value = local_ns.get("result")
        result.namespace = local_ns
        return result

    return sandbox_exec
