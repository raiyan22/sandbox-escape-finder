"""Subprocess worker: run ONE payload against real RestrictedPython, isolated.

The dynamic prober launches this module as a separate process
(``python -m sandbox_escape_finder._worker``) once per payload. Running in a
child process is the isolation boundary the task requires: if a payload really
escapes and does something destructive, it does so inside this short-lived
child with its canary pointed at a throwaway temp path -- the parent test
runner is never in the blast radius.

Protocol: the parent writes one JSON object to our stdin
(``{"code": ..., "canary": ...}``) and reads one JSON object from our stdout
(``{"compiled", "executed", "escaped", "error"}``). The escape verdict is
computed *here*, because the oracle's object-leak check needs the live Python
objects the payload produced, and those cannot be serialised back to the
parent.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    # Local imports so an import error is reported as JSON, not a raw crash.
    from .oracle import CanaryOracle
    from .sandbox import make_restricted_exec

    request = json.loads(sys.stdin.read())
    code: str = request["code"]
    canary: str = request["canary"]

    # Build the REAL, unmodified RestrictedPython sandbox. The only extra we
    # inject is CANARY -- a plain path string the payload may use as its write
    # target. Handing over a string does not weaken the cage: the payload still
    # has to defeat the sandbox to obtain a way to write that path.
    sandbox_exec = make_restricted_exec(extra_globals={"CANARY": canary})
    oracle = CanaryOracle(canary)

    pre = oracle.snapshot()
    result = sandbox_exec(code)
    post = oracle.snapshot()
    escaped = oracle(pre, result, post)

    out = {
        "compiled": result.compiled,
        "executed": result.executed,
        "escaped": bool(escaped),
        "error": result.error,
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
