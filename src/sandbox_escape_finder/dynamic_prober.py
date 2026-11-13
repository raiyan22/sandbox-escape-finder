"""The dynamic prober: run the payload corpus and compare with the static side.

For each payload it produces one report row combining:
  * the STATIC verdict  -- did the static analyzer flag this payload?
  * the DYNAMIC result  -- did it compile, execute, and did the oracle confirm
                           an escape?
  * timing.

The comparison between the static flag and the real escape is the deliverable's
centrepiece (the required false-positive / false-negative analysis), so the
prober also offers :meth:`analyze` to summarise it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from random import Random
from typing import Any, Callable, Iterable

from .config import Config
from .payloads import build_corpus
from .static_analyzer import StaticAnalyzer


class DynamicProber:
    """Runs payloads against a sandbox and judges escapes with an oracle.

    ``sandbox_exec`` and ``oracle`` are injected (dependency injection) so the
    test suite can swap in a deliberately-broken toy sandbox in-process. The
    default *production* path, :meth:`run`, ignores them in favour of an
    isolated subprocess running real RestrictedPython; the injected pair is
    used by the in-process path (:meth:`run` with ``isolate=False``), which is
    what the oracle-correctness test drives.
    """

    def __init__(
        self,
        sandbox_exec: Callable | None = None,
        oracle: Callable | None = None,
        config: Config | dict | None = None,
        static_analyzer: StaticAnalyzer | None = None,
    ) -> None:
        self.sandbox_exec = sandbox_exec
        self.oracle = oracle
        self.config = config if isinstance(config, Config) else Config.from_dict(config)
        self.analyzer = static_analyzer or StaticAnalyzer(self.config)

    # -- public API --------------------------------------------------------

    def run(self, payload_corpus: Iterable | None = None, isolate: bool = True) -> list[dict[str, Any]]:
        """Probe every payload and return a list of report rows.

        ``payload_corpus`` may be ``None`` (use the built-in corpus plus any
        ``config.extra_payloads``) or an iterable of payloads, where each is
        either a raw code string or a ``{"code", "technique", ...}`` dict.
        """
        corpus = self._normalise(payload_corpus)

        # Reproducible ordering: shuffle with the configured seed so a run is
        # deterministic yet not biased by corpus authoring order.
        Random(self.config.seed).shuffle(corpus)

        report: list[dict[str, Any]] = []
        # One throwaway directory for the whole run; a per-payload canary file
        # inside it. Nothing here is ever a real system path.
        with tempfile.TemporaryDirectory(prefix="sef_canary_") as tmp:
            for i, payload in enumerate(corpus):
                canary = os.path.join(tmp, f"canary_{i}.txt")
                report.append(self._probe_one(payload, canary, isolate))
        return report

    def analyze(self, report: list[dict]) -> dict[str, Any]:
        """Summarise the static-vs-dynamic comparison (FP / FN analysis)."""
        flagged_no_escape = [r for r in report if r["static_flagged"] and not r["escaped"]]
        escaped_not_flagged = [r for r in report if r["escaped"] and not r["static_flagged"]]
        return {
            "total": len(report),
            "statically_flagged": sum(r["static_flagged"] for r in report),
            "executed": sum(r["executed"] for r in report),
            "escaped": sum(r["escaped"] for r in report),
            # "false positive" HERE = flagged as an attempt but did not escape
            # the real sandbox (usually because RestrictedPython blocked it).
            "flagged_but_no_escape": [r["id"] for r in flagged_no_escape],
            # "false negative" = actually escaped but the analyzer missed it.
            "escaped_but_not_flagged": [r["id"] for r in escaped_not_flagged],
        }

    # -- internals ---------------------------------------------------------

    def _normalise(self, payload_corpus: Iterable | None) -> list[dict]:
        """Turn whatever the caller passed into a uniform list of payload dicts."""
        if payload_corpus is None:
            return build_corpus(self.config.extra_payloads)
        out: list[dict] = []
        for i, p in enumerate(payload_corpus):
            if isinstance(p, str):
                out.append({"id": f"payload_{i}", "technique": "unknown",
                            "source": "caller", "code": p, "note": ""})
            else:
                out.append(dict(p))
        return out

    def _probe_one(self, payload: dict, canary: str, isolate: bool) -> dict[str, Any]:
        """Run a single payload and build its report row."""
        code = payload["code"]

        # STATIC side: scan the source and record what the analyzer thinks.
        findings = self.analyzer.scan(code)
        static_techniques = sorted({f["technique"] for f in findings})

        # DYNAMIC side: time the run.
        start = time.perf_counter()
        if isolate:
            dyn = self._run_isolated(code, canary)
        else:
            dyn = self._run_in_process(code, canary)
        seconds = time.perf_counter() - start

        return {
            "id": payload.get("id", "?"),
            "technique": payload.get("technique", "unknown"),
            "source": payload.get("source", "?"),
            "note": payload.get("note", ""),
            "static_flagged": bool(findings),
            "static_techniques": static_techniques,
            "compiled": dyn["compiled"],
            "executed": dyn["executed"],
            "escaped": dyn["escaped"],
            "error": dyn["error"],
            "seconds": round(seconds, 4),
        }

    def _run_isolated(self, code: str, canary: str) -> dict[str, Any]:
        """Run one payload in a child process (the production path)."""
        # Put the package's parent dir (src/) on the child's import path so it
        # can import sandbox_escape_finder even before an editable install.
        pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ)
        env["PYTHONPATH"] = pkg_parent + os.pathsep + env.get("PYTHONPATH", "")

        proc = subprocess.Popen(
            [sys.executable, "-m", "sandbox_escape_finder._worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True,
        )
        request = json.dumps({"code": code, "canary": canary})
        try:
            out, err = proc.communicate(request, timeout=self.config.exec_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return {"compiled": None, "executed": False, "escaped": False,
                    "error": "timeout"}

        if not out.strip():
            # The worker died before answering (e.g. hard crash); surface it.
            return {"compiled": None, "executed": False, "escaped": False,
                    "error": f"worker-crash: {err.strip()[:200]}"}
        return json.loads(out)

    def _run_in_process(self, code: str, canary: str) -> dict[str, Any]:
        """Run one payload in-process with the injected sandbox and oracle.

        Used by tests (including the toy-broken-sandbox oracle test). Requires
        both ``sandbox_exec`` and ``oracle`` to have been provided.
        """
        if self.sandbox_exec is None or self.oracle is None:
            raise ValueError("in-process mode needs sandbox_exec and oracle injected")
        pre = self.oracle.snapshot()
        result = self.sandbox_exec(code)
        post = self.oracle.snapshot()
        escaped = self.oracle(pre, result, post)
        return {"compiled": result.compiled, "executed": result.executed,
                "escaped": bool(escaped), "error": result.error}
