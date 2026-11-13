"""The escape oracle: an *automated* judge of whether a payload broke out.

The task forbids "manual inspection": a human eyeballing output does not scale
and is not reproducible. So the oracle is a plain callable with the signature
the task fixes::

    oracle(pre_state, exec_result, post_state) -> bool

It returns ``True`` when it has objective evidence of an out-of-sandbox effect.

We judge an escape on two independent kinds of evidence, because an escape can
show up in two different ways:

1. **A real-world side effect** -- the payload reached the filesystem and
   wrote/modified a *canary* file that a properly caged program could never
   touch. The canary lives at a throwaway path; its appearance or change
   between the before/after snapshots is proof.

2. **A leaked forbidden object** -- the payload did not touch the disk but
   handed back a reference it should never have, e.g. the ``os`` module, the
   real ``open`` builtin, or the genuine ``__builtins__`` dict. We inspect the
   value the payload produced and recognise these.

Either kind of evidence is sufficient; we OR them together.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

# If a leaked object belongs to one of these modules, the cage was defeated.
_FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {"os", "nt", "posix", "subprocess", "sys", "builtins", "importlib", "ctypes"}
)
# Builtin names that must never be reachable from inside the sandbox.
_FORBIDDEN_BUILTIN_NAMES: frozenset[str] = frozenset(
    {"open", "eval", "exec", "__import__", "compile", "input"}
)


class CanaryOracle:
    """A callable oracle built around one canary file path.

    The path must point somewhere disposable (the dynamic prober creates it in
    a fresh temp directory). The oracle never writes the canary itself -- only
    an *escaping payload* can, which is the entire point.
    """

    def __init__(self, canary_path: str) -> None:
        self.canary_path = canary_path

    # -- state capture -----------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Record the canary's observable state at a moment in time.

        The prober calls this once *before* a payload runs and once *after*.
        We capture existence, modification time and a content hash so we can
        detect both "created" and "modified in place" escapes.
        """
        try:
            st = os.stat(self.canary_path)
        except FileNotFoundError:
            return {"exists": False, "mtime": None, "sha256": None}
        with open(self.canary_path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        return {"exists": True, "mtime": st.st_mtime_ns, "sha256": digest}

    # -- the oracle decision ----------------------------------------------

    def __call__(self, pre_state: dict, exec_result: Any, post_state: dict) -> bool:
        """Return True if there is objective evidence of an escape."""
        return self._canary_changed(pre_state, post_state) or self._result_leaks(
            exec_result
        )

    # -- evidence tests ----------------------------------------------------

    @staticmethod
    def _canary_changed(pre: dict, post: dict) -> bool:
        """Did the canary get created or modified while the payload ran?"""
        if not pre.get("exists") and post.get("exists"):
            return True  # created out of nothing -> filesystem escape
        if pre.get("exists") and post.get("exists"):
            # Existed before and after: changed content or timestamp = write.
            if pre.get("sha256") != post.get("sha256"):
                return True
            if pre.get("mtime") != post.get("mtime"):
                return True
        return False

    @classmethod
    def _result_leaks(cls, exec_result: Any) -> bool:
        """Inspect the payload's produced value for a forbidden reference.

        ``exec_result`` is a SandboxResult from our wrapper. We look at the
        ``value`` the payload stored in ``result`` and at everything left in
        its namespace, and ask: is any of it something the cage should have
        kept out of reach?
        """
        candidates: list[Any] = []
        value = getattr(exec_result, "value", None)
        if value is not None:
            candidates.append(value)
        namespace = getattr(exec_result, "namespace", None)
        if isinstance(namespace, dict):
            candidates.extend(namespace.values())

        return any(cls._is_forbidden(obj) for obj in candidates)

    @classmethod
    def _is_forbidden(cls, obj: Any) -> bool:
        """True if a single object is one the sandbox should never surrender."""
        # A module object (os, sys, subprocess, ...).
        if getattr(obj, "__class__", None).__name__ == "module":
            name = getattr(obj, "__name__", "")
            if name.split(".")[0] in _FORBIDDEN_MODULES:
                return True

        # A function/builtin that lives in a forbidden module, e.g. os.system.
        mod = getattr(obj, "__module__", None)
        if isinstance(mod, str) and mod.split(".")[0] in _FORBIDDEN_MODULES:
            if callable(obj):
                return True

        # A forbidden builtin recovered by name, e.g. the real `open`.
        name = getattr(obj, "__name__", None)
        if name in _FORBIDDEN_BUILTIN_NAMES and callable(obj):
            return True

        # The genuine __builtins__ dict (not RestrictedPython's trimmed one):
        # it is the real one if it still carries dangerous names.
        if isinstance(obj, dict) and {"open", "eval", "__import__"} & set(obj):
            return True

        return False
