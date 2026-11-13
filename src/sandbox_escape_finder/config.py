"""Configuration schema and loading for SandboxEscapeFinder.

The whole toolbox is driven by a single ``dict`` (which can come from a JSON
file). Keeping configuration in data -- instead of hard-coded constants spread
through the code -- is one of the task's explicit requirements: it lets a user
turn individual detectors on or off, add their own payloads, and reproduce a
run exactly via the random ``seed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The five (plus one) technique classes the static analyzer knows about.
# Each name is a stable identifier we also use when attributing payloads,
# so the static side and the dynamic side speak the same vocabulary.
KNOWN_TECHNIQUES: tuple[str, ...] = (
    "subclasses_traversal",      # ().__class__.__bases__[0].__subclasses__()
    "globals_closure_access",    # func.__globals__ / func.__closure__
    "builtins_restoration",      # recover __builtins__ / __import__
    "frame_introspection",       # __code__, gi_frame, sys._getframe
    "format_string_attribute",   # "{0.__class__}".format(obj)
    "import_usage",              # bare import / __import__ call
)


@dataclass
class Config:
    """Validated configuration object.

    We accept a plain ``dict`` from the user and convert it into this typed
    object so the rest of the code can rely on the fields existing and having
    the right types, instead of doing ``config.get(...)`` defensively
    everywhere.
    """

    # Which detectors are active. Default: all known techniques.
    enabled_techniques: set[str] = field(
        default_factory=lambda: set(KNOWN_TECHNIQUES)
    )
    # Confidence below this is dropped from the findings list.
    min_confidence: float = 0.0
    # Extra payloads the user wants to add to the corpus, each a dict with
    # keys "code" and "technique". Lets you extend the corpus without editing
    # the source.
    extra_payloads: list[dict[str, str]] = field(default_factory=list)
    # Seed for any randomness (payload shuffling), so runs are reproducible.
    seed: int = 0
    # Seconds a single payload may run in the subprocess before we kill it.
    exec_timeout: float = 5.0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Config":
        """Build a Config from a raw dict, validating as we go.

        Passing ``None`` or ``{}`` gives an all-defaults config, which is what
        the quickstart uses.
        """
        data = dict(data or {})  # copy so we never mutate the caller's dict

        enabled = data.get("enabled_techniques", list(KNOWN_TECHNIQUES))
        enabled_set = set(enabled)
        unknown = enabled_set - set(KNOWN_TECHNIQUES)
        if unknown:
            raise ValueError(f"Unknown technique(s) in config: {sorted(unknown)}")

        min_conf = float(data.get("min_confidence", 0.0))
        if not 0.0 <= min_conf <= 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")

        extra = data.get("extra_payloads", [])
        for p in extra:
            if "code" not in p or "technique" not in p:
                raise ValueError(
                    "each extra_payload needs 'code' and 'technique' keys"
                )

        return cls(
            enabled_techniques=enabled_set,
            min_confidence=min_conf,
            extra_payloads=list(extra),
            seed=int(data.get("seed", 0)),
            exec_timeout=float(data.get("exec_timeout", 5.0)),
        )
