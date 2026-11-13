# SandboxEscapeFinder

A small program-analysis toolbox that evaluates the robustness of a Python
execution sandbox. It has two halves:

1. **`StaticAnalyzer`** — parses Python source into an AST and flags code that
   looks like a known sandbox-escape technique, **without running it**.
2. **`DynamicProber`** — runs a corpus of real escape payloads against a live,
   unmodified [`RestrictedPython`](https://github.com/zopefoundation/RestrictedPython)
   sandbox inside an **isolated subprocess**, and uses an automated **oracle**
   to decide which payloads actually escaped.

It then compares the two: what was *flagged* versus what actually *escaped*
(the false-positive / false-negative analysis).

> This is a defensive-security research tool. All dynamic payloads run against a
> local sandbox instance inside a subprocess, with any write target pointed at a
> throwaway temp path — a genuine escape cannot affect the host.

## Installation

```bash
pip install -e .          # core
pip install -e ".[dev]"   # core + pytest
```

Requires Python ≥ 3.10. The only runtime dependency is `RestrictedPython==8.5`.

## Usage

```python
from sandbox_escape_finder import StaticAnalyzer, DynamicProber

# --- Static side ---
analyzer = StaticAnalyzer(config={"min_confidence": 0.0})
findings = analyzer.scan("().__class__.__bases__[0].__subclasses__()")
# -> [{'technique': 'subclasses_traversal', 'lineno': 1, 'col_offset': 0,
#      'snippet': '().__class__', 'confidence': 0.8, ...}, ...]

# --- Dynamic side (real RestrictedPython, isolated subprocesses) ---
prober = DynamicProber(config={"seed": 1})
report = prober.run()                 # uses the built-in attributed corpus
summary = prober.analyze(report)      # the FP/FN comparison
```

Run the full demo:

```bash
python examples/quickstart.py
```

## The six technique classes detected

| Technique | Fingerprint | Example |
|---|---|---|
| `subclasses_traversal` | `.__class__`, `.__bases__`, `.__mro__`, `.__subclasses__` | `().__class__.__bases__[0].__subclasses__()` |
| `globals_closure_access` | `.__globals__`, `.__closure__`, `.cell_contents` | `(lambda:0).__globals__['__builtins__']` |
| `builtins_restoration` | `__builtins__`, `__import__`, `eval`, `exec` | `__builtins__['open']('/etc/passwd')` |
| `frame_introspection` | `.__code__`, `.gi_frame`, `.f_globals`, `.f_builtins`, `sys._getframe` | `sys._getframe(0).f_builtins` |
| `format_string_attribute` | `"{0.__class__}".format(obj)` | attribute walk hidden inside a format string |
| `import_usage` | `import`, `from ... import` | `import os; os.system(...)` |

Detection is **AST-based, not regex**: the analyzer matches the *structure* of
the code, so `__class__` inside a comment or string literal is correctly
ignored, and nested chains are walked in full.

## The oracle

The oracle is an automated callable `(pre_state, exec_result, post_state) ->
bool`. It confirms an escape on either of two independent signals:

- **Canary file** — the payload reached the filesystem and created/modified a
  canary file (tracked by existence + mtime + SHA-256) at a throwaway path a
  caged program could never touch.
- **Leaked object** — the payload handed back a forbidden reference: a module
  such as `os`, a callable from a forbidden module, the real `open`, or the
  genuine `__builtins__` dict.

Its correctness is verified against a deliberately-broken toy sandbox fixture
(`tests/test_oracle.py`): that sandbox leaks `open`, a payload escapes, and the
oracle must return `True`. This proves "0 escapes against real RestrictedPython"
is a genuine result, not a silent always-`False` oracle.

## Results

Running the built-in 13-payload corpus against real, unmodified
**RestrictedPython 8.5** (`python examples/quickstart.py`):

| Payload | Technique | Statically flagged | Executed | Escaped |
|---|---|:--:|:--:|:--:|
| subclasses_catch_warnings | subclasses_traversal | ✅ | ❌ | ❌ |
| subclasses_mro | subclasses_traversal | ✅ | ❌ | ❌ |
| getattr_by_string | subclasses_traversal | ✅ | ❌ | ❌ |
| lambda_globals_open | globals_closure_access | ✅ | ❌ | ❌ |
| closure_cell_contents | globals_closure_access | ✅ | ❌ | ❌ |
| builtins_dict_open | builtins_restoration | ✅ | ❌ | ❌ |
| builtins_import_os | builtins_restoration | ✅ | ❌ | ❌ |
| eval_recovery | builtins_restoration | ✅ | ❌ | ❌ |
| frame_getframe_builtins | frame_introspection | ✅ | ❌ | ❌ |
| frame_code_globals | frame_introspection | ✅ | ❌ | ❌ |
| format_class_walk | format_string_attribute | ✅ | ❌ | ❌ |
| format_globals_read | format_string_attribute | ✅ | ❌ | ❌ |
| import_os_system | import_usage | ✅ | ❌ | ❌ |

**13 flagged, 0 executed cleanly, 0 escaped, 0 false negatives.**

### Why RestrictedPython blocks every payload

Four distinct defenses, observed empirically from the recorded errors:

1. **Compile-time underscore rule** — any attribute name starting with `_` is
   rejected by `compile_restricted` (*"`__class__` is an invalid attribute name
   because it starts with `_`"*). Stops every technique that needs a dunder
   written in the source.
2. **A named-restricted-name blocklist** — e.g. `f_builtins` is *"a restricted
   name, forbidden to access"*.
3. **A runtime guard disabling `str.format`** — the format-string payloads
   *compile* (their dunders hide inside a string) but raise at runtime (*"Using
   the format*() methods of str is not safe"*). This is the one technique the
   underscore rule cannot catch, so RestrictedPython closes it with a dedicated
   guard.
4. **A trimmed `__builtins__`** — `import os` raises *"`__import__` not found"*;
   `eval`/`open` are absent.

### Interpreting the false-positive / false-negative comparison

Every statically-flagged payload is, from the escape point of view, a "false
positive" — flagged as an *attempt* but it did not escape. This is expected and
correct: the static analyzer flags **intent**, the dynamic prober measures
**success**, and the gap between them is exactly the sandbox's defenses. There
are **no false negatives** (nothing escaped that the analyzer failed to flag).

## Running the tests

```bash
pytest
```

30 tests: AST detector positive/negative snippets, oracle correctness against a
broken toy sandbox, and an end-to-end corpus run against RestrictedPython.

## Project layout

```
sandbox_escape_finder/
├── src/sandbox_escape_finder/
│   ├── __init__.py          # public API
│   ├── config.py            # config schema + validation
│   ├── static_analyzer.py   # AST-based detector
│   ├── sandbox.py           # faithful RestrictedPython wrapper
│   ├── oracle.py            # automated escape oracle (canary + object leak)
│   ├── payloads.py          # attributed payload corpus
│   ├── dynamic_prober.py    # runs corpus, compares static vs dynamic
│   └── _worker.py           # subprocess worker (isolation boundary)
├── tests/
├── examples/quickstart.py
├── pyproject.toml
└── README.md
```

## Configuration

All behaviour is data-driven via a `dict` / JSON `config`:

| Key | Meaning | Default |
|---|---|---|
| `enabled_techniques` | which detectors are active | all six |
| `min_confidence` | drop findings below this (0–1) | `0.0` |
| `extra_payloads` | add `{code, technique}` payloads to the corpus | `[]` |
| `seed` | reproducible payload ordering | `0` |
| `exec_timeout` | seconds per payload before the subprocess is killed | `5.0` |
