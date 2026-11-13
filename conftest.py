"""Make the ``src/`` layout importable during tests without an install.

Once the package is installed with ``pip install -e .`` this file is not
strictly needed, but keeping it means ``pytest`` works straight from a fresh
checkout, which is friendlier for a reviewer.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
