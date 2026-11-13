"""Compatibility shim.

All real metadata lives in ``pyproject.toml``. This one-line ``setup.py`` only
exists so that older versions of pip (before PEP 660 editable support in pip
21.3) can still run ``pip install -e .``. Modern pip ignores it and uses
``pyproject.toml`` directly.
"""

from setuptools import setup

setup()
