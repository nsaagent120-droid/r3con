#!/usr/bin/env python3
"""Shim for backwards compatibility - use pyproject.toml."""
from setuptools import setup

# All metadata is in pyproject.toml
# This file exists for pip install -e . compatibility with older tooling
if __name__ == "__main__":
    setup()
