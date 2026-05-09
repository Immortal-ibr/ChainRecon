"""Backward-compatible import shim for ``chainrecon.plugins``."""

from importlib import import_module
import sys

_TARGET = import_module("chainrecon.plugins")
globals().update(_TARGET.__dict__)
sys.modules[__name__] = _TARGET
