"""Minimal import shim for pure helper tests when GenVM SDK is absent.

Live linting and deployment use the real SDK. These tests exercise bounded
normalization helpers only, so a tiny shim keeps local CI useful on a clean
machine without pretending to emulate GenVM.
"""
import sys
import types


if "genlayer" not in sys.modules:
    gl = types.SimpleNamespace()
    gl.public = types.SimpleNamespace(view=lambda f: f, write=lambda f: f)
    gl.Contract = object
    gl.message = types.SimpleNamespace(sender_address="0x0")
    gl.block = types.SimpleNamespace(timestamp=0)
    gl.eq_principle = types.SimpleNamespace(prompt_comparative=lambda f, **kwargs: f())
    gl.llm = types.SimpleNamespace(infer=lambda prompt: {})
    gl.require = lambda condition, message: None
    package = types.ModuleType("genlayer")
    package.gl = gl
    package.Address = str
    package.TreeMap = dict
    package.DynArray = list
    package.allow_storage = lambda cls: cls
    package.u256 = int
    sys.modules["genlayer"] = package
    sys.modules["genlayer.gl"] = gl
