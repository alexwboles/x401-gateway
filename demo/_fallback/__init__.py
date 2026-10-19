"""Minimal reference fallback for the sibling ``x401`` / ``wallet`` packages.

Used ONLY when the real packages (built by parallel tracks) are not importable.
``demo/_compat.py`` prefers the real packages whenever they exist. Every module here
implements the documented API surface the demo/tests were coded against; anything
marked "fallback-only extra" is not part of that contract.
"""
