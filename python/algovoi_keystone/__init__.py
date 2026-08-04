"""algovoi-keystone: verify that an agentic-action keystone chain composes end to end.

Public API:
    from algovoi_keystone import verify_chain, ChainResult, KeystoneError
"""
from .verify import (
    AssertionResult,
    ChainResult,
    KeystoneError,
    LinkResult,
    scope_contains,
    verify_chain,
)

__all__ = [
    "verify_chain", "ChainResult", "LinkResult", "AssertionResult",
    "scope_contains", "KeystoneError",
]
__version__ = "0.1.0"
