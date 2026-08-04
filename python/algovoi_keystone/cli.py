"""`keystone verify <chain.json>` -- one command to prove a keystone chain composes.

Exit code 0 if the whole chain recomputes and composes; 1 if any link is broken or
declared reference mismatches; 2 on a malformed chain.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .verify import KeystoneError, verify_chain

_USAGE = "usage: keystone verify <chain.json>"


def _verify(path: str) -> int:
    try:
        chain = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        r = verify_chain(chain)
    except KeystoneError as exc:
        print(f"error: malformed keystone chain: {exc}", file=sys.stderr)
        return 2

    arrow = "  ->  "
    print("keystone chain:", arrow.join(l.name for l in r.links))
    print("-" * 60)
    for l in r.links:
        mark = "OK  " if l.ok else "BAD "
        binds = f"  binds {', '.join(l.binds)}" if l.binds else ""
        print(f"  {mark}{l.name}")
        print(f"      {l.computed}{binds}")
        if not l.ok:
            print(f"      ^ {l.detail}")
    if r.assertions:
        print("assertions:")
        for a in r.assertions:
            print(f"  {'OK  ' if a.ok else 'BAD '}{a.kind}" + ("" if a.ok else f": {a.detail}"))
    print("-" * 60)

    if r.ok:
        n = len(r.links)
        extra = ""
        if r.assertions:
            kinds = sorted({a.kind for a in r.assertions})
            extra = " + " + ", ".join(k.replace("_", "-") for k in kinds) + " hold"
        print(f"KEYSTONE VALID: {n}/{n} links compose, recompute byte-for-byte, no issuer contact{extra}.")
        if r.capped:
            print(f"  capped: {r.cap} is one verdict over [{', '.join(r.cap_covers)}] in order.")
        return 0

    bad = r.first_broken
    if bad is not None:
        print(f"KEYSTONE BROKEN at {bad.name}: {bad.detail or 'reference mismatch'}.")
        print("  every link that binds it is therefore not provable from these bytes.")
    else:
        fa = r.failed_assertion
        print(f"KEYSTONE BROKEN: {fa.kind} failed -- {fa.detail}.")
        print("  the chain recomputes, but it does not prove what it claims (e.g. scope widened, or out of window).")
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(_USAGE)
        return 0 if argv else 2
    if argv[0] == "verify":
        if len(argv) != 2:
            print(_USAGE, file=sys.stderr)
            return 2
        return _verify(argv[1])
    print(f"error: unknown command '{argv[0]}'\n{_USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
