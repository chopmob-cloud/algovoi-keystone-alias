#!/usr/bin/env python3
"""One-command proof for the L1/L2 alias-layering evidence pack.

Run from the repo root:

    python evidence/alias-l2-layering/prove.py

It proves, offline and from source, that:
  1. The keystone conformance gate passes in BOTH twins (Python and Node), which
     includes the alias grammar (4/4), journey, and revocation.
  2. L2 resolves an @marker to a concrete reference BEFORE L1 canonicalizes, so
     the substrate never sees an alias (the marker is gone from the object L1
     hashes), and L1's reference of the resolved object equals the declared ref.
  3. The @@ escape ref diverges from the @ resolve ref (honest @-data can never
     be silently swapped for a link), and an unknown @name fails closed.

Exit 0 iff every check passes. Node parity is reported; if node is absent the
Python conformance gate alone still proves the grammar (the twins are identical).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]   # repo root
sys.path.insert(0, str(ROOT / "python"))
from algovoi_keystone.verify import verify_chain, _resolve, _ref, KeystoneError  # noqa: E402

fails: list[str] = []


def _run(cmd: list[str], label: str) -> None:
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    except Exception as e:  # noqa: BLE001
        fails.append(f"{label}: could not run ({e})")
        return
    ok = p.returncode == 0
    tail = (p.stdout.strip().splitlines() or ["<no output>"])[-1]
    print(f"  [{'ok ' if ok else 'BAD'}] {label}")
    print(f"        {tail}")
    if not ok:
        fails.append(f"{label}: exit {p.returncode}")


print("== 1. conformance gate, both twins ==")
_run([sys.executable, "conformance/run.py"], "python conformance/run.py")
node = shutil.which("node")
if node:
    _run([node, "conformance/run.mjs"], "node conformance/run.mjs")
else:
    print("  [--] node not found; skipping Node twin (Python gate is identical)")

print("\n== 2. L1 never sees an alias (resolve, then canonicalize) ==")
doc = json.loads((ROOT / "examples" / "alias-escape.json").read_text(encoding="utf-8"))
res = next(c for c in doc["cases"] if c["name"] == "alias-resolves-and-binds")
esc = next(c for c in doc["cases"] if c["name"] == "escaped-literal-collides-with-link-name")
acme_ref = res["expect"]["refs"]["acmecorp"]
resolved = _resolve({"author": "@acmecorp", "body": "hello"}, {"acmecorp": acme_ref}, "post")
marker_survives = "@acmecorp" in json.dumps(resolved)
ref_matches = _ref(resolved) == res["expect"]["refs"]["post"]
print(f"  resolved object handed to L1: {resolved}")
print(f"  [{'ok ' if not marker_survives else 'BAD'}] @marker gone before L1 canonicalizes")
print(f"  [{'ok ' if ref_matches else 'BAD'}] L1 _ref(resolved) == declared post ref")
if marker_survives:
    fails.append("alias marker survived into L1")
if not ref_matches:
    fails.append("L1 ref of resolved object != declared ref")

print("\n== 3. @@ escape diverges from @ resolve; unknown alias fails closed ==")
diverge = esc["expect"]["refs"]["post"] != res["expect"]["refs"]["post"]
print(f"  @@ escape  post ref: {esc['expect']['refs']['post']}")
print(f"  @  resolve post ref: {res['expect']['refs']['post']}")
print(f"  [{'ok ' if diverge else 'BAD'}] escape ref != resolve ref")
if not diverge:
    fails.append("@@ escape ref equals @ resolve ref")
unk = next(c for c in doc["cases"] if c["name"] == "unknown-alias-rejected")
try:
    verify_chain({"chain": unk["chain"]})
    fails.append("unknown alias did not fail closed")
    print("  [BAD] unknown alias did not raise")
except KeystoneError as e:
    print(f"  [ok ] unknown alias fails closed: {e}")

print("\n" + ("ALIAS L2-LAYERING PACK: ALL GREEN" if not fails
             else "ALIAS L2-LAYERING PACK: FAILED\n  - " + "\n  - ".join(fails)))
sys.exit(1 if fails else 0)
