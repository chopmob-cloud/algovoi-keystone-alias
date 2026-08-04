# L1/L2 alias-layering evidence pack

This pack proves one claim, offline and from source: **the AlgoVoi keystone (L2)
delivers alias usability without adding any alias rule to the canonicalization
substrate (L1), and without the thousands of alias-variant vectors an alias-aware
substrate would need.**

The design write-up is [`../../SUBSTRATE-CLEAN-ALIAS-LAYERING.md`](../../SUBSTRATE-CLEAN-ALIAS-LAYERING.md).
The narrative version is the show-and-tell post
`platform/drafts/keystone-alias-layering-show-and-tell.md`.

## One command

From the repo root:

```bash
python evidence/alias-l2-layering/prove.py
```

Expected tail:

```
ALIAS L2-LAYERING PACK: ALL GREEN
```

It runs three things:

1. **The conformance gate in both twins.** `python conformance/run.py` and
   `node conformance/run.mjs` both PASS, and both agree byte-for-byte
   (`[Node == Python]`). The gate includes the alias grammar (4/4), journey, and
   revocation.
2. **L1 never sees an alias.** For `author: "@acmecorp"`, L2's `_resolve` hands L1
   the concrete object `{'author': 'sha256:238ff…', 'body': 'hello'}`; the
   `@`-marker is gone before L1 canonicalizes, and L1's reference of the resolved
   object equals the declared reference.
3. **The `@@` escape is real, and unknown aliases fail closed.** The `@@`-escape
   reference diverges from the `@`-resolve reference (so honest `@`-data can never
   be silently swapped for a link), and an unescaped `@name` with no matching
   earlier link raises rather than degrading into a literal.

## What proves what

| claim | evidence in this repo |
|---|---|
| L2 resolves aliases before L1 canonicalizes | `python/algovoi_keystone/verify.py` (`_resolve` then `_ref`), `node/keystone.mjs` twin |
| the substrate carries no alias rule or vector | the corpus (`algovoi-jcs-conformance-vectors`), 49 run sets, none referencing an alias |
| the grammar is correct and cross-implementation | `examples/alias-escape.json` + `conformance/run.py` / `run.mjs` section 4, Python == Node |
| the vector count is additive, not multiplicative | the counting argument in `SUBSTRATE-CLEAN-ALIAS-LAYERING.md` |
| aliases in L2 keep the forgery surface bounded | KAF P4 strata blast (3897 forgeries, 0 escapes) in the corpus repo |

## Files

- `prove.py` — the one-command proof above.
- `README.md` — this index.

Everything the proof needs is already in the repo; there is nothing to install
beyond the keystone's own dependency (RFC 8785 JCS + SHA-256) and, for the Node
twin, `node`.
