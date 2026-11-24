<!-- Public front door for the AlgoVoi Keystone (L2). Becomes README.md in the
public repo. -->

# AlgoVoi Keystone (L2): compose agentic-trust chains, verify them offline


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

**One command proves an agentic-action keystone chain composes end to end.**

Everyone has receipts. The keystone is the *composition*: the proof that identity
binds to authority binds to policy binds to the decision binds to the execution
binds to one trust verdict, every link a content address, recomputable offline,
with no issuer contact.

```bash
keystone verify chain.json
# KEYSTONE VALID: 7/7 links compose, recompute byte-for-byte, no issuer contact.
```

RFC 8785 JCS + SHA-256 is the whole dependency. Tamper any link and that link,
and every link that binds it, diverge.

---

## The two-layer model (and why it matters)

- **L1, the substrate.** RFC 8785 JCS canonicalization + SHA-256:
  `ref = "sha256:" + SHA-256(JCS(object))`. It maps a concrete object to canonical
  bytes to a content address. It is closed and total: it knows nothing about
  chains, links, or aliases. Its conformance corpus is 45 anchor sets / 374
  vectors, cross-validated across 10 independent language implementations.
- **L2, the keystone (this repo).** Chain composition and binding. A downstream
  link refers to an upstream link by an `@name` alias, so its content address
  cannot be computed without the exact upstream address.

The design decision this framework is built on: **usability lives one layer above
integrity.** Aliases, composition, and assertions are L2 concerns; L1 stays a
clean canonicalizer. See [`SUBSTRATE-CLEAN-ALIAS-LAYERING.md`](SUBSTRATE-CLEAN-ALIAS-LAYERING.md)
for the full proof.

## What additionality this brings

1. **Composition proof, not just receipt-checking.** A plain receipt checker
   recomputes individual digests. The keystone recomputes the whole chain and
   proves it *binds* into one recomputable sequence, capped by one verdict.
2. **Alias usability with zero substrate cost.** Authors write `@issuer`, not a
   71-character hash. Because L2 resolves aliases to concrete references *before*
   L1 canonicalizes, the substrate needs no alias rule and no alias vector.
   Adding an alias adds **zero** L1 and **zero** L2 vectors: the specification
   cost is a sum (`V` corpus vectors + `R` grammar rules), not a product
   (`V x alias-vocabulary x positions`, which would be thousands of alias-variant
   mutations).
3. **Integrity is never contaminated by usability.** The `@@` escape guarantees
   honest data that begins with `@` (handles, some DIDs) can never be silently
   swapped for a link; an unknown `@name` fails closed (error, not text). So the
   hashed preimage is always exactly what the author wrote.
4. **A bounded, well-defined forgery surface.** Because L1 is alias-free, the
   adversarial mutation-forgery fuzzer attacks one surface (canonical bytes of
   concrete objects): 634 seeded forgeries, 0 escapes in the latest run.
5. **Offline, zero-trust verification.** No issuer contact, no network. The whole
   dependency is RFC 8785 JCS + SHA-256 (+ Ed25519 for the sealed evidence chain).
6. **Cross-implementation, not "trust my tests."** Python and Node verifiers
   cross-verify byte-for-byte; the L1 corpus is agreed across 10 languages.

## Install

```bash
# Python
pip install -e python/            # or: pip install algovoi-keystone

# Node
cd node && npm install
```

Runtime dependency is just an RFC 8785 JCS implementation and SHA-256.

## Quickstart: verify a chain

A chain is an ordered list of content-addressed links. Each link's reference is
`"sha256:" + SHA-256(RFC 8785 JCS(preimage))`.

```python
from algovoi_keystone import verify_chain

chain = {
  "chain": [
    {"name": "passport",  "preimage": {"agent_id": "agent-A", "issuer": "did:algo:issuer"}},
    {"name": "mandate",   "preimage": {"grantor": "@passport", "max_amount": 100}},
    {"name": "decision",  "preimage": {"under": "@mandate", "verdict": "ALLOW"}}
  ]
}
r = verify_chain(chain)
print(r.ok, r.capped, [(l.name, l.computed) for l in r.links])
```

`@passport` and `@mandate` resolve to the earlier links' `sha256:...` references,
so `decision` cannot be computed without the exact upstream bytes. Tamper any
upstream preimage and `decision` diverges.

CLI + Node twin:

```bash
python -m algovoi_keystone.cli verify chain.json    # or: keystone verify chain.json
node node/keystone.mjs verify chain.json             # identical output, byte-for-byte
```

## The alias grammar (L2 composition)

| syntax | meaning |
|---|---|
| `@name` | resolve to the earlier link `name`'s reference; recorded as a binding |
| `@@name` | the literal string `@name`; binds nothing (the escape) |
| `@` not leading | ordinary data, untouched (e.g. `support@shop.example`) |
| `@name` with no earlier link | error, fail closed (never treated as text) |

The escape is what keeps L1 clean: `@@acme` and `@acme` produce **different**
references, so honest `@`-data is never mistaken for a link.

## Integrating into the L2 Keystone framework

1. **Model your flow as links.** Each step (identity, authority, policy, decision,
   execution, verdict) is a link with a `preimage` object. Keep preimages minimal
   and concrete.
2. **Bind steps with `@name`.** A downstream preimage references an upstream link
   by its name. This is what makes the chain *compose* rather than sit as
   independent receipts.
3. **Add assertions** (optional) to prove relational properties the hashes alone
   do not. Supported kinds:
   - `scope_subset` — an inner scope never widened an outer scope.
   - `field_equals` — two link fields match (e.g. delegate continuity).
   - `time_within` — an action fell inside a validity window.
   - `not_revoked` — an execution happened before a revocation (with cascade to
     downstream authority derived from a revoked grant).
   - `journey` — one `journey_ref` covers every hop of a multi-agent task; an
     omitted hop fails.
4. **Cap the chain** with a final link that aggregates the others (a
   `trust_query_ref` / `journey_ref`); verifying the cap proves the whole chain.
5. **Verify offline** with `verify_chain` (library), the CLI, or the Node twin.
   Exit 0 = composes, 1 = a link is broken, 2 = malformed chain.

Worked examples live in [`examples/`](examples/): `keystone-golden.json`,
`delegation-golden.json` (+ the broken variants), `journey-golden.json`,
`revocation-golden.json`, and `alias-escape.json` (the grammar).

## Verify it yourself (the proof is a clone)

```bash
# 1. the L1/L2 alias-layering pack (both verifier twins + the separation proof)
python evidence/alias-l2-layering/prove.py
# -> ALIAS L2-LAYERING PACK: ALL GREEN

# 2. the full conformance gate (both twins, byte-for-byte)
python conformance/run.py
node   conformance/run.mjs
# -> ... alias grammar 4/4; journey; revocation ... [Node == Python]
```

The AlgoVoi conformance corpus (L1) and its offline-verifiable, hash-chained
evidence (the Keystone Assurance Framework) live in the
`algovoi-jcs-conformance-vectors` repo: 45 anchor sets / 374 vectors, 10-language
cross-validation, and an Ed25519-sealed receipt chain you re-verify offline with
`kaf_verify` (no trust in us).

## What is in this repo

| path | what |
|---|---|
| `python/`, `node/` | the L2 keystone verifier, two independent implementations |
| `conformance/` | the self-test gate (`run.py` + `run.mjs`), Python == Node |
| `examples/` | golden + broken chains, the alias grammar, journey, revocation |
| `evidence/alias-l2-layering/` | one-command proof of the L1/L2 separation |
| `SUBSTRATE-CLEAN-ALIAS-LAYERING.md` | the design proof (aliases are L2, not L1 mutations) |

## License

Apache-2.0. Redistribution requires the `NOTICE` attribution (Apache-2.0 4(d)).
