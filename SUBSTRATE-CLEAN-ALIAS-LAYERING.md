# Keeping the substrate clean: aliases are an L2 concern, not L1 mutations

## The claim

The AlgoVoi trust stack has two layers with a hard boundary between them:

- **L1, the substrate.** RFC 8785 JCS canonicalization plus SHA-256:
  `ref = "sha256:" + SHA-256(JCS(object))`. It maps a concrete object to
  canonical bytes to a content address. It is closed and total: it knows nothing
  about chains, links, bindings, or aliases. Its conformance corpus is the 49
  vector sets (352 entries) in `algovoi-jcs-conformance-vectors`.

- **L2, the keystone.** Chain composition and binding. A downstream link refers
  to an upstream link by an `@name` alias, so its content address cannot be
  computed without the exact upstream address. This is where alias usability
  lives: authors write `@issuer` instead of copying a 71-character
  `sha256:...` by hand.

The claim this document proves: **L2 delivers alias usability without adding a
single alias-aware rule to L1, and without the combinatorial explosion of
alias-variant vectors ("thousands of mutations") that an alias-aware substrate
would require.** The substrate stays clean because L2 resolves every alias to a
concrete reference *before* L1 ever sees the object.

## The mechanism: resolve, then canonicalize

L2 recomputes each link in order. The load-bearing two lines
(`python/algovoi_keystone/verify.py`, the recompute loop):

```python
resolved = _resolve(link["preimage"], refs, name)   # L2: rewrite @markers -> concrete refs
computed = _ref(resolved)                            # L1: JCS + sha256 of a concrete object
```

`_ref` is the entire L1 dependency (`verify.py:30`):

```python
def _ref(obj):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()
```

`_resolve` is the entire L2 alias grammar (`verify.py:34`). It is four rules and
nothing else:

```python
if isinstance(value, str) and value.startswith("@"):
    if value.startswith("@@"):          # (1) escape: '@@name' -> literal '@name', binds nothing
        return value[1:]
    target = value[1:]                  # (2) resolve: '@name' -> refs[name]
    if target not in refs:              # (3) fail-closed: unknown '@name' is an error, never text
        raise KeystoneError(...)
    return refs[target]
if isinstance(value, list):  return [_resolve(v, ...) for v in value]
if isinstance(value, dict):  return {k: _resolve(v, ...) for k, v in value.items()}
return value                            # (4) untouched: non-string, or '@' not leading
```

The Node twin is byte-identical in behavior (`node/keystone.mjs:22` `ref`,
`:27` `resolve`), which is why Python and Node cross-verify.

## The proof that L1 never sees an alias

Run the `alias_escape_v1` cases through the real verifier. For the resolving
case, `author: "@acmecorp"`, L2 hands L1 this concrete object:

```
L2 resolved preimage handed to L1: {'author': 'sha256:238ffde5...437548f3c', 'body': 'hello'}
marker '@' survives into L1?        False        (the substrate never sees a marker)
L1 _ref(resolved) == declared ref:  True
```

The `@acmecorp` marker is gone by the time L1 runs. L1 canonicalizes a plain
object whose fields are ordinary strings. This is exactly the kind of object the
49 L1 vector sets already cover. L1 needs no new rule and no new vector to
support this alias, or any alias.

All four grammar cases reach their declared result:

```
ok  escaped-literal-collides-with-link-name   refs+binds match declared
ok  alias-resolves-and-binds                  refs+binds match declared
ok  at-not-leading-is-untouched               refs+binds match declared
ok  unknown-alias-rejected                    fail-closed: references @nosuchlink
```

## Why this avoids thousands of mutations (the counting argument)

Let `V` be the number of L1 canonical vectors (352), `A` the size of an author's
alias vocabulary (the distinct link names a chain can reference), and `P` the
number of string positions in a preimage where an alias could appear.

**Counterfactual: an alias-aware substrate.** If L1 itself had to understand
`@name`, then correctness would depend on the interaction of every alias, in
every position, with every canonical shape. To specify and test that, the vector
corpus would need alias-variant *mutations* of the base vectors: roughly
`O(V x A x P)`, plus per-vector escape and unknown-alias cases. For `V = 352`, a
modest `A ~ 20`, and a handful of positions, that is on the order of tens of
thousands of alias-variant vectors, and it grows every time anyone introduces a
new link name. That is the "thousands of mutations" this architecture refuses to
pay.

**Actual: the layer split turns the product into a sum.** Because L2 resolves
before L1:

- L1 cost is `V` (352). It is **independent of `A`**. No alias vector exists in
  the L1 corpus, and adding a new alias adds none.
- L2 cost is `R`, the number of grammar rules, tested once by `alias_escape_v1`
  (4 cases for the 4 rules). It is **independent of `V`**: the resolver is proven
  correct on the grammar, not re-proven against every canonical shape, because
  whatever it emits is a concrete object that L1 already handles.

Total specification cost is `V + R` (an addition), not `V x A x P` (a
multiplication). Adding a new alias or link name to a real chain adds **zero**
L1 vectors and **zero** L2 vectors: it is data flowing through a pipeline whose
two halves are each already proven. That is the whole saving.

## The clean-substrate guarantee: the `@@` escape

Keeping aliases out of L1 is only safe if alias syntax can never contaminate
honest data. Domain values legitimately begin with `@` (social handles, some
DIDs). The `@@` escape is what makes the substrate clean rather than merely
alias-free:

- `@@acmecorp` is the literal string `@acmecorp`; it binds nothing, and its
  canonical preimage is exactly what the author wrote.
- `@acmecorp` (single `@`) resolves to the earlier link's reference and is
  reported as a binding.

These two must never collapse to the same bytes, and they do not:

```
@@ escape  post ref: sha256:00c242237153ee62...218d210fd
@  resolve post ref: sha256:2c40d9f03c7cac24...ff71793de
DIVERGE (escape != resolve): True
```

Without the escape, an author whose data happens to equal a link name would have
that data silently replaced by the link's reference, so the hashed preimage would
not be what they wrote, a substrate-level integrity break. The escape confines
the entire `@` convention to L2 and guarantees L1 always hashes the author's
actual bytes. An unescaped `@name` with no matching earlier link is an error, not
text (rule 3), so a broken binding fails closed instead of degrading into a
literal.

## Bonus: it also bounds the adversarial mutation surface (P4)

The KAF P4 strata blast is a *different* sense of "mutation": seeded
mutation-forgery fuzzing that tries to make a tampered object still verify. Its
result was 3897 forgeries, 0 escapes. That bound is only achievable because L1 is
alias-free. If the substrate resolved aliases, every resolution path would be a
new place to forge (swap a marker, collide a name, race the escape), and the
forgery surface would grow with `A`. Keeping aliases in L2 means the P4 fuzzer
attacks one small, well-defined surface (canonical bytes of concrete objects),
which is why it can claim exhaustive zero-escape coverage.

## Reproduce

```
# L2 alias grammar is now part of the standing conformance gate (both twins):
python conformance/run.py     # ... alias grammar 4/4 (@@ escape diverges from @ resolve, unknown alias fails closed)
node   conformance/run.mjs    # ... same, [Node == Python]

# L1 substrate corpus (no alias vectors, by design)
#   every runner in algovoi-jcs-conformance-vectors/vectors/<set>/ is green
#   and none references an alias.
```

## Scope note

`examples/alias-escape.json` fully specifies the grammar with expected references
recomputed by both the Python and Node verifiers, and is now wired into the
standing `conformance/run.py` and `conformance/run.mjs` gate (section 4): all four
cases must reach their declared refs/binds (or fail closed), and the `@@` escape
ref must diverge from the `@` resolve ref, or conformance fails. The grammar it
exercises is the exact code path L2 uses for every chain.
