"""Conformance self-test for algovoi-keystone (Python).

Confirms the verifier's behaviour on the canonical and tampered chains, and that
every reference it computes matches the published keystone_v1 composition. Run the
Node twin (run.mjs) against the same examples to prove Python == Node parity.

    python conformance/run.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))
from algovoi_keystone import verify_chain  # noqa: E402
from algovoi_keystone.verify import KeystoneError  # noqa: E402

EX = ROOT / "examples"

# published keystone_v1 references (algovoi-jcs-conformance-vectors)
PUBLISHED = {
    "passport_ref": "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be",
    "mandate_ref": "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35",
    "policy_bound_ref": "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21",
    "decision_ref": "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",
    "execution_ref": "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a",
    "trust_query_ref": "sha256:18fb601a08c71eb6bed11e1c117f33bdc0ada6d635ea9bb9cca15e8410ce7ebd",
}


def main() -> int:
    fails: list[str] = []

    # 1. golden chain is valid, capped, and every link matches the published keystone
    g = verify_chain(json.loads((EX / "keystone-golden.json").read_text(encoding="utf-8")))
    if not g.ok:
        fails.append("golden not valid")
    if not g.capped or g.cap != "trust_query_ref":
        fails.append("golden cap not detected")
    by = {l.name: l.computed for l in g.links}
    for name, ref in PUBLISHED.items():
        if by.get(name) != ref:
            fails.append(f"golden {name} != published")

    # 2. tampered execution breaks at execution_ref AND cascades to the cap that binds it
    b = verify_chain(json.loads((EX / "broken-execution.json").read_text(encoding="utf-8")))
    if b.ok:
        fails.append("broken chain reported valid")
    if not b.first_broken or b.first_broken.name != "execution_ref":
        fails.append(f"broken: first failure should be execution_ref, got {b.first_broken.name if b.first_broken else None}")
    if next(l for l in b.links if l.name == "trust_query_ref").ok:
        fails.append("broken: cap should also fail (it binds execution_ref)")

    # 3. cross-party delegation: golden valid; each negative caught by the right assertion
    cp = verify_chain(json.loads((EX / "delegation-golden.json").read_text(encoding="utf-8")))
    if not cp.ok or not cp.capped:
        fails.append("cross-party golden not valid/capped")
    if [a.kind for a in cp.assertions] != ["field_equals", "field_equals", "scope_subset", "scope_subset", "time_within"]:
        fails.append("cross-party golden assertions wrong shape")
    for fname, want in (("delegation-broken-scope", "scope_subset"),
                        ("delegation-broken-delegate", "field_equals"),
                        ("delegation-broken-expired", "time_within")):
        r = verify_chain(json.loads((EX / f"{fname}.json").read_text(encoding="utf-8")))
        if r.ok:
            fails.append(f"{fname} reported valid")
        elif not r.failed_assertion or r.failed_assertion.kind != want:
            got = r.failed_assertion.kind if r.failed_assertion else None
            fails.append(f"{fname}: expected {want} to fail, got {got}")

    # 4. alias grammar (alias_escape_v1): the L2 @-marker is resolved to a concrete
    #    reference BEFORE L1 canonicalizes, so the substrate never sees a marker.
    #    Each case must reach its declared refs/binds (or fail closed), and the @@
    #    escape must diverge from the @ resolve (else honest '@'-data could be
    #    silently swapped for a link -- a substrate integrity break).
    ax = json.loads((EX / "alias-escape.json").read_text(encoding="utf-8"))
    for case in ax["cases"]:
        exp = case["expect"]
        try:
            r = verify_chain({"chain": case["chain"]})
        except KeystoneError as e:
            if "error_contains" not in exp or exp["error_contains"] not in str(e):
                fails.append(f"alias {case['name']}: unexpected error {e}")
            continue
        if "error_contains" in exp:
            fails.append(f"alias {case['name']}: expected error, got ok")
            continue
        got_refs = {l.name: l.computed for l in r.links}
        got_binds = {l.name: l.binds for l in r.links}
        if got_refs != exp["refs"]:
            fails.append(f"alias {case['name']}: refs != declared")
        if "binds" in exp and got_binds != exp["binds"]:
            fails.append(f"alias {case['name']}: binds != declared")
    esc = next(c for c in ax["cases"] if c["name"] == "escaped-literal-collides-with-link-name")
    res = next(c for c in ax["cases"] if c["name"] == "alias-resolves-and-binds")
    if esc["expect"]["refs"]["post"] == res["expect"]["refs"]["post"]:
        fails.append("alias: @@ escape and @ resolve produce the same ref (escape ineffective)")

    # 5. multi-agent journey: one journey_ref binds every hop A->B->C; golden composes,
    #    and an omitted hop is caught by the journey assertion (not silently uncovered).
    jg = verify_chain(json.loads((EX / "journey-golden.json").read_text(encoding="utf-8")))
    if not jg.ok:
        fails.append("journey-golden not valid")
    jb = verify_chain(json.loads((EX / "journey-broken.json").read_text(encoding="utf-8")))
    if jb.ok or not jb.failed_assertion or jb.failed_assertion.kind != "journey":
        fails.append("journey-broken: expected a journey assertion failure")

    # 6. cross-party revocation: golden valid; execution at/after a revocation is caught
    #    by not_revoked; a cascade (downstream authority derived from a revoked upstream
    #    grant) is caught too; a revoker that is not the grantor is caught by field_equals.
    rg = verify_chain(json.loads((EX / "revocation-golden.json").read_text(encoding="utf-8")))
    if not rg.ok:
        fails.append("revocation-golden not valid")
    for fname, want in (("revocation-broken-after", "not_revoked"),
                        ("revocation-multihop", "not_revoked"),
                        ("revocation-broken-revoker", "field_equals")):
        r = verify_chain(json.loads((EX / f"{fname}.json").read_text(encoding="utf-8")))
        if r.ok or not r.failed_assertion or r.failed_assertion.kind != want:
            got = r.failed_assertion.kind if r.failed_assertion else None
            fails.append(f"{fname}: expected {want} to fail, got {got}")

    n = len(g.links)
    if fails:
        print("conformance FAIL:", "; ".join(fails))
        return 1
    print(f"algovoi-keystone conformance: PASS "
          f"(golden {n}/{n} composes == published keystone_v1; tampered execution caught; "
          f"cross-party A->B composes + scope-consistent + in-window, and widened-scope / wrong-delegate / "
          f"expired each rejected by the right check; alias grammar 4/4 (@@ escape diverges from @ resolve, "
          f"unknown alias fails closed); journey composes and an omitted hop is caught; revocation golden valid "
          f"with at/after, cascade, and wrong-revoker each rejected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
