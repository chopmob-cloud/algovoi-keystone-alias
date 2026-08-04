/**
 * Conformance self-test for algovoi-keystone (Node).
 *
 * Same checks as run.py against the same examples. A PASS here plus a PASS there,
 * with identical computed references, is the Python == Node parity proof.
 *
 *   node conformance/run.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, KeystoneError } from "../node/keystone.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EX = join(ROOT, "examples");
const load = (f) => JSON.parse(readFileSync(join(EX, f), "utf-8"));

const PUBLISHED = {
  passport_ref: "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be",
  mandate_ref: "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35",
  policy_bound_ref: "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21",
  decision_ref: "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",
  execution_ref: "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a",
  trust_query_ref: "sha256:18fb601a08c71eb6bed11e1c117f33bdc0ada6d635ea9bb9cca15e8410ce7ebd",
};

const fails = [];
const g = verifyChain(load("keystone-golden.json"));
if (!g.ok) fails.push("golden not valid");
if (!g.capped || g.cap !== "trust_query_ref") fails.push("golden cap not detected");
const by = Object.fromEntries(g.links.map((l) => [l.name, l.computed]));
for (const [name, ref] of Object.entries(PUBLISHED)) if (by[name] !== ref) fails.push(`golden ${name} != published`);

const b = verifyChain(load("broken-execution.json"));
if (b.ok) fails.push("broken chain reported valid");
if (!b.firstBroken || b.firstBroken.name !== "execution_ref") fails.push("broken: first failure should be execution_ref");
if (b.links.find((l) => l.name === "trust_query_ref").ok) fails.push("broken: cap should also fail");

// cross-party delegation: golden valid; each negative caught by the right assertion
const cp = verifyChain(load("delegation-golden.json"));
if (!cp.ok || !cp.capped) fails.push("cross-party golden not valid/capped");
if (JSON.stringify(cp.assertions.map((a) => a.kind)) !== JSON.stringify(["field_equals", "field_equals", "scope_subset", "scope_subset", "time_within"]))
  fails.push("cross-party golden assertions wrong shape");
for (const [fname, want] of [["delegation-broken-scope", "scope_subset"], ["delegation-broken-delegate", "field_equals"], ["delegation-broken-expired", "time_within"]]) {
  const r = verifyChain(load(`${fname}.json`));
  if (r.ok) fails.push(`${fname} reported valid`);
  else if (!r.failedAssertion || r.failedAssertion.kind !== want) fails.push(`${fname}: expected ${want}, got ${r.failedAssertion ? r.failedAssertion.kind : null}`);
}

// alias grammar (alias_escape_v1): L2 resolves @markers to concrete refs BEFORE
// L1 canonicalizes, so the substrate never sees a marker. Each case must reach
// its declared refs/binds (or fail closed), and @@ escape must diverge from @.
const ax = load("alias-escape.json");
for (const c of ax.cases) {
  const exp = c.expect;
  let r;
  try { r = verifyChain({ chain: c.chain }); }
  catch (e) {
    if (!(e instanceof KeystoneError) || !("error_contains" in exp) || !String(e.message).includes(exp.error_contains))
      fails.push(`alias ${c.name}: unexpected error ${e}`);
    continue;
  }
  if ("error_contains" in exp) { fails.push(`alias ${c.name}: expected error, got ok`); continue; }
  for (const l of r.links) {
    if (l.computed !== exp.refs[l.name]) fails.push(`alias ${c.name}: ${l.name} ref != declared`);
    if ("binds" in exp && JSON.stringify(l.binds) !== JSON.stringify(exp.binds[l.name]))
      fails.push(`alias ${c.name}: ${l.name} binds != declared`);
  }
}
const escC = ax.cases.find((c) => c.name === "escaped-literal-collides-with-link-name");
const resC = ax.cases.find((c) => c.name === "alias-resolves-and-binds");
if (escC.expect.refs.post === resC.expect.refs.post)
  fails.push("alias: @@ escape and @ resolve produce the same ref (escape ineffective)");

// multi-agent journey: one journey_ref binds every hop; golden composes, omitted hop caught.
const jg = verifyChain(load("journey-golden.json"));
if (!jg.ok) fails.push("journey-golden not valid");
const jb = verifyChain(load("journey-broken.json"));
if (jb.ok || !jb.failedAssertion || jb.failedAssertion.kind !== "journey") fails.push("journey-broken: expected a journey assertion failure");

// cross-party revocation: golden valid; at/after revocation, cascade, and wrong-revoker each caught.
const rg = verifyChain(load("revocation-golden.json"));
if (!rg.ok) fails.push("revocation-golden not valid");
for (const [fname, want] of [["revocation-broken-after", "not_revoked"], ["revocation-multihop", "not_revoked"], ["revocation-broken-revoker", "field_equals"]]) {
  const r = verifyChain(load(`${fname}.json`));
  if (r.ok || !r.failedAssertion || r.failedAssertion.kind !== want) fails.push(`${fname}: expected ${want}, got ${r.failedAssertion ? r.failedAssertion.kind : null}`);
}

const n = g.links.length;
if (fails.length) { console.error("conformance FAIL:", fails.join("; ")); process.exit(1); }
console.log(`algovoi-keystone conformance: PASS (golden ${n}/${n} == published keystone_v1; tampered execution caught; cross-party A->B composes + scope-consistent + in-window, widened/wrong-delegate/expired each rejected by the right check; alias grammar 4/4 (@@ escape diverges from @ resolve, unknown alias fails closed); journey composes and an omitted hop is caught; revocation golden valid with at/after, cascade, and wrong-revoker each rejected) [Node == Python]`);
