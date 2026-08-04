#!/usr/bin/env node
/**
 * algovoi-keystone (Node reference implementation).
 *
 * Verify that an agentic-action keystone chain composes end to end. Each link's
 * reference is "sha256:" + SHA-256(RFC 8785 JCS(preimage)); a downstream preimage
 * refers to an upstream link by @name, so composition is structural. A PASS here
 * against the same references the Python verifier computes is the byte-for-byte
 * Python == Node parity proof.
 *
 * Usage:  node keystone.mjs verify <chain.json>
 *
 * Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { canonicalize } from "@algovoi/substrate";

export class KeystoneError extends Error {}

const ref = (obj) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(obj), "utf-8")).digest("hex");

// A leading "@@" is an escape: "@@name" is the literal string "@name" and never
// resolves. Domain data that legitimately begins with "@" (handles, some DIDs) is
// written escaped, so it can never be mistaken for a composition marker.
function resolve(value, refs, linkName) {
  if (typeof value === "string" && value.startsWith("@")) {
    if (value.startsWith("@@")) return value.slice(1);
    const target = value.slice(1);
    if (!(target in refs)) throw new KeystoneError(`link '${linkName}' references @${target}, which is not an earlier link`);
    return refs[target];
  }
  if (Array.isArray(value)) return value.map((v) => resolve(v, refs, linkName));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolve(v, refs, linkName);
    return out;
  }
  return value;
}

function bindsOf(value, acc) {
  if (typeof value === "string" && value.startsWith("@")) { if (!value.startsWith("@@")) acc.push(value.slice(1)); }
  else if (Array.isArray(value)) for (const v of value) bindsOf(v, acc);
  else if (value && typeof value === "object") for (const v of Object.values(value)) bindsOf(v, acc);
}

// scope model (v1): true iff inner is wholly within outer (widened nothing)
export function scopeContains(outer, inner) {
  const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);
  if (!isObj(outer) || !isObj(inner)) {
    const eq = JSON.stringify(outer) === JSON.stringify(inner);
    return [eq, eq ? "" : "non-object scopes differ"];
  }
  if ("resource" in outer) {
    const seg = (s) => String(s ?? "").split("/").filter((x) => x !== "");
    const o = seg(outer.resource), i = seg(inner.resource);
    if (JSON.stringify(i.slice(0, o.length)) !== JSON.stringify(o))
      return [false, `resource ${JSON.stringify(inner.resource)} not within ${JSON.stringify(outer.resource)}`];
  }
  if ("max_amount" in outer) {
    const iv = inner.max_amount;
    if (iv === undefined || iv > outer.max_amount) return [false, `max_amount ${iv} exceeds ${outer.max_amount}`];
  }
  for (const dim of ["capabilities", "jurisdictions"]) {
    if (dim in outer) {
      const os = new Set(outer[dim]);
      if (!(inner[dim] ?? []).every((x) => os.has(x)))
        return [false, `${dim} ${JSON.stringify(inner[dim])} not a subset of ${JSON.stringify(outer[dim])}`];
    }
  }
  return [true, ""];
}

function getPath(path, preimages) {
  if (!path.includes(".")) throw new KeystoneError(`assertion path '${path}' must be 'link.field'`);
  const [link, ...rest] = path.split(".");
  if (!(link in preimages)) throw new KeystoneError(`assertion references link '${link}', not in the chain`);
  // An absent field is an error, never undefined. Returning undefined silently made an
  // assertion between two missing fields compare equal and PASS, so a typo or a renamed
  // field turned a load-bearing assertion vacuous while the chain still reported ok.
  const fld = rest.join(".");
  if (!(fld in preimages[link])) throw new KeystoneError(`assertion path '${path}' names no field on link '${link}'`);
  return preimages[link][fld];
}

function evalAssertion(a, preimages) {
  if (a.kind === "scope_subset") {
    for (const nm of [a.inner, a.outer]) if (!(nm in preimages)) throw new KeystoneError(`scope_subset references '${nm}', not in the chain`);
    const [ok, why] = scopeContains(preimages[a.outer].scope, preimages[a.inner].scope);
    return { kind: "scope_subset", ok, detail: ok ? "" : `${a.inner}.scope widens ${a.outer}.scope: ${why}` };
  }
  if (a.kind === "field_equals") {
    const av = getPath(a.a, preimages), bv = getPath(a.b, preimages);
    const ok = JSON.stringify(av) === JSON.stringify(bv);
    return { kind: "field_equals", ok, detail: ok ? "" : `${a.a} (${JSON.stringify(av)}) != ${a.b} (${JSON.stringify(bv)})` };
  }
  if (a.kind === "time_within") {
    if (!(a.window in preimages)) throw new KeystoneError(`time_within references window '${a.window}', not in the chain`);
    const t = getPath(a.time, preimages);
    const nb = preimages[a.window].not_before_ms, na = preimages[a.window].not_after_ms;
    const ok = Number.isInteger(t) && Number.isInteger(nb) && Number.isInteger(na) && nb <= t && t <= na;
    return { kind: "time_within", ok, detail: ok ? "" : `${a.time} (${t}) not within ${a.window} [${nb}, ${na}]` };
  }
  if (a.kind === "not_revoked") {
    // valid only if the action happened strictly before the authority it relies on was revoked.
    for (const nm of [a.action, a.revocation]) if (!(nm in preimages)) throw new KeystoneError(`not_revoked references link '${nm}', not in the chain`);
    const t = getPath(a.time, preimages);
    const revokedAt = preimages[a.revocation].revoked_at_ms;
    const ok = Number.isInteger(t) && Number.isInteger(revokedAt) && t < revokedAt;
    return { kind: "not_revoked", ok, detail: ok ? "" : `${a.action} acted at ${t} >= ${a.revocation}.revoked_at_ms (${revokedAt}): authority revoked` };
  }
  if (a.kind === "journey") {
    // one ref for the whole multi-agent task: the journey link must bind every declared hop.
    if (!(a.ref in preimages)) throw new KeystoneError(`journey references link '${a.ref}', not in the chain`);
    const covered = []; bindsOf(preimages[a.ref], covered);
    const hops = a.hops ?? [];
    const missing = hops.filter((h) => !covered.includes(h) || !(h in preimages));
    const ok = hops.length > 0 && missing.length === 0;
    return { kind: "journey", ok, detail: ok ? "" : `journey '${a.ref}' does not cover hops ${JSON.stringify(missing)}` };
  }
  throw new KeystoneError(`unknown assertion kind '${a.kind}'`);
}

export function verifyChain(chain) {
  const links = chain.chain;
  if (!Array.isArray(links) || links.length === 0) throw new KeystoneError("chain must contain a non-empty 'chain' array");
  const refs = {};
  const preimages = {};
  const out = { links: [], assertions: [], cap: null, capCovers: [], capped: false };
  links.forEach((link, i) => {
    const name = link.name;
    if (!name) throw new KeystoneError(`link at index ${i} has no 'name'`);
    if (name in refs) throw new KeystoneError(`duplicate link name '${name}'`);
    if (!("preimage" in link)) throw new KeystoneError(`link '${name}' has no 'preimage'`);
    const binds = [];
    bindsOf(link.preimage, binds);
    const computed = ref(resolve(link.preimage, refs, name));
    const expected = link.ref ?? null;
    const ok = expected === null || computed === expected;
    refs[name] = computed;
    preimages[name] = link.preimage;
    out.links.push({ name, computed, expected, ok, binds, detail: ok ? "" : `recomputed ${computed} != declared ${expected}` });
  });
  for (const a of chain.assertions ?? []) out.assertions.push(evalAssertion(a, preimages));
  const final = links[links.length - 1];
  const finalBinds = [];
  bindsOf(final.preimage ?? {}, finalBinds);
  if (finalBinds.length >= 2 && finalBinds.every((b) => b in refs)) {
    out.cap = final.name;
    out.capCovers = finalBinds;
    out.capped = out.links[out.links.length - 1].ok;
  }
  out.ok = out.links.length > 0 && out.links.every((l) => l.ok) && out.assertions.every((a) => a.ok);
  out.firstBroken = out.links.find((l) => !l.ok) || null;
  out.failedAssertion = out.assertions.find((a) => !a.ok) || null;
  return out;
}

function cli(argv) {
  const USAGE = "usage: keystone verify <chain.json>";
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") { console.log(USAGE); return argv.length ? 2 : 0; }
  if (argv[0] !== "verify") { console.error(`error: unknown command '${argv[0]}'\n${USAGE}`); return 2; }
  if (argv.length !== 2) { console.error(USAGE); return 2; }
  let chain;
  try { chain = JSON.parse(readFileSync(argv[1], "utf-8")); }
  catch (e) { console.error(`error: cannot read ${argv[1]}: ${e.message}`); return 2; }
  let r;
  try { r = verifyChain(chain); }
  catch (e) { console.error(`error: malformed keystone chain: ${e.message}`); return 2; }
  console.log("keystone chain:", r.links.map((l) => l.name).join("  ->  "));
  console.log("-".repeat(60));
  for (const l of r.links) {
    console.log(`  ${l.ok ? "OK  " : "BAD "}${l.name}`);
    console.log(`      ${l.computed}${l.binds.length ? "  binds " + l.binds.join(", ") : ""}`);
    if (!l.ok) console.log(`      ^ ${l.detail}`);
  }
  if (r.assertions.length) {
    console.log("assertions:");
    for (const a of r.assertions) console.log(`  ${a.ok ? "OK  " : "BAD "}${a.kind}` + (a.ok ? "" : `: ${a.detail}`));
  }
  console.log("-".repeat(60));
  if (r.ok) {
    const n = r.links.length;
    let extra = "";
    if (r.assertions.length) {
      const kinds = [...new Set(r.assertions.map((a) => a.kind))].sort().map((k) => k.replace(/_/g, "-"));
      extra = " + " + kinds.join(", ") + " hold";
    }
    console.log(`KEYSTONE VALID: ${n}/${n} links compose, recompute byte-for-byte, no issuer contact${extra}.`);
    if (r.capped) console.log(`  capped: ${r.cap} is one verdict over [${r.capCovers.join(", ")}] in order.`);
    return 0;
  }
  if (r.firstBroken) {
    console.log(`KEYSTONE BROKEN at ${r.firstBroken.name}: ${r.firstBroken.detail || "reference mismatch"}.`);
    console.log("  every link that binds it is therefore not provable from these bytes.");
  } else {
    console.log(`KEYSTONE BROKEN: ${r.failedAssertion.kind} failed -- ${r.failedAssertion.detail}.`);
    console.log("  the chain recomputes, but it does not prove what it claims (e.g. scope widened, or out of window).");
  }
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(cli(process.argv.slice(2)));
}
