# Ecosystem scan — aggregate study

An application of sealpin's source/supply-chain rules to **109 real, published MCP
servers**. The goal is twofold: measure whether the rules find real problems at
real frequency, and measure sealpin's own **false-positive behaviour** against
code it did not write.

Reproduce with: `node scripts/scan-ecosystem.mjs scripts/packages.txt`
(downloads tarballs over HTTPS and analyses them statically — nothing is
installed or executed).

## Method

For each package: fetch its published tarball, extract it in memory, and run the
`MCP-S*` rules over its **first-party source**. To keep the measurement about
the *server* and not its dependencies:

- **`src/` is preferred** when shipped (unbundled first-party source).
- **Bundles are de-vendored, not skipped.** Most servers ship a compiled `dist/`
  that inlines their dependencies. esbuild delimits each inlined module with a
  `// <path>` comment; sealpin keeps only the first-party regions (paths without
  `node_modules/`) and blanks the vendored ones, line-preserving. So a bundle is
  analysed as the server's own code, not as Ajv/`debug`/ONNX. Bundles that can't
  be split confidently (minified single-line output) are reported as opaque.
- **Test, example, and template code is excluded** — shipped in some tarballs,
  but not the server's runtime attack surface.

## Batch

109 packages across three tiers: the official `@modelcontextprotocol/server-*`
reference servers; well-known vendor servers (Playwright, BrowserStack, Heroku,
Stripe, HubSpot, Sentry, Notion, Supabase, Brave, Perplexity, Apify, Salesforce,
SAP, …); and a long tail of smaller community/"weekend-project" servers, where
real issues are most likely.

## Headline results

- **109 scanned; 108 source-analyzable.** De-vendoring recovered first-party code
  from every esbuild bundle, so **0 packages were unauditable** in this batch
  (an earlier, skip-the-whole-bundle approach left 6% opaque). Minified or
  non-esbuild bundles would still be opaque — none remained so here.
- **18 (17%) had at least one finding** (down from 33% before the data-flow
  refinements below — the reduction is false positives removed, not detections
  lost).
- **After triage, no confirmed, exploitable vulnerabilities.** A handful of
  servers interpolate runtime, tool-controlled values into shell execution — a
  genuine command-injection *shape* worth a maintainer's review. Those are being
  handled by private disclosure per the policy below and are not named here.

De-vendoring also *removed* false positives: several packages that previously
lit up (Ajv/`depd`/ONNX inside their bundle) are now correctly clean, and the
findings that remain are on the server's own code (e.g. a Figma server's own
`api.figma.com` calls, on their real line numbers inside the bundle).

## By rule (of 108 source-analyzable packages), with triage

| Rule | Packages | What the flags actually were |
|------|----------|------------------------------|
| `MCP-S002` install script | 3% | Real `pre/postinstall` scripts — flagged for transparency (review the script), not presumed malicious. |
| `MCP-S003` command injection | 5% | One common, defensible idiom (opening a URL in the browser during OAuth); and a genuine subset that interpolate tool-controlled values (a container name, a cron entry) into a shell command — privately disclosed. |
| `MCP-S004` env exfiltration | 0% | None. With the data-flow refinement, the rule now fires only when the *whole* `process.env` flows into an outbound call; no server in the batch does this. The 24% it flagged before were all env passed to a subprocess, a dotenv loader, or read inside an inbound route handler. |
| `MCP-S005` hardcoded egress | 7% | All legitimate first-party endpoints — a Notion server calling `api.notion.com`, a Figma server calling `api.figma.com`, self-update checks against the npm registry. |
| `MCP-S006` dynamic code exec | 4% | A vendored ONNX-Runtime WASM file (`new Function`); plugin loaders with genuinely data-derived module paths. Internal `import(join(__dirname, "…"))` bin-wrappers are no longer flagged. |

## What this says about the rules

The scan drove three real precision fixes, all regression-tested:

1. **`MCP-S006` matched member calls** (`sap.ui.require`, `fn.eval`) because callee
   resolution used the member property name. Now only bare-global
   `eval`/`require`/`import`.
2. **`MCP-S005` flagged URLs passed to any call** — README links, deprecation
   warnings, test URLs. Now only URLs into an actual network sink. False-positive
   rate fell from 55% → 6% of packages.
3. **`MCP-S003` matched any `.exec()`** — a SQLite `db.exec(sql)` was flagged as
   command injection. Now only genuine `child_process` calls (a bare global
   `exec`/`spawn`, or a member on a `child_process`-like receiver); `db.exec`,
   `regexp.exec`, and similar are no longer flagged.
4. **`MCP-S004` now uses intraprocedural data-flow.** It flags only when the
   whole `process.env` reaches an outbound/network call — directly, or via a
   variable it was assigned — and never counts env inside a nested function
   body (an inbound route handler is not an outbound call). This took its false
   positives from 24% of packages to 0 while still detecting the real
   `fetch(url, { body: JSON.stringify(process.env) })` shape (unit-tested).
5. **`MCP-S006` now checks argument provenance.** `require()`/`import()` is
   flagged only when the module path is data-derived; a fixed internal path
   built from string literals, `__dirname`/`import.meta`, and path helpers
   (`import(join(__dirname, "…"))`) is not. `eval`/`new Function` still always
   flag.

One honest limitation remains: the data-flow is **intraprocedural** — a capture
in one function that is exfiltrated by another is not connected, and non-esbuild
bundles (webpack/rollup) are not de-vendored, so a `new Function` from a bundled
dependency can still surface. These are documented, not silently ignored.

## Status (source/supply-chain study)

Aggregate study over 109 packages. The takeaway: across a broad slice of the
real MCP ecosystem, there were no confirmed exploitable vulnerabilities, but a
real minority of servers interpolate tool-controlled input into shell execution
(worth review). Dependency-aware de-vendoring now recovers first-party code from
published esbuild bundles, so the earlier "unauditable" gap closed (0% in this
batch) and vendored-dependency false positives dropped.

---

# Cross-server composition study

A separate study of the `MCP-X*` rules, which reason about the *combination* of
servers loaded in one agent context rather than any single server.

Reproduce with: `node scripts/scenarios.mjs`.

## Method

There is no public corpus of real users' MCP configs (they are private), so this
uses **14 representative setups** built from real published servers — the
combinations people actually configure (a coding assistant = filesystem + github
+ web-search + shell; a research assistant = web-search + fetch + notion +
filesystem; a payments agent = stripe + fetch + filesystem; etc.), plus a few
deliberately conservative ones. Capabilities are inferred from the config alone;
nothing is executed.

These are *representative scenarios*, not a random sample of real users' configs
— the honest framing is "how often does the trifecta appear in typical setups,"
not "N% of real users are vulnerable."

## Result

| Composition risk | Scenarios |
|------------------|-----------|
| **Lethal trifecta (`MCP-X001`)** | **10 / 14 (71%)** |
| Untrusted content → exec (`MCP-X002`) | 2 / 14 (14%) |
| Confused deputy (`MCP-X003`) | 0 / 14 |
| Any composition finding | 10 / 14 (71%) |

**Roughly seven in ten realistic multi-tool agent setups contain a lethal-trifecta
path** — private-data access, untrusted-content intake, and an outbound channel
co-loaded in one context — even though every individual server is reasonable. The
clean scenarios are exactly the ones you'd expect: web-browse-only (no private
data), a read-only local DB, a scoped-filesystem scratchpad, and a
DevOps/SRE set with no untrusted-content ingress.

This is the core argument for composition-level analysis: the danger is not in
any one server a per-server linter would flag, it is in the *combination* that a
user assembles without realising the three legs are now in one room.

## Honest limitations

- Config-only inference **under-tags** some capabilities that only a manifest
  reveals — e.g. an issue-tracker's `create_issue` (a subtle exfil channel) or a
  server whose tool returns untrusted content it does not advertise in its name.
  So the 71% is a floor, not a ceiling; `--probe` manifests would raise recall.
- `MCP-X003` (single-server confused deputy) is rare in realistic setups because
  people split credential-holding and content-fetching across servers — which is
  exactly the cross-server trifecta the other rules catch.

## Responsible disclosure

Both studies are deliberately **aggregate**: they name no package in connection
with a potential weakness. Per policy, any finding warranting a maintainer's
attention is contacted privately first (SECURITY.md / repo email), with a 90-day
window, and only aggregate statistics are published until a fix ships or the
maintainer is unresponsive and the risk is active. Per-package raw results
(`scripts/ecosystem-results.json`) are kept local and untracked.
