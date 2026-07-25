# Ecosystem scan — first batch (methodology + honest results)

A first application of sealpin's source/supply-chain rules to real, published MCP
servers. The point of this exercise is twofold: measure whether the rules find
real problems at real frequency, and — just as important — measure sealpin's
own **false-positive behaviour** against code it did not write.

Reproduce with: `node scripts/scan-ecosystem.mjs` (downloads tarballs over HTTPS
and analyses them statically; nothing is installed or executed).

## Batch

20 packages: the official `@modelcontextprotocol/server-*` reference servers,
reputable vendor servers (`@notionhq`, `@sentry`, `@upstash`, `@sap-ux`, `@ui5`,
`@apify`, `chrome-devtools-mcp`), and popular community servers. Reputable
packages are deliberately chosen — they are the strongest false-positive test.

## Headline result

**After triage, zero genuine vulnerabilities were found in the 20 packages.**

The raw scan flagged 11/20 packages, but every finding fell into one of four
non-vulnerability buckets. The interesting result is not a scary percentage —
it is *what the false positives taught us about scanning published packages*.

## What the raw numbers were, and what they actually were

| Rule | Raw | After triage | What the flags actually were |
|------|-----|--------------|------------------------------|
| `MCP-S003` command injection | 5% | 0 real | Sentry's `exec(\`open ${JSON.stringify(url)}\`)` — opening an OAuth URL in the browser. A defensible, low-risk pattern, not attacker-controlled input. |
| `MCP-S004` whole-env capture | 45% | ~0 real | The bundled `debug` library enumerating `DEBUG` env vars; dotenv-style env loading (`parseEnv(process.env)`); env spread into a spawned Chrome process; and one *intentional* demo tool (`server-everything`'s `get-env`). |
| `MCP-S005` hardcoded egress | 15% | 0 real | Legitimate service endpoints — a Notion server calling `api.notion.com`, a Figma server calling `api.figma.com`. Expected egress. |
| `MCP-S006` dynamic code exec | 25% | 0 real | 100% bundled dependencies: Ajv compiling validators with `new Function`, the `depd` deprecation shim, ONNX Runtime WASM glue. |

## The real lesson: published bundles are mostly *other people's code*

Most MCP servers ship a compiled, bundled `dist/` (esbuild/rollup) that inlines
their dependencies. Running source rules over that bundle therefore analyses
**Ajv, `debug`, `depd`, ONNX, dotenv, …**, not the server's own logic. Those
libraries legitimately use `new Function`, read `process.env`, and call out to
the network — so they light up supply-chain rules while telling you nothing
about the *server*.

This is a genuine limitation, and it points at where the rules are actually
useful:

- **On a server's own source tree** (`sealpin scan --source-dir .` in a maintainer's
  repo, before bundling) — the intended, high-signal use case.
- **Not** on a published bundle, without dependency-awareness. Making the
  future registry/tarball resolver skip vendored/bundled code (or prefer
  `src/` over `dist/`) is the clear next improvement.

## Rule fixes this exercise directly produced

The scan found real defects in sealpin's own rules, now fixed and regression-tested:

1. **`MCP-S006` matched method calls.** `sap.ui.require([...])`, `fn.eval(x)`, and
   ONNX's `Module.eval` were flagged because callee resolution used the member
   *property* name. Now only bare-global `eval`/`require`/`import` match, and an
   array/object-literal module argument is excluded.
2. **`MCP-S005` flagged any URL passed to any call** — README links, deprecation
   warning strings, and `__tests__` URLs. Now only URLs passed to an actual
   network sink (`fetch`/`axios`/`request`/`WebSocket`/…) are flagged. This
   dropped its false-positive rate from 55% → 15% of packages, and the remaining
   15% are all legitimate first-party endpoints.
3. **Test/example/template code excluded** from the ecosystem measurement — it is
   shipped in some tarballs but is not the server's runtime attack surface.

## Responsible disclosure

Nothing here rises to a disclosable vulnerability, so there is nothing to report
to maintainers. The one pattern worth a neutral mention — Sentry's browser-open
`exec` during OAuth device flow — is a common, low-risk idiom in reputable code
and is noted here only as an example of a "true-positive-by-pattern, low-risk"
finding, not as a security issue.

Aggregate-first remains the policy for any future named findings: publish
statistics freely, contact maintainers privately before naming a specific
server, and only after a fix ships or the maintainer is unresponsive and the
risk is active.

## Status

This is a first batch (20 packages) and a first pass at the methodology. Scaling
to ~100 packages and adding dependency-aware scanning of published bundles are
the next steps. The honest takeaway so far: **the rules are precise enough to be
trustworthy on a server's own source, and the main work left is scoping them
correctly when scanning published, bundled packages.**
