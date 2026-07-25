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
- **Bundled/minified files are excluded** — a file with esbuild `// node_modules/`
  markers or extremely long lines inlines dependency code, so analysing it
  measures Ajv/`debug`/ONNX/etc., not the server.
- **Test, example, and template code is excluded** — shipped in some tarballs,
  but not the server's runtime attack surface.

## Batch

109 packages across three tiers: the official `@modelcontextprotocol/server-*`
reference servers; well-known vendor servers (Playwright, BrowserStack, Heroku,
Stripe, HubSpot, Sentry, Notion, Supabase, Brave, Perplexity, Apify, Salesforce,
SAP, …); and a long tail of smaller community/"weekend-project" servers, where
real issues are most likely.

## Headline results

- **109 scanned; 7 (6%) ship no auditable first-party source** — only a bundled
  or minified artifact. You cannot review what a bundle-only package actually
  does from what it publishes. A supply-chain **transparency** finding in itself.
- **101 source-analyzable; 34 (34%) had at least one finding.**
- **After triage, no confirmed, exploitable vulnerabilities.** A handful of
  servers interpolate runtime, tool-controlled values into shell execution — a
  genuine command-injection *shape* worth a maintainer's review. Those are being
  handled by private disclosure per the policy below and are not named here.

## By rule (of 101 source-analyzable packages), with triage

| Rule | Packages | What the flags actually were |
|------|----------|------------------------------|
| `MCP-S002` install script | 3% | Real `pre/postinstall` scripts — flagged for transparency (review the script), not presumed malicious. |
| `MCP-S003` command injection | 5% | One common, defensible idiom (opening a URL in the browser during OAuth); and a genuine subset that interpolate tool-controlled values (a container name, a cron entry) into a shell command — privately disclosed. |
| `MCP-S004` whole-env capture | 23% | Almost all benign: spreading `process.env` into a spawned child process, dotenv-style `parseEnv(process.env)`, config loading, one intentional demo tool. Low signal for actual exfiltration intent. |
| `MCP-S005` hardcoded egress | 6% | All legitimate first-party endpoints — a Notion server calling `api.notion.com`, a BrowserStack server calling `percy.io`, self-update checks against the npm registry. |
| `MCP-S006` dynamic code exec | 4% | A vendored ONNX-Runtime WASM file (`new Function`); plugin loaders and internal `import(join(dir, "…"))` bin-wrappers. No attacker-controlled code execution. |

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

Two honest limitations remain:

- **`MCP-S004` (whole-env capture) has low precision.** Referencing the whole
  environment is common and usually benign (passing env to a subprocess, loading
  dotenv). Separating capture-then-*exfiltrate* from capture-then-*use* needs
  data-flow analysis, beyond a deterministic AST-pattern rule.
- **`MCP-S006` dynamic import/require** is dominated by plugin loaders and
  internal relative-path imports (`import(join(__dirname, "…"))`), which are
  low-signal. Same class of limitation.

## Responsible disclosure

This public write-up is deliberately **aggregate**: it names no package in
connection with a potential weakness. Per policy, any finding that warrants a
maintainer's attention is contacted privately first (SECURITY.md / repo email),
with a 90-day window, and only aggregate statistics are published until a fix
ships or the maintainer is unresponsive and the risk is active. The per-package
raw results (`scripts/ecosystem-results.json`) are kept local and untracked.

## Status

Aggregate study over 109 packages. The takeaway: across a broad slice of the
real MCP ecosystem, there were no confirmed exploitable vulnerabilities, but a
real minority of servers interpolate tool-controlled input into shell execution
(worth review), and 6% ship code that cannot be audited from the registry at
all. The rules are precise on a server's own source; the residual work is
data-flow-aware refinement of `MCP-S004`/`S006` and dependency-aware scanning of
bundle-only packages.
