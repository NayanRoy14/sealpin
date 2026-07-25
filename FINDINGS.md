# Ecosystem scan — aggregate study

An application of sealpin's source/supply-chain rules to real, published MCP
servers. The goal is twofold: measure whether the rules find real problems at
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

51 packages across three tiers: the official `@modelcontextprotocol/server-*`
reference servers; well-known vendor servers (Playwright, BrowserStack, Heroku,
Clerk, Salesforce, Storybook, Sentry, Notion, Upstash, SAP, Apify, …); and a
long tail of smaller community/"weekend-project" servers, where real issues are
most likely.

## Headline results

- **51 scanned; 5 (10%) ship no auditable first-party source** — only a bundled
  or minified artifact. You cannot review what a bundle-only package actually
  does from what it publishes. This is a supply-chain **transparency** finding
  in its own right.
- **45 source-analyzable; 17 (38%) had at least one finding.**
- **After triage, no confirmed, exploitable vulnerabilities were found.** A small
  number of servers use patterns worth a maintainer's review (runtime values
  interpolated into `child_process` execution); those are being handled by
  private disclosure per the policy below and are not named here.

## By rule (of 45 source-analyzable packages), with triage

| Rule | Packages | What the flags actually were |
|------|----------|------------------------------|
| `MCP-S003` command injection | 7% | One common, defensible idiom (opening a URL in the browser during OAuth); a few genuine "value interpolated into a shell command" patterns worth review (privately disclosed). |
| `MCP-S004` whole-env capture | 27% | Almost all benign: spreading `process.env` into a spawned child process, dotenv-style `parseEnv(process.env)`, config loading, and one *intentional* demo tool. Low signal for actual exfiltration intent. |
| `MCP-S005` hardcoded egress | 9% | All legitimate first-party endpoints — a Notion server calling `api.notion.com`, a BrowserStack server calling `percy.io`, self-update checks against the npm registry. |
| `MCP-S006` dynamic code exec | 4% | A vendored ONNX-Runtime WASM file (`new Function`) and plugin-style `import(variablePath)`. No attacker-controlled code execution. |
| `MCP-S002` install script | 2% | A real `postinstall` — flagged for transparency (its script should be reviewed), not presumed malicious. |

## What this says about the rules

The scan drove real precision improvements (all fixed and regression-tested):

1. **`MCP-S006` matched member calls** (`sap.ui.require`, `fn.eval`, ONNX
   `Module.eval`) because callee resolution used the member property name. Now
   only bare-global `eval`/`require`/`import`; literal-array/object module args
   excluded.
2. **`MCP-S005` flagged URLs passed to any call** — README links, deprecation
   warnings, test URLs. Now only URLs into an actual network sink. False-positive
   rate fell from 55% → 9% of packages, and the remainder are all legitimate
   first-party endpoints.
3. **First-party source preference + bundle/minified exclusion** removed the
   dominant noise source (vendored dependency code in published bundles).

Two honest limitations remain:

- **`MCP-S004` (whole-env capture) has low precision.** Referencing the whole
  environment is common and usually benign (passing env to a subprocess, loading
  dotenv). Distinguishing capture-then-*exfiltrate* from capture-then-*use* needs
  data-flow analysis, which is beyond a deterministic AST-pattern rule. It is
  best read as "worth a glance," not "vulnerable."
- **Bundle-only packages cannot be source-audited** from what they publish;
  scanning their bundle would measure their dependencies. Dependency-aware bundle
  or repo-source scanning is the next improvement.

## Responsible disclosure

This public write-up is deliberately **aggregate**: it names no package in
connection with a potential weakness. Per policy, any finding that warrants a
maintainer's attention is contacted privately first (SECURITY.md / repo email),
with a 90-day window, and only aggregate statistics are published until a fix
ships or the maintainer is unresponsive and the risk is active. The per-package
raw results (`scripts/ecosystem-results.json`) are kept local and untracked.

## Status

First aggregate batch (51 packages). Next: scale further, add dependency-aware
scanning of bundle-only packages (or scan first-party source from the source
repo), and refine `MCP-S004` toward exfiltration-specific signal. The takeaway so
far: the rules are precise enough to be trustworthy on a server's own source, the
main residual work is scoping them for published bundles, and a non-trivial slice
of the ecosystem ships code that cannot be audited from the registry at all.
