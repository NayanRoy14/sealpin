# sealpin

[![ci](https://github.com/NayanRoy14/sealpin/actions/workflows/ci.yml/badge.svg)](https://github.com/NayanRoy14/sealpin/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/sealpin.svg)](https://www.npmjs.com/package/sealpin)

**`npm audit` for the MCP servers your AI agent trusts.**

sealpin is a supply-chain and prompt-injection scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers. You point it at your MCP config and it tells you which servers can quietly read your SSH keys, which ones changed their tool definitions since you approved them, and which ones are hiding instructions to the model inside tool descriptions.

> Status: **v1, pre-release.** The scanner, rule packs, manifest lockfile, and live sandboxed extraction (`--probe`) all work end to end. Static extraction (`--manifest-dir`) remains the default; probing is strictly opt-in (see [Manifests](#manifests)).

## Why

When you add a server to `claude_desktop_config.json` or `.mcp.json`, you execute arbitrary code, hand it your environment variables, and let it inject text into your model's context as trusted tool documentation — again, with no re-review, every time the package updates. There is no signing, no permission manifest, and no standard way to notice that a server's tool definitions changed after you approved them.

Existing tooling (`npm audit`, Snyk) can't see the prompt-layer attacks at all: to them a tool description is just a string. That gap is what sealpin covers.

## Install

```bash
npm install -g sealpin
# or run without installing:
npx sealpin scan
```

## Quick start

```bash
# 1. See what you're trusting, and get findings on the config alone
sealpin scan

# 2. Extract live tool manifests by running each server in a sandbox, and scan them
sealpin scan --probe

# 3. Pin the current tool manifests
sealpin lock --probe

# 4. Later — did anything change since you approved it?
sealpin verify --probe    # exit 2 if a manifest drifted
sealpin diff   --probe     # show exactly what changed
```

## The lockfile — the point of the tool

A linter you run once; a lockfile lives in your repo forever. `sealpin.json` is the only defense against a **rug pull** (a server that is benign at install time and ships a malicious tool description in a later version) that doesn't require re-auditing every server by hand on every update.

```
sealpin lock     canonically hash every server's full tool manifest
                 (names, descriptions, JSON schemas, annotations) and pin it

sealpin verify   re-hash the current manifests and diff against the lock;
                 any drift is surfaced and exits non-zero

sealpin diff     human-readable changeset of what actually changed
```

Canonicalization is order-independent and whitespace-normalized, so reordering a server's tools or reflowing a description doesn't register as drift — only a real change to what the model is told does.

## What it detects

Run `sealpin rules` for the live list, or `sealpin explain <id>` for any one rule.

| Rule | Severity | Attack | Detects |
|------|----------|--------|---------|
| `MCP-P001` | critical | A1 Tool poisoning | Tool descriptions that instruct the *model* (read credentials, exfiltrate data, ignore prior instructions) rather than document the tool |
| `MCP-P002` | high | A4 Hidden characters | Zero-width, bidirectional-override, and Unicode-tag characters — invisible to a reviewer, tokenized by the model |
| `MCP-P003` | medium | A4 Hidden characters | ANSI escape sequences that hide/overwrite text in a console |
| `MCP-P004` | medium | A4 Hidden characters | HTML comments (hidden in rendered markdown, read by the model) |
| `MCP-P005` | low | A4 Hidden characters | Long opaque base64 blobs in a human-readable description |
| `MCP-P006` | high | A3 Tool shadowing | Tools sharing a name across servers in one context window |
| `MCP-C001` | high | A5 Over-broad capability | Filesystem server rooted at `/`, a drive root, or `$HOME` |
| `MCP-C002` | high | A5 Over-broad capability | Shell/command server with no visible command allowlist |
| `MCP-C003` | medium | A6 Secret exfiltration | Live credentials stored in plaintext in the config `env` block |
| `MCP-S001` | high | A8 Supply chain | Package name edit-distance 1 from a popular package — likely typosquat |
| `MCP-S002` | high | A8 Supply chain | `preinstall`/`install`/`postinstall` script (runs on `npm install`) |
| `MCP-S003` | critical | A7 Command injection | `child_process` exec/spawn with an interpolated command string |
| `MCP-S004` | high | A6 Secret exfiltration | Whole `process.env` captured (serialized/spread/passed), not a specific key |
| `MCP-S005` | medium | A6 Secret exfiltration | Hardcoded external URL passed into a network call |
| `MCP-S006` | high | A7 Command injection | `eval` / `new Function` / dynamic `require`/`import` |

The `MCP-S*` source rules (Node/TS only) need the server's source — pass `--source-dir` or run a server from a local path (auto-detected). `MCP-S001` (typosquat) works from the package name alone, no source required.

Every finding carries a **confidence** level and, more importantly, a **rationale** — the *why*, not just the *what*. Findings never echo a detected secret back in full.

## Output & CI

```bash
sealpin scan --json                 # machine-readable
sealpin scan --sarif > sealpin.sarif # SARIF 2.1.0 for GitHub code scanning
sealpin scan --severity high         # hide findings below a severity
sealpin scan --fail-on critical      # exit 1 only on critical (default: high)
```

**Exit codes:** `0` clean · `1` findings at/above `--fail-on` · `2` drift detected · `3` scan error. This makes both `scan` and `verify` usable as CI gates. A GitHub Action wrapper is in [`examples/github-action.yml`](examples/github-action.yml).

## Manifests

Reading a server's tool manifest ultimately requires talking to the server, which means running third-party code. Config-only rules (`MCP-C001`–`C003`) run on `sealpin scan` with **no manifests at all**; the prompt-layer rules and the lockfile need a manifest, which you obtain one of two ways:

**`--manifest-dir <dir>` (static, default).** A directory of `<server-name>.json` files, each matching the tool-manifest shape. Nothing is executed.

**`--probe` (live, opt-in).** sealpin runs each server through the MCP handshake to read its real `tools/list`, inside the strongest sandbox available on your platform. Safety invariants:

- **Never runs install scripts.** Only the server's own launch command is executed — sealpin never runs `npm install`.
- **Scrubbed environment.** The server gets an operational allowlist (`PATH`, etc.) plus its own declared `env` — your unrelated shell secrets are never inherited.
- **Isolated cwd.** A fresh empty temp directory, not your project.
- **OS isolation where available.** On Linux (bubblewrap/firejail) or macOS (`sandbox-exec`), network and filesystem are confined. On platforms without a sandbox (notably Windows), the probe is *process-only* and prints a warning that network is not blocked. Use `--require-sandbox` to hard-fail rather than probe without network isolation.
- **Bounded.** A hard `--probe-timeout` and an output byte cap; the process tree is always killed and the temp dir removed.

Because `--probe` executes code, it is never the default. `--manifest-dir` and config-only scanning require no execution at all.

## Discovery

`sealpin scan` auto-discovers servers from:

- **Claude Desktop** — `claude_desktop_config.json` (platform-specific location)
- **Claude Code** — project `.mcp.json` and user `~/.claude.json`
- **Cursor** — project `.cursor/mcp.json` and global `~/.cursor/mcp.json`

Or point at one file with `--config <path>`.

## Development

```bash
npm install
npm run typecheck
npm test          # vitest
npm run build     # → dist/
npm run dev -- scan --config test/fixtures/scan/config.json --manifest-dir test/fixtures/scan/manifests
```

## Safety model

- **`discover/`** reads config files. Untrusted input; everything is validated through [zod](https://zod.dev) before use.
- **`probe/`** is the only component that executes third-party code, and only under `--probe`. It runs the server's launch command (never install scripts) inside an OS sandbox where available, with a scrubbed environment, an isolated temp cwd, a hard timeout, and an output byte cap. Every tool it reads is zod-validated before use.
- **`resolve/`** reads server source from the local filesystem for the `MCP-S*` rules. It only ever *reads* files (`node_modules` excluded, bounded count/size) — nothing is executed. A registry/tarball resolver (download + unpack, still never executed) is future work.
- **`rules/`** operate purely on already-parsed manifest, config, and source data — AST analysis via `@babel/parser`, no evaluation. No code execution.

## License

MIT
