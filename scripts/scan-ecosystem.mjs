// Ecosystem scan harness for sealpin's aggregate study.
//
// For each package: fetch its published tarball from the npm registry over
// HTTPS and extract it IN MEMORY (gunzip + a small tar reader — no `tar`
// subprocess, no temp files, nothing executed). Then run sealpin's
// source/supply-chain rules over the SHIPPED code (including dist/, since that
// is what actually runs on a user's machine) and aggregate the findings.
//
// Safety: nothing here installs or runs the scanned packages. It downloads
// bytes and analyzes them statically.
//
// Usage:  node scripts/scan-ecosystem.mjs [packages.txt]

import { gunzipSync } from 'node:zlib';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { relative } from 'node:path';

import { scanServers, severityOf, analyzableSource } from '../dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));

const DEFAULT_PACKAGES = [
  // Official reference servers (best false-positive test — should be clean)
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  // Reputable orgs
  '@notionhq/notion-mcp-server',
  '@sentry/mcp-server',
  '@upstash/context7-mcp',
  '@sap-ux/fiori-mcp-server',
  '@ui5/mcp-server',
  '@apify/actors-mcp-server',
  // Popular community servers
  'chrome-devtools-mcp',
  'figma-mcp',
  'ref-tools-mcp',
  'puppeteer-mcp-server',
  'enhanced-postgres-mcp-server',
  '@sylphlab/mcp-filesystem',
  'mcp-github-server',
  'rime-mcp',
  '@jsonresume/mcp',
  'ref-mcp-cli',
];

const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);
const SKIP_DIRS = new Set(['node_modules', '.git']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 800;

// Test/example/template code is shipped in some tarballs but is not the
// server's runtime attack surface; excluding it avoids counting test fixtures
// and scaffolding as findings.
const NON_RUNTIME = /(^|\/)(__tests__|__mocks__|test|tests|spec|examples?|fixtures?|templates?|resources)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/i;

/** Minimal tar reader: yields { name, content } for regular file entries. */
function readTar(buf) {
  const entries = [];
  let off = 0;
  let override = null; // pending long/pax name for the next entry
  while (off + 512 <= buf.length) {
    const block = buf.subarray(off, off + 512);
    off += 512;
    if (block.every((b) => b === 0)) break; // end-of-archive
    const name = cstr(block, 0, 100);
    const size = parseInt(cstr(block, 124, 12).trim() || '0', 8) || 0;
    const type = String.fromCharCode(block[156]);
    const prefix = cstr(block, 345, 155);
    const data = buf.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;

    if (type === 'L') {
      override = data.toString('utf-8').replace(/\0+$/, '');
      continue;
    }
    if (type === 'x' || type === 'g') {
      const m = /(?:^|\n)\d+ path=([^\n]+)\n/.exec(data.toString('utf-8'));
      if (m) override = m[1];
      continue;
    }
    let full = override ?? (prefix ? `${prefix}/${name}` : name);
    override = null;
    if (type === '0' || type === '\0' || type === '') {
      entries.push({ name: full, content: data });
    }
  }
  return entries;
}

function cstr(block, start, len) {
  let end = start;
  const max = start + len;
  while (end < max && block[end] !== 0) end++;
  return block.toString('utf-8', start, end);
}

async function resolveTarball(spec) {
  const encoded = spec.startsWith('@') ? '@' + encodeURIComponent(spec.slice(1)) : encodeURIComponent(spec);
  const res = await fetch(`https://registry.npmjs.org/${encoded}`);
  if (!res.ok) throw new Error(`registry ${res.status}`);
  const meta = await res.json();
  const version = meta['dist-tags']?.latest ?? Object.keys(meta.versions ?? {}).pop();
  const tarball = meta.versions?.[version]?.dist?.tarball;
  if (!tarball) throw new Error('no tarball url in registry metadata');
  return { version, tarball };
}

async function scanPackage(spec) {
  const { version, tarball } = await resolveTarball(spec);
  const res = await fetch(tarball);
  if (!res.ok) throw new Error(`download ${res.status}`);
  const entries = readTar(gunzipSync(Buffer.from(await res.arrayBuffer())));

  const candidates = [];
  let packageJson = null;
  for (const e of entries) {
    if (!e.name.startsWith('package/')) continue;
    const rel = e.name.slice('package/'.length);
    if (rel === 'package.json') {
      try { packageJson = JSON.parse(e.content.toString('utf-8')); } catch { /* ignore */ }
      continue;
    }
    if (rel.split('/').some((seg) => SKIP_DIRS.has(seg))) continue;
    if (NON_RUNTIME.test(rel)) continue;
    if (!SOURCE_EXT.has(extname(rel).toLowerCase()) || rel.endsWith('.d.ts')) continue;
    if (e.content.length > MAX_FILE_BYTES) continue;
    candidates.push({ relPath: rel, content: e.content.toString('utf-8') });
  }

  // Dependency-aware: pass ordinary source through, de-vendor esbuild bundles to
  // their first-party regions, and drop opaque (minified) bundles.
  const analyzable = [];
  for (const c of candidates) {
    const a = analyzableSource(c.content);
    if (a) analyzable.push({ relPath: c.relPath, content: a.content });
  }
  // Prefer src/ (unbundled first-party) when present, to avoid double-counting a
  // package that ships both src/*.ts and a de-vendored dist bundle of the same code.
  const src = analyzable.filter((c) => c.relPath === 'src' || c.relPath.startsWith('src/'));
  const chosen = (src.length ? src : analyzable).slice(0, MAX_FILES);
  const bundleOnly = chosen.length === 0 && candidates.length > 0;

  const files = chosen.map((c) => ({ path: `package/${c.relPath}`, relPath: c.relPath, content: c.content }));
  const server = { name: spec, command: 'npx', args: ['-y', spec], env: {}, client: 'claude-desktop', configPath: `${spec} (npm)` };
  const resolver = { async resolve() { return { root: `npm:${spec}`, packageJson, files }; } };
  const summary = await scanServers([server], { sourceResolver: resolver });

  return {
    spec,
    fileCount: files.length,
    bundleOnly,
    version: packageJson?.version ?? version ?? '?',
    findings: summary.findings,
  };
}

async function main() {
  const listArg = process.argv[2];
  const packages = listArg
    ? (await readFile(listArg, 'utf-8')).split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'))
    : DEFAULT_PACKAGES;

  const results = [];
  const errors = [];
  console.log(`Scanning ${packages.length} packages (no code executed; HTTPS fetch + in-memory static analysis)\n`);

  for (const spec of packages) {
    process.stdout.write(`  ${spec} … `);
    try {
      const r = await scanPackage(spec);
      results.push(r);
      const tag = r.bundleOnly ? ' [bundle-only — no first-party source shipped]' : '';
      console.log(`${r.fileCount} files, ${r.findings.length} findings ${tally(r.findings)}${tag}`);
    } catch (err) {
      errors.push({ spec, message: err instanceof Error ? err.message : String(err) });
      console.log(`ERROR: ${err instanceof Error ? err.message.split('\n')[0] : err}`);
    }
  }

  report(results, errors);

  const outPath = join(HERE, 'ecosystem-results.json');
  await writeFile(outPath, JSON.stringify({ scannedAt: new Date().toISOString(), results, errors }, null, 2));
  console.log(`\nRaw results written to ${relative(process.cwd(), outPath)}`);
}

function tally(findings) {
  const c = {};
  for (const f of findings) {
    const s = severityOf(f.ruleId);
    c[s] = (c[s] ?? 0) + 1;
  }
  const parts = ['critical', 'high', 'medium', 'low'].filter((s) => c[s]).map((s) => `${c[s]} ${s}`);
  return parts.length ? `(${parts.join(', ')})` : '';
}

function report(results, errors) {
  console.log('\n' + '='.repeat(72));
  console.log('AGGREGATE');
  console.log('='.repeat(72));

  const scanned = results.length;
  const byRule = {};
  const pkgsWithRule = {};
  for (const r of results) {
    const seen = new Set();
    for (const f of r.findings) {
      byRule[f.ruleId] = (byRule[f.ruleId] ?? 0) + 1;
      if (!seen.has(f.ruleId)) {
        pkgsWithRule[f.ruleId] = (pkgsWithRule[f.ruleId] ?? 0) + 1;
        seen.add(f.ruleId);
      }
    }
  }

  const bundleOnly = results.filter((r) => r.bundleOnly).length;
  const analyzable = results.filter((r) => !r.bundleOnly && r.fileCount > 0);
  const withAny = analyzable.filter((r) => r.findings.length > 0).length;
  console.log(`\nPackages scanned successfully:   ${scanned}`);
  console.log(`  bundle-only (unauditable src): ${bundleOnly} (${pct(bundleOnly, scanned)})`);
  console.log(`  source-analyzable:             ${analyzable.length}`);
  console.log(`Analyzable pkgs with >=1 finding: ${withAny} (${pct(withAny, analyzable.length)})`);
  if (errors.length) console.log(`Packages that failed to fetch:   ${errors.length}`);

  console.log('\nBy rule (packages affected / total findings):');
  for (const ruleId of Object.keys(byRule).sort()) {
    console.log(`  ${ruleId}  ${pkgsWithRule[ruleId]} pkgs (${pct(pkgsWithRule[ruleId], scanned)}) · ${byRule[ruleId]} findings`);
  }

  console.log('\nPer package:');
  for (const r of results) {
    const ids = r.bundleOnly ? 'bundle-only' : [...new Set(r.findings.map((f) => f.ruleId))].sort().join(', ') || 'clean';
    console.log(`  ${r.spec}@${r.version}  [${r.fileCount} files]  ${ids}`);
  }
  if (errors.length) {
    console.log('\nFetch errors:');
    for (const e of errors) console.log(`  ${e.spec}: ${e.message.split('\n')[0]}`);
  }
}

function pct(n, total) {
  return total === 0 ? '0%' : `${Math.round((n / total) * 100)}%`;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
