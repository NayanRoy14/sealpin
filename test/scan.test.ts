import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { discoverFromFile } from '../src/discover/index.js';
import { FileManifestSource, scanServers, hasFindingAtOrAbove } from '../src/scan/index.js';
import { severityOf } from '../src/rules/index.js';
import { renderJson, renderSarif, renderText } from '../src/report/index.js';
import { setColorEnabled } from '../src/report/color.js';
import { server } from './helpers.js';

const SCAN_FIXTURES = join(__dirname, 'fixtures', 'scan');

setColorEnabled(false); // deterministic report output in tests

async function runScan() {
  const servers = await discoverFromFile(join(SCAN_FIXTURES, 'config.json'));
  const source = new FileManifestSource(join(SCAN_FIXTURES, 'manifests'));
  return { servers, summary: await scanServers(servers, { manifestSource: source }) };
}

describe('FileManifestSource resilience', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'sealpin-manifest-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('skips a malformed manifest file (returns null + onError) instead of throwing', async () => {
    await writeFile(join(dir, 'bad.json'), '{ not valid json', 'utf-8');
    const errors: string[] = [];
    const src = new FileManifestSource(dir, { onError: (s, m) => errors.push(`${s}: ${m}`) });

    const result = await src.load(server({ name: 'bad' }));
    expect(result).toBeNull();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('bad');
  });

  it('a bad manifest for one server does not abort the scan of the others', async () => {
    await writeFile(join(dir, 'bad.json'), '{ broken', 'utf-8');
    await writeFile(
      join(dir, 'good.json'),
      JSON.stringify({ server: 'good', tools: [{ name: 'ok', inputSchema: { type: 'object' } }] }),
      'utf-8',
    );
    const servers = [server({ name: 'bad' }), server({ name: 'good' })];
    const summary = await scanServers(servers, { manifestSource: new FileManifestSource(dir) });
    expect(summary.serversScanned).toBe(2);
    expect(summary.serversWithManifest).toBe(1); // only "good" loaded
  });
});

describe('scan pipeline', () => {
  it('scans a fixture config end to end and reports the expected finding classes', async () => {
    const { summary } = await runScan();
    expect(summary.serversScanned).toBe(3);
    expect(summary.serversWithManifest).toBe(3);

    const ruleIds = new Set(summary.findings.map((f) => f.ruleId));
    expect(ruleIds).toContain('MCP-P001'); // injection in github.create_issue
    expect(ruleIds).toContain('MCP-C001'); // fs rooted at /
    expect(ruleIds).toContain('MCP-C003'); // ghp token in env
    expect(ruleIds).toContain('MCP-P006'); // "notes" tool collides across github/notes
  });

  it('sorts findings most-severe first', async () => {
    const { summary } = await runScan();
    const ranks = summary.findings.map((f) => severityOf(f.ruleId));
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const numeric = ranks.map((r) => order.indexOf(r));
    const sorted = [...numeric].sort((a, b) => a - b);
    expect(numeric).toEqual(sorted);
  });

  it('runs capability rules even when no manifest is available', async () => {
    const servers = await discoverFromFile(join(SCAN_FIXTURES, 'config.json'));
    const summary = await scanServers(servers); // no manifest source
    expect(summary.serversWithManifest).toBe(0);
    const ruleIds = new Set(summary.findings.map((f) => f.ruleId));
    // config-only rules still fire...
    expect(ruleIds).toContain('MCP-C001');
    expect(ruleIds).toContain('MCP-C003');
    // ...but manifest-dependent prompt rules do not
    expect(ruleIds).not.toContain('MCP-P001');
  });

  it('respects the minSeverity filter', async () => {
    const servers = await discoverFromFile(join(SCAN_FIXTURES, 'config.json'));
    const source = new FileManifestSource(join(SCAN_FIXTURES, 'manifests'));
    const summary = await scanServers(servers, { manifestSource: source, minSeverity: 'high' });
    for (const f of summary.findings) {
      expect(['critical', 'high']).toContain(severityOf(f.ruleId));
    }
  });

  it('hasFindingAtOrAbove drives the fail-on gate', async () => {
    const { summary } = await runScan();
    expect(hasFindingAtOrAbove(summary.findings, 'high')).toBe(true);
    expect(hasFindingAtOrAbove([], 'info')).toBe(false);
  });
});

describe('reporters', () => {
  it('renders valid JSON with severity attached', async () => {
    const { summary } = await runScan();
    const parsed = JSON.parse(renderJson(summary));
    expect(parsed.tool).toBe('sealpin');
    expect(parsed.findings.length).toBe(summary.findings.length);
    expect(parsed.findings[0]).toHaveProperty('severity');
  });

  it('renders valid SARIF 2.1.0 with a result per finding', async () => {
    const { summary } = await runScan();
    const sarif = JSON.parse(renderSarif(summary));
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('sealpin');
    expect(run.results.length).toBe(summary.findings.length);
    // every result references a rule that exists in the driver
    const ruleIds = new Set(run.tool.driver.rules.map((r: { id: string }) => r.id));
    for (const res of run.results) {
      expect(ruleIds.has(res.ruleId)).toBe(true);
      expect(res.locations[0].physicalLocation.artifactLocation.uri).toBeTruthy();
    }
  });

  it('renders a text report that names findings and a summary', async () => {
    const { summary } = await runScan();
    const text = renderText(summary);
    expect(text).toContain('MCP-C001');
    expect(text).toContain('Summary:');
  });

  it('reports a clean run with no findings', () => {
    const text = renderText({ serversScanned: 2, serversWithManifest: 2, findings: [] });
    expect(text).toContain('No findings');
  });
});
