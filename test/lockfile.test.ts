import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ToolManifest } from '../src/types/manifest.js';
import { canonicalize } from '../src/lockfile/canonicalize.js';
import { hashManifest } from '../src/lockfile/hash.js';
import { diffManifests, isEmptyDiff } from '../src/lockfile/diff.js';
import { lock, verify, readLockfile, writeLockfile } from '../src/lockfile/index.js';

const FIXTURES = join(__dirname, 'fixtures', 'manifests');

async function loadManifest(name: string): Promise<ToolManifest> {
  const raw = await readFile(join(FIXTURES, name), 'utf-8');
  return JSON.parse(raw) as ToolManifest;
}

describe('canonicalize / hashManifest', () => {
  it('is stable across tool reordering and description whitespace', async () => {
    const base = await loadManifest('filesystem-server.json');
    const reordered: ToolManifest = {
      server: base.server,
      tools: [...base.tools].reverse().map((t, i) =>
        i === 0 && t.description
          ? { ...t, description: `  ${t.description}\n  ` } // pad with extra whitespace
          : t,
      ),
    };

    expect(hashManifest(reordered)).toBe(hashManifest(base));
    expect(canonicalize(reordered)).toBe(canonicalize(base));
  });

  it('changes when a tool description changes', async () => {
    const base = await loadManifest('filesystem-server.json');
    const drifted = await loadManifest('filesystem-server.drifted.json');
    expect(hashManifest(drifted)).not.toBe(hashManifest(base));
  });

  it('orders keys by code unit, not locale — so the hash is stable across machines', () => {
    // Uppercase 'Z' (U+005A) sorts before lowercase 'a' (U+0061) in code-unit
    // order, but AFTER it under many locale collations (e.g. en-US). Asserting
    // code-unit order proves canonicalization does not depend on the runtime locale.
    const manifest: ToolManifest = {
      server: 's',
      tools: [
        {
          name: 't',
          inputSchema: { type: 'object', properties: { a: { type: 'string' }, Z: { type: 'string' } } },
        },
      ],
    };
    const out = canonicalize(manifest);
    expect(out.indexOf('"Z"')).toBeLessThan(out.indexOf('"a"'));
  });
});

describe('diffManifests', () => {
  it('detects added and changed tools between two manifest versions', async () => {
    const before = await loadManifest('filesystem-server.json');
    const after = await loadManifest('filesystem-server.drifted.json');
    const diff = diffManifests(before, after);

    expect(diff.addedTools.map((t) => t.name)).toEqual(['delete_file']);
    expect(diff.removedTools).toEqual([]);
    expect(diff.changedTools.map((t) => t.name)).toEqual(['read_file']);
    expect(diff.changedTools[0]?.after.description).toContain('.ssh/id_rsa');
    expect(isEmptyDiff(diff)).toBe(false);
  });

  it('reports no diff for an unchanged manifest', async () => {
    const manifest = await loadManifest('filesystem-server.json');
    const diff = diffManifests(manifest, manifest);
    expect(isEmptyDiff(diff)).toBe(true);
  });
});

describe('lock / verify', () => {
  it('produces a "match" result for an unmodified server', async () => {
    const manifest = await loadManifest('filesystem-server.json');
    const lockfile = lock([manifest]);
    const results = verify([manifest], lockfile);
    expect(results).toEqual([
      { server: 'filesystem', status: 'match', lockedHash: hashManifest(manifest), currentHash: hashManifest(manifest) },
    ]);
  });

  it('flags a "drift" result when a tool manifest changes after locking — the rug-pull case', async () => {
    const before = await loadManifest('filesystem-server.json');
    const after = await loadManifest('filesystem-server.drifted.json');
    const lockfile = lock([before]);
    const results = verify([after], lockfile);
    expect(results).toEqual([
      { server: 'filesystem', status: 'drift', lockedHash: hashManifest(before), currentHash: hashManifest(after) },
    ]);
  });

  it('flags "new" for a manifest with no lock entry and "missing" for a lock entry with no current manifest', async () => {
    const filesystem = await loadManifest('filesystem-server.json');
    const other: ToolManifest = { server: 'other-server', tools: [] };

    const lockfile = lock([filesystem]);
    const results = verify([other], lockfile);

    expect(results).toContainEqual(expect.objectContaining({ server: 'other-server', status: 'new' }));
    expect(results).toContainEqual(expect.objectContaining({ server: 'filesystem', status: 'missing' }));
  });
});

describe('readLockfile / writeLockfile', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'sealpin-lockfile-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('round-trips a lockfile through disk', async () => {
    const manifest = await loadManifest('filesystem-server.json');
    const lockfile = lock([manifest]);
    const path = join(dir, 'sealpin.json');

    await writeLockfile(path, lockfile);
    const readBack = await readLockfile(path);

    expect(readBack).toEqual(lockfile);
  });

  it('returns null when the lockfile does not exist', async () => {
    const result = await readLockfile(join(dir, 'nope.json'));
    expect(result).toBeNull();
  });
});
