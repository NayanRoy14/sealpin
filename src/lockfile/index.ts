import { readFile, writeFile } from 'node:fs/promises';
import type { ToolManifest } from '../types/manifest.js';
import { hashManifest } from './hash.js';
import { LockFileSchema, type LockEntry, type LockFile } from './schema.js';

export const DEFAULT_LOCKFILE_NAME = 'sealpin.json';

/** Builds a fresh lockfile from the current set of manifests. */
export function lock(manifests: ToolManifest[]): LockFile {
  const lockedAt = new Date().toISOString();
  const entries: LockEntry[] = manifests.map((manifest) => ({
    server: manifest.server,
    hash: hashManifest(manifest),
    manifest,
    lockedAt,
  }));
  return { version: 1, entries };
}

export type VerifyStatus = 'match' | 'drift' | 'new' | 'missing';

export interface VerifyResult {
  server: string;
  status: VerifyStatus;
  lockedHash?: string;
  currentHash?: string;
}

/**
 * Compares live manifests against a previously written lockfile.
 * 'drift' is the headline case: same server, hash no longer matches — the
 * server changed its tools since it was last locked.
 */
export function verify(manifests: ToolManifest[], lockfile: LockFile): VerifyResult[] {
  const lockedByServer = new Map(lockfile.entries.map((e) => [e.server, e]));
  const currentByServer = new Map(manifests.map((m) => [m.server, m]));

  const results: VerifyResult[] = [];

  for (const [server, manifest] of currentByServer) {
    const entry = lockedByServer.get(server);
    const currentHash = hashManifest(manifest);
    if (!entry) {
      results.push({ server, status: 'new', currentHash });
      continue;
    }
    results.push({
      server,
      status: entry.hash === currentHash ? 'match' : 'drift',
      lockedHash: entry.hash,
      currentHash,
    });
  }

  for (const [server, entry] of lockedByServer) {
    if (!currentByServer.has(server)) {
      results.push({ server, status: 'missing', lockedHash: entry.hash });
    }
  }

  return results;
}

export async function readLockfile(path: string): Promise<LockFile | null> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (isNodeError(err) && err.code === 'ENOENT') return null;
    throw err;
  }
  return LockFileSchema.parse(JSON.parse(raw));
}

export async function writeLockfile(path: string, lockfile: LockFile): Promise<void> {
  await writeFile(path, JSON.stringify(lockfile, null, 2) + '\n', 'utf-8');
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}

export { hashManifest } from './hash.js';
export { canonicalize, canonicalizeTool } from './canonicalize.js';
export { diffManifests, isEmptyDiff, type ManifestDiff, type ChangedTool } from './diff.js';
export { LockFileSchema, LockEntrySchema, type LockFile, type LockEntry } from './schema.js';
