import { homedir } from 'node:os';
import { readFile, readdir, stat } from 'node:fs/promises';
import { dirname, extname, isAbsolute, join, relative, resolve as resolvePath } from 'node:path';
import type { ServerConfig } from '../types/config.js';
import type { ServerSource, SourceFile, SourceResolver } from './types.js';

const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out']);
const MAX_FILES = 300;
const MAX_FILE_BYTES = 512 * 1024;

export interface LocalSourceResolverOptions {
  /** Explicit source root applied to every server (e.g. --source-dir). */
  dir?: string;
  /** Base directory for resolving relative paths found in server args. */
  cwd?: string;
}

/**
 * Resolves a server's source from the local filesystem — no network, no
 * execution. Two strategies, in order:
 *   1. An explicit `dir` (from --source-dir), applied to every server.
 *   2. Auto-detection, deliberately conservative: an arg that is a local
 *      *source file* (walked up to its package root), or a *directory that
 *      directly contains package.json*. Arbitrary data directories and
 *      filesystem/drive/home roots are never treated as source — a
 *      filesystem server's `/` argument is its operating target, not its code.
 * Returns null when no local source can be found (a plain `npx <pkg>` server
 * whose code only exists in the registry — that's the tarball resolver's job,
 * which is future work).
 */
export class LocalSourceResolver implements SourceResolver {
  private readonly dir: string | undefined;
  private readonly cwd: string;

  constructor(options: LocalSourceResolverOptions = {}) {
    this.dir = options.dir;
    this.cwd = options.cwd ?? process.cwd();
  }

  async resolve(server: ServerConfig): Promise<ServerSource | null> {
    const root = this.dir ? resolvePath(this.cwd, this.dir) : await this.detectRoot(server);
    if (!root) return null;
    if (!(await isDirectory(root))) return null;

    const packageJson = await readPackageJson(root);
    const files = await collectSourceFiles(root);
    return { root, packageJson, files };
  }

  private async detectRoot(server: ServerConfig): Promise<string | null> {
    for (const arg of server.args) {
      if (arg.startsWith('-')) continue; // flag, not a path
      const candidate = isAbsolute(arg) ? arg : join(this.cwd, arg);
      let info;
      try {
        info = await stat(candidate);
      } catch {
        continue; // not an existing local path
      }

      if (info.isFile()) {
        // Only a source file identifies the package; data files do not.
        if (!SOURCE_EXT.has(extname(candidate).toLowerCase())) continue;
        const dir = dirname(candidate);
        return (await nearestPackageRoot(dir)) ?? dir;
      }

      if (info.isDirectory()) {
        // A directory is source only if it is itself a package (has
        // package.json). This deliberately excludes filesystem/drive/home
        // roots and arbitrary data directories a server merely operates on.
        if (isDangerousRoot(candidate)) continue;
        if (await hasPackageJson(candidate)) return candidate;
      }
    }
    return null;
  }
}

function isDangerousRoot(path: string): boolean {
  const p = path.replace(/[\\/]+$/, '') || '/';
  if (p === '' || p === '/') return true;
  if (/^[A-Za-z]:$/.test(p)) return true; // drive root (C:)
  if (p === homedir().replace(/[\\/]+$/, '')) return true;
  return false;
}

async function hasPackageJson(dir: string): Promise<boolean> {
  try {
    return (await stat(join(dir, 'package.json'))).isFile();
  } catch {
    return false;
  }
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

async function readPackageJson(root: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(join(root, 'package.json'), 'utf-8'));
  } catch {
    return null;
  }
}

/** Walk up from `startDir` to the nearest directory containing package.json. */
async function nearestPackageRoot(startDir: string): Promise<string | null> {
  let dir = startDir;
  for (let i = 0; i < 20; i++) {
    try {
      await stat(join(dir, 'package.json'));
      return dir;
    } catch {
      /* keep walking */
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

async function collectSourceFiles(root: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];

  async function walk(dir: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        await walk(full);
      } else if (entry.isFile()) {
        const dot = entry.name.lastIndexOf('.');
        const ext = dot === -1 ? '' : entry.name.slice(dot);
        if (!SOURCE_EXT.has(ext)) continue;
        if (entry.name.endsWith('.d.ts')) continue;
        try {
          const info = await stat(full);
          if (info.size > MAX_FILE_BYTES) continue;
          const content = await readFile(full, 'utf-8');
          files.push({ path: full, relPath: relative(root, full).replace(/\\/g, '/'), content });
        } catch {
          /* unreadable file: skip */
        }
      }
    }
  }

  await walk(root);
  return files;
}
