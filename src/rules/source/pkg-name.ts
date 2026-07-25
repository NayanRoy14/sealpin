import type { ServerConfig } from '../../types/config.js';

const RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'npm', 'pnpx']);
// Subcommands that precede the actual package name for some runners.
const SUBCOMMANDS = new Set(['exec', 'dlx', 'run', 'x']);

/**
 * Extracts the npm package spec a server launches, if any. Handles
 * `npx -y <pkg>`, `pnpm dlx <pkg>`, `npm exec <pkg>`, etc. Returns null for
 * servers that run a local file (`node ./index.js`) or a bare binary, where
 * there is no registry package name to compare against.
 */
export function extractPackageName(server: ServerConfig): string | null {
  const runner = baseName(server.command).toLowerCase();
  if (!RUNNERS.has(runner)) return null;

  for (const arg of server.args) {
    if (arg.startsWith('-')) continue; // flags like -y, --yes
    if (SUBCOMMANDS.has(arg.toLowerCase())) continue;
    if (looksLikePath(arg)) return null; // a local path, not a registry package
    const name = stripVersion(arg);
    if (isValidPackageName(name)) return name;
    return null;
  }
  return null;
}

function baseName(command: string): string {
  const parts = command.split(/[\\/]/);
  const last = parts[parts.length - 1] ?? command;
  return last.replace(/\.(cmd|exe|ps1)$/i, '');
}

function looksLikePath(arg: string): boolean {
  return arg.startsWith('.') || arg.startsWith('/') || arg.startsWith('~') || /^[A-Za-z]:[\\/]/.test(arg);
}

/** `@scope/name@1.2.3` → `@scope/name`; `name@1.2.3` → `name`. */
export function stripVersion(spec: string): string {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash === -1) return spec;
    const at = spec.indexOf('@', slash);
    return at === -1 ? spec : spec.slice(0, at);
  }
  const at = spec.indexOf('@');
  return at <= 0 ? spec : spec.slice(0, at);
}

function isValidPackageName(name: string): boolean {
  return /^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name);
}

/** Damerau-agnostic Levenshtein edit distance. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        (prev[j] ?? 0) + 1, // deletion
        (curr[j - 1] ?? 0) + 1, // insertion
        (prev[j - 1] ?? 0) + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n] ?? 0;
}
