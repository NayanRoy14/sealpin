import { homedir } from 'node:os';
import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

/**
 * A5 — over-broad filesystem scope. The canonical MCP filesystem server takes
 * its allowed roots as positional args. A root of `/`, a drive root, or the
 * user's home directory hands the model (and thus any prompt injection that
 * reaches it) read/write over effectively everything.
 */
function isDangerousRoot(arg: string): string | null {
  const p = arg.trim();
  if (p === '/' ) return 'filesystem root';
  if (/^[A-Za-z]:[\\/]?$/.test(p)) return 'drive root';
  if (p === '~' || p === homedir()) return 'home directory';
  if (/^~[\\/]?$/.test(p)) return 'home directory';
  return null;
}

// Only treat positional args as roots for servers that look like a filesystem
// server, to avoid flagging unrelated paths passed to other tools.
function looksLikeFilesystemServer(command: string, args: string[]): boolean {
  const hay = `${command} ${args.join(' ')}`.toLowerCase();
  return /filesystem|server-filesystem|\bfs\b|file-?system/.test(hay);
}

export const filesystemRootRule: Rule = {
  id: 'MCP-C001',
  severity: 'high',
  confidence: 'likely',
  category: 'capability',
  async check(ctx) {
    const { command, args, name } = ctx.server;
    if (!looksLikeFilesystemServer(command, args)) return [];

    const findings = [];
    for (const arg of args) {
      const kind = isDangerousRoot(arg);
      if (!kind) continue;
      findings.push(
        makeFinding('MCP-C001', name, {
          location: { file: ctx.server.configPath },
          message: `Filesystem server "${name}" is rooted at ${kind} ("${arg}").`,
          evidence: snippet(`${command} ${args.join(' ')}`),
          rationale:
            'A filesystem server grants the model read/write access to every declared root. Rooting it at the filesystem or home directory means any prompt injection that reaches this agent can read secrets (SSH keys, .env, credentials) or overwrite arbitrary files. Declared scope should match the task, not the whole disk.',
          remediation: 'Restrict the server to the narrowest directory it needs (e.g. a single project folder) instead of a drive/home/filesystem root.',
        }),
      );
    }
    return findings;
  },
};
