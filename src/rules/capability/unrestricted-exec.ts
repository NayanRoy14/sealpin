import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

// Terms that identify a shell/command server, matched against the server name,
// launched binary, and package spec only (not arbitrary flags/args, so
// `--command-timeout` does not trigger it). Whole-word to avoid substring hits.
const SHELL_TERMS = /\b(shell|terminal|bash|zsh|fish|powershell|pwsh|cmd|exec|execute|repl)\b/i;
// Shell interpreters used directly as the launch binary.
const SHELL_BINARIES = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh']);
// Signs the operator constrained what the shell can run.
const ALLOWLIST_HINT = /allow|whitelist|permit|only|restrict|command[s]?=/i;

function baseName(command: string): string {
  const parts = command.split(/[\\/]/);
  return (parts[parts.length - 1] ?? command).toLowerCase();
}

/** The first non-flag argument, which for a runner is the package/spec. */
function packageSpec(args: string[]): string {
  for (const arg of args) {
    if (!arg.startsWith('-')) return arg;
  }
  return '';
}

/**
 * A5 (exec variant) — a shell/command-execution server with no visible
 * command allowlist. Whatever the model can be talked into running, the
 * server runs on the host.
 */
export const unrestrictedExecRule: Rule = {
  id: 'MCP-C002',
  severity: 'high',
  confidence: 'possible',
  category: 'capability',
  async check(ctx) {
    const { command, args, name, env } = ctx.server;
    const binary = baseName(command);
    const identity = `${name} ${binary} ${packageSpec(args)}`;

    const looksLikeShell = SHELL_BINARIES.has(binary) || SHELL_TERMS.test(identity);
    if (!looksLikeShell) return [];

    // A shell interpreter launched directly is unrestricted regardless of args;
    // otherwise, treat an explicit allowlist hint anywhere in args/env as constrained.
    const configuredSurface = `${args.join(' ')} ${Object.keys(env).join(' ')}`;
    if (!SHELL_BINARIES.has(binary) && ALLOWLIST_HINT.test(configuredSurface)) return [];

    return [
      makeFinding('MCP-C002', name, {
        location: { file: ctx.server.configPath },
        message: `Shell/command server "${name}" has no visible command allowlist.`,
        evidence: snippet(`${command} ${args.join(' ')}`),
        rationale:
          'A command-execution server with no allowlist runs arbitrary commands chosen by the model. Combined with prompt injection reaching the agent, this is direct remote code execution on the host.',
        remediation: 'Configure an explicit command allowlist for the server if it supports one, or replace it with a purpose-built tool that only exposes the specific operations you need.',
      }),
    ];
  },
};
