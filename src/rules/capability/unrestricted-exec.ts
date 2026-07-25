import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

const SHELL_SERVER = /shell|terminal|command|exec|bash|\bsh\b|powershell|cmd/i;
// Signs that the operator constrained what the shell can run.
const ALLOWLIST_HINT = /allow|whitelist|permit|only|restrict|command[s]?=/i;

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
    const surface = `${name} ${command} ${args.join(' ')}`;
    if (!SHELL_SERVER.test(surface)) return [];

    const configuredSurface = `${args.join(' ')} ${Object.keys(env).join(' ')}`;
    if (ALLOWLIST_HINT.test(configuredSurface)) return [];

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
