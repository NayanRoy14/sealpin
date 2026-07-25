import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

/**
 * A3 — tool shadowing. When two servers in the same scan expose a tool with
 * the same name, both definitions land in one model context window. A benign
 * server's tool can be shadowed by a malicious server redefining the same
 * name, or a description on one can alter how the model uses the other.
 */
export const shadowingRule: Rule = {
  id: 'MCP-P006',
  severity: 'high',
  confidence: 'likely',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const collidingServers = ctx.workspace
        .filter((m) => m.server !== ctx.manifest.server)
        .filter((m) => m.tools.some((t) => t.name === tool.name))
        .map((m) => m.server);

      if (collidingServers.length === 0) continue;

      findings.push(
        makeFinding('MCP-P006', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" collides with a tool of the same name on: ${collidingServers.join(', ')}.`,
          evidence: snippet(`${ctx.manifest.server}.${tool.name} vs ${collidingServers.map((s) => `${s}.${tool.name}`).join(', ')}`),
          rationale:
            'Multiple servers exposing the same tool name share one model context window. A malicious or compromised server can redefine a trusted tool name, or use its description to change how the model invokes a namesake on another server (cross-server contamination).',
          remediation:
            'Confirm each colliding server is trusted, or disambiguate by running them in separate agents/contexts. Be especially wary if one of the colliding servers was recently added or updated.',
        }),
      );
    }
    return findings;
  },
};
