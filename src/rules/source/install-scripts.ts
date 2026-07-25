import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'] as const;

/**
 * A8 — install-time code execution. preinstall/install/postinstall scripts run
 * automatically during `npm install`, before you ever call a tool and before
 * any manifest review. sealpin itself never runs them; this rule flags their
 * mere presence so you can inspect them.
 */
export const installScriptsRule: Rule = {
  id: 'MCP-S002',
  severity: 'high',
  confidence: 'certain',
  category: 'supply-chain',
  async check(ctx) {
    const pkg = ctx.source?.packageJson;
    if (!isRecord(pkg)) return [];
    const scripts = pkg['scripts'];
    if (!isRecord(scripts)) return [];

    const findings = [];
    for (const hook of INSTALL_HOOKS) {
      const cmd = scripts[hook];
      if (typeof cmd !== 'string' || cmd.trim().length === 0) continue;
      findings.push(
        makeFinding('MCP-S002', ctx.server.name, {
          location: { file: `${ctx.source?.root ?? ''}/package.json`.replace(/\\/g, '/') },
          message: `Package defines a "${hook}" script that runs automatically on install.`,
          evidence: snippet(`"${hook}": ${JSON.stringify(cmd)}`),
          rationale:
            'Install hooks execute on `npm install` — before the server is ever run and before any tool review. This is a standard place to hide code that steals credentials or establishes persistence, and it runs even if you never call a single tool.',
          remediation: 'Read the script. If it does anything beyond a trivial local build step, do not install with scripts enabled (`npm install --ignore-scripts`) and raise it with the maintainer.',
        }),
      );
    }
    return findings;
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
