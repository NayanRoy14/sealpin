import type { Rule } from '../../types/rule.js';
import { makeFinding } from '../util.js';

/**
 * A6 (config variant) — long-lived secrets sitting in plaintext inside the MCP
 * config. These files are world-readable on most setups, sync to the cloud,
 * and get committed to repos (.mcp.json is checked in by design). Every
 * high-signal token pattern here identifies a specific credential type.
 */
const SECRET_PATTERNS: { label: string; re: RegExp }[] = [
  { label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/ },
  { label: 'OpenAI/Anthropic-style key', re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { label: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { label: 'private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
];

// Keys whose name implies a secret even when the value doesn't match a pattern.
const SECRET_KEY_NAME = /token|secret|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key/i;

export const plaintextSecretsRule: Rule = {
  id: 'MCP-C003',
  severity: 'medium',
  confidence: 'likely',
  category: 'capability',
  async check(ctx) {
    const findings = [];
    for (const [key, value] of Object.entries(ctx.server.env)) {
      const matched = SECRET_PATTERNS.find((p) => p.re.test(value));
      const looksSecretByName = SECRET_KEY_NAME.test(key) && value.trim().length > 0;
      if (!matched && !looksSecretByName) continue;

      const label = matched?.label ?? 'secret-named variable';
      findings.push(
        makeFinding('MCP-C003', ctx.server.name, {
          location: { file: ctx.server.configPath },
          message: `Environment variable "${key}" on server "${ctx.server.name}" holds a plaintext ${label}.`,
          // Never echo the secret itself into the report.
          evidence: `${key}=${redact(value)}`,
          rationale:
            'MCP config files are frequently world-readable, synced to the cloud, and (for project-level .mcp.json) committed to source control. Storing a live credential in plaintext there means the secret is exposed to anyone who can read the file, and it is handed to the server process wholesale.',
          remediation: 'Move the secret to a secrets manager or an untracked local env file, and reference it indirectly. Rotate the credential if this config has ever been shared or committed.',
        }),
      );
    }
    return findings;
  },
};

function redact(value: string): string {
  const v = value.trim();
  if (v.length <= 6) return '***';
  return `${v.slice(0, 3)}…${v.slice(-2)} (${v.length} chars)`;
}
