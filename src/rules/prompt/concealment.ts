import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

// eslint-disable-next-line no-control-regex
const ANSI_ESCAPE = /\[[0-9;]*[A-Za-z]/;
const HTML_COMMENT = /<!--[\s\S]*?-->/;
// A run of base64-ish characters long enough to encode a meaningful payload,
// and not obviously a normal word.
const BASE64_BLOB = /\b[A-Za-z0-9+/]{40,}={0,2}\b/;

export const ansiEscapeRule: Rule = {
  id: 'MCP-P003',
  severity: 'medium',
  confidence: 'certain',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const m = ANSI_ESCAPE.exec(tool.description ?? '');
      if (!m) continue;
      findings.push(
        makeFinding('MCP-P003', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" description contains ANSI escape sequences.`,
          evidence: snippet(JSON.stringify(m[0])),
          rationale:
            'ANSI escape sequences let a description overwrite or hide text in a terminal, so a reviewer reading the raw description in a console can be shown something different from what the model receives.',
          remediation: 'Tool descriptions should be plain text. Reject descriptions carrying terminal control sequences.',
        }),
      );
    }
    return findings;
  },
};

export const htmlCommentRule: Rule = {
  id: 'MCP-P004',
  severity: 'medium',
  confidence: 'likely',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const m = HTML_COMMENT.exec(tool.description ?? '');
      if (!m) continue;
      findings.push(
        makeFinding('MCP-P004', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" description contains an HTML comment.`,
          evidence: snippet(m[0]),
          rationale:
            'HTML comments are hidden when a description is rendered as markdown in a client UI, but the model still reads the raw string. This is a way to hide instructions from a human reviewing the rendered description.',
          remediation: 'Inspect the comment contents. Legitimate descriptions rarely need HTML comments; treat hidden instructions as a poisoning attempt.',
        }),
      );
    }
    return findings;
  },
};

export const base64BlobRule: Rule = {
  id: 'MCP-P005',
  severity: 'low',
  confidence: 'possible',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const m = BASE64_BLOB.exec(tool.description ?? '');
      if (!m) continue;
      findings.push(
        makeFinding('MCP-P005', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" description contains a long base64-like blob.`,
          evidence: snippet(m[0]),
          rationale:
            'A long opaque base64 string in a human-readable description is unusual and can encode an instruction or payload that is not visible in plain text. This is a weak signal on its own (it may be a legitimate example value), hence low severity.',
          remediation: 'Decode the blob and confirm it is benign. If it decodes to instructions or unexpected data, treat the description as poisoned.',
        }),
      );
    }
    return findings;
  },
};
