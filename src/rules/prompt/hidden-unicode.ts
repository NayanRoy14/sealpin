import type { Rule } from '../../types/rule.js';
import { codepoint, makeFinding } from '../util.js';

/**
 * Characters that are invisible (or misleading) to a human reviewer but are
 * still tokenized and read by the model. A payload hidden in these can say one
 * thing on screen and another to the model.
 */
function classify(cp: number): string | null {
  // Zero-width and joiners
  if (cp === 0x200b) return 'zero-width space';
  if (cp === 0x200c) return 'zero-width non-joiner';
  if (cp === 0x200d) return 'zero-width joiner';
  if (cp === 0xfeff) return 'zero-width no-break space (BOM)';
  if (cp === 0x2060) return 'word joiner';
  // Bidirectional overrides — used to visually reorder text
  if (cp >= 0x202a && cp <= 0x202e) return 'bidirectional override';
  if (cp >= 0x2066 && cp <= 0x2069) return 'bidirectional isolate';
  // Unicode Tags block — invisible, historically abused to smuggle ASCII
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'Unicode tag character';
  // Other format/control characters (excluding ordinary whitespace)
  if (cp === 0x00ad) return 'soft hyphen';
  if (cp >= 0x2000 && cp <= 0x200a) return 'exotic whitespace';
  return null;
}

export const hiddenUnicodeRule: Rule = {
  id: 'MCP-P002',
  severity: 'high',
  confidence: 'certain',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const text = tool.description ?? '';
      const offenders = new Map<string, { label: string; count: number }>();
      for (const ch of text) {
        const cp = ch.codePointAt(0);
        if (cp === undefined) continue;
        const label = classify(cp);
        if (!label) continue;
        const key = codepoint(ch);
        const existing = offenders.get(key);
        if (existing) existing.count += 1;
        else offenders.set(key, { label, count: 1 });
      }
      if (offenders.size === 0) continue;

      const evidence = [...offenders.entries()]
        .map(([cpStr, { label, count }]) => `${cpStr} (${label})×${count}`)
        .join(', ');

      findings.push(
        makeFinding('MCP-P002', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" description contains ${offenders.size} kind(s) of hidden or invisible Unicode characters.`,
          evidence,
          rationale:
            'Zero-width, bidirectional-override, and Unicode-tag characters are invisible in a normal review but are tokenized and read by the model. They are a standard way to hide a prompt-injection payload from a human while delivering it to the model.',
          remediation:
            'Treat any hidden characters in a tool description as hostile. Inspect the raw bytes of the description, and do not update to this version until the maintainer explains and removes them.',
        }),
      );
    }
    return findings;
  },
};
