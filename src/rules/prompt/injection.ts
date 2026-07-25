import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';

/**
 * Patterns that signal a tool description is talking to the *model* rather
 * than documenting the tool for a human. Split into two tiers:
 *
 *  - `secretAccess` / `exfil`: high-signal. A description that instructs the
 *    model to read credentials or send data somewhere is almost never benign.
 *  - `imperative`: medium-signal. Model-directed imperatives ("before calling
 *    any tool, ...", "ignore previous instructions") that are suspicious in
 *    aggregate, especially alongside a secret/exfil hit.
 */
const SECRET_ACCESS: RegExp[] = [
  /\.ssh\b|id_rsa|id_ed25519/i,
  /\.aws[\\/]credentials|\baws_secret_access_key\b/i,
  /\.env\b|process\.env|environment variables?/i,
  /~?[\\/]?\.?(?:npmrc|netrc|kube[\\/]config|docker[\\/]config)/i,
  /\b(?:api[_-]?key|secret|token|password|credential)s?\b/i,
];

const EXFIL: RegExp[] = [
  /\binclude\b[^.]{0,60}\b(?:contents?|value|output)\b[^.]{0,60}\b(?:response|context|argument|parameter)\b/i,
  /\bsend\b[^.]{0,40}\b(?:to|https?:\/\/)/i,
  /\b(?:exfiltrat|leak|upload|post)\w*\b[^.]{0,40}\b(?:to|https?:\/\/)/i,
];

const IMPERATIVE: RegExp[] = [
  /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\b/i,
  /\bbefore\s+(?:calling|using|invoking|returning|you\s+(?:call|use|respond))\b/i,
  /\b(?:do\s*not|don't|never)\s+(?:tell|inform|mention|reveal|show|disclose)\b[^.]{0,40}\b(?:user|human|them)\b/i,
  /\b(?:system|developer)\s+prompt\b/i,
  /\byou\s+(?:must|should|will|are\s+required\s+to)\b/i,
  /<\s*(?:important|system|instructions?)\s*>/i,
];

interface Hit {
  tier: 'secret' | 'exfil' | 'imperative';
  match: string;
}

function scan(text: string): Hit[] {
  const hits: Hit[] = [];
  for (const re of SECRET_ACCESS) {
    const m = re.exec(text);
    if (m) hits.push({ tier: 'secret', match: m[0] });
  }
  for (const re of EXFIL) {
    const m = re.exec(text);
    if (m) hits.push({ tier: 'exfil', match: m[0] });
  }
  for (const re of IMPERATIVE) {
    const m = re.exec(text);
    if (m) hits.push({ tier: 'imperative', match: m[0] });
  }
  return hits;
}

export const injectionRule: Rule = {
  id: 'MCP-P001',
  severity: 'critical',
  confidence: 'likely',
  category: 'prompt',
  async check(ctx) {
    const findings = [];
    for (const tool of ctx.manifest.tools) {
      const text = `${tool.description ?? ''}\n${tool.annotations?.title ?? ''}`;
      const hits = scan(text);
      if (hits.length === 0) continue;

      const hasSecret = hits.some((h) => h.tier === 'secret');
      const hasExfil = hits.some((h) => h.tier === 'exfil');
      const hasImperative = hits.some((h) => h.tier === 'imperative');

      // Require more than a lone keyword: either a secret+exfil pair, a
      // secret/exfil hit alongside a model-directed imperative, or two
      // distinct imperatives. A single "token" mention on its own is far too
      // common in legitimate descriptions to flag.
      const strong = (hasSecret && hasExfil) || ((hasSecret || hasExfil) && hasImperative);
      const imperativeCount = hits.filter((h) => h.tier === 'imperative').length;
      if (!strong && imperativeCount < 2) continue;

      findings.push(
        makeFinding('MCP-P001', ctx.server.name, {
          location: { tool: tool.name },
          message: `Tool "${tool.name}" description contains instructions directed at the model, not documentation for a human.`,
          evidence: snippet(hits.map((h) => `[${h.tier}] ${h.match}`).join('  ·  ')),
          rationale:
            'The description field is injected verbatim into the model context as trusted tool documentation. Text that instructs the model to read credentials, exfiltrate data, or override prior instructions is a tool-poisoning payload (OWASP LLM01): the user never sees the description, but the model always does.',
          remediation:
            'Do not install or update this server until the maintainer removes the model-directed instructions. If you trust the source, open an issue quoting the flagged text and pin the last known-good manifest with `sealpin lock`.',
        }),
      );
    }
    return findings;
  },
};
