import type { Finding } from '../types/rule.js';

export const MAX_EVIDENCE = 160;

/**
 * Truncates a snippet for the `evidence` field so a malicious server can't
 * blow up the report with a megabyte-long description, and collapses newlines
 * so multi-line payloads stay on one line in the output.
 */
export function snippet(text: string, max = MAX_EVIDENCE): string {
  const oneLine = text.replace(/\r?\n/g, '\\n');
  if (oneLine.length <= max) return oneLine;
  return oneLine.slice(0, max - 1) + '…';
}

/**
 * Renders any character as a visible token, so zero-width and control
 * characters (which are invisible in a terminal by definition) show up in
 * evidence as e.g. U+200B instead of nothing at all.
 */
export function codepoint(ch: string): string {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return '?';
  return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
}

export interface FindingInit extends Omit<Finding, 'ruleId' | 'server'> {}

/** Small factory so each rule doesn't repeat ruleId/server plumbing. */
export function makeFinding(ruleId: string, server: string, init: FindingInit): Finding {
  return { ruleId, server, ...init };
}
