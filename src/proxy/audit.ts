import { appendFileSync } from 'node:fs';
import type { AuditEvent } from './engine.js';

/**
 * Builds an audit sink. Audit output must NEVER go to stdout — that is the MCP
 * protocol channel to the client. It goes to a JSONL file (if given) or stderr.
 */
export function createAuditSink(path?: string): (event: AuditEvent) => void {
  return (event: AuditEvent) => {
    if (path) {
      try {
        appendFileSync(path, JSON.stringify(event) + '\n');
      } catch {
        /* never let auditing break the proxy */
      }
      return;
    }
    const parts = [`[sealpin:${event.server}]`, event.kind];
    if (event.tool) parts.push(event.tool);
    if (event.decision) parts.push(event.decision.toUpperCase());
    if (event.reason) parts.push(`— ${event.reason}`);
    process.stderr.write(parts.join(' ') + '\n');
  };
}
