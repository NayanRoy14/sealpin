import { spawn } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { killTree } from '../probe/kill-tree.js';
import type { Tool } from '../types/manifest.js';
import { ProxyEngine, type AuditEvent, type JsonRpcMessage } from './engine.js';
import type { Policy } from './policy.js';

export interface RunProxyOptions {
  command: string;
  args: string[];
  serverName: string;
  policy?: Policy;
  lockedTools?: Tool[];
  dryRun?: boolean;
  onAudit?: (event: AuditEvent) => void;
  /** Client-side streams. Default to the process stdio; overridable for testing. */
  input?: Readable;
  output?: Writable;
}

/**
 * Runs the MCP enforcement proxy: spawns the real server and pipes JSON-RPC in
 * both directions through the ProxyEngine, which forwards, blocks, or rewrites
 * each message. The proxy is transparent when nothing is blocked. Resolves with
 * the exit code to use.
 */
export function runProxy(opts: RunProxyOptions): Promise<number> {
  const engine = new ProxyEngine({
    serverName: opts.serverName,
    ...(opts.policy ? { policy: opts.policy } : {}),
    ...(opts.lockedTools ? { lockedTools: opts.lockedTools } : {}),
    ...(opts.dryRun ? { dryRun: true } : {}),
    ...(opts.onAudit ? { onAudit: opts.onAudit } : {}),
  });

  const input = opts.input ?? process.stdin;
  const output = opts.output ?? process.stdout;

  const child = spawn(opts.command, opts.args, {
    stdio: ['pipe', 'pipe', 'inherit'], // server stderr (its logs) passes straight to ours
    env: process.env,
    windowsHide: true,
  });

  const writeLine = (stream: Writable, msg: JsonRpcMessage): void => {
    if (!stream.destroyed) stream.write(JSON.stringify(msg) + '\n');
  };

  // client → engine → server (or a blocked reply straight back to the client)
  wireLines(input, (line) => {
    const msg = tryParse(line);
    if (!msg) {
      if (child.stdin && !child.stdin.destroyed) child.stdin.write(line + '\n');
      return;
    }
    const out = engine.handleClientMessage(msg);
    if (out.toServer && child.stdin) writeLine(child.stdin, out.toServer);
    if (out.toClient) writeLine(output, out.toClient);
  });

  // server → engine → client
  wireLines(child.stdout, (line) => {
    const msg = tryParse(line);
    if (!msg) {
      output.write(line + '\n');
      return;
    }
    const out = engine.handleServerMessage(msg);
    if (out.toClient) writeLine(output, out.toClient);
  });

  if (input === process.stdin) {
    const shutdown = (): void => killTree(child);
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }
  input.on('end', () => {
    if (child.stdin && !child.stdin.destroyed) child.stdin.end();
  });

  return new Promise<number>((resolve) => {
    child.on('error', (err) => {
      process.stderr.write(`sealpin proxy: failed to launch server: ${err.message}\n`);
      resolve(3);
    });
    child.on('exit', (code) => resolve(code ?? 0));
  });
}

/** Split a stream into newline-delimited lines and invoke `onLine` for each. */
function wireLines(stream: Readable, onLine: (line: string) => void): void {
  let buffer = '';
  stream.setEncoding('utf-8');
  stream.on('data', (chunk: string) => {
    buffer += chunk;
    let nl: number;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      if (line.length > 0) onLine(line);
    }
  });
  stream.on('end', () => {
    if (buffer.trim().length > 0) onLine(buffer);
  });
}

function tryParse(line: string): JsonRpcMessage | null {
  const t = line.trim();
  if (!t) return null;
  try {
    const v = JSON.parse(t);
    return typeof v === 'object' && v !== null ? (v as JsonRpcMessage) : null;
  } catch {
    return null;
  }
}
