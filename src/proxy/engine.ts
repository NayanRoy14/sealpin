import { canonicalizeTool } from '../lockfile/canonicalize.js';
import type { Tool } from '../types/manifest.js';
import { evaluateToolCall, resolveServerPolicy, type Policy, type ServerPolicy } from './policy.js';

export type JsonRpcMessage = Record<string, unknown>;

export interface AuditEvent {
  ts: string;
  server: string;
  kind: 'tool-call' | 'drift' | 'blocked';
  tool?: string;
  decision?: 'allow' | 'deny';
  reason?: string;
  detail?: string;
}

export interface ClientOutcome {
  /** Forward this message on to the real server. */
  toServer?: JsonRpcMessage;
  /** Answer the client directly (a blocked call), without touching the server. */
  toClient?: JsonRpcMessage;
}

export interface ServerOutcome {
  toClient?: JsonRpcMessage;
}

export interface ProxyEngineOptions {
  serverName: string;
  policy?: Policy;
  /** Locked manifest tools for this server (from sealpin.json) — enables drift blocking. */
  lockedTools?: Tool[];
  /** Log decisions but do not block anything. */
  dryRun?: boolean;
  onAudit?: (event: AuditEvent) => void;
}

const POLICY_DENY_CODE = -32001;

/**
 * The pure decision core of the MCP proxy. It sees every JSON-RPC message in
 * both directions and decides what to forward, block, or rewrite — with no I/O,
 * so it can be exhaustively unit-tested. proxy.ts wires it to real streams.
 */
export class ProxyEngine {
  private readonly sp: ServerPolicy;
  private readonly lockedByName: Map<string, string> | undefined;
  private readonly pending = new Map<string | number, string>();

  constructor(private readonly opts: ProxyEngineOptions) {
    this.sp = resolveServerPolicy(opts.policy, opts.serverName);
    if (opts.lockedTools) {
      this.lockedByName = new Map(opts.lockedTools.map((t) => [t.name, canonicalizeTool(t)]));
    }
  }

  private audit(event: Omit<AuditEvent, 'ts' | 'server'>): void {
    this.opts.onAudit?.({ ts: new Date().toISOString(), server: this.opts.serverName, ...event });
  }

  /** A message travelling client → server. */
  handleClientMessage(msg: JsonRpcMessage): ClientOutcome {
    const method = typeof msg['method'] === 'string' ? (msg['method'] as string) : undefined;
    const id = msg['id'] as string | number | undefined;
    if (method && id !== undefined) this.pending.set(id, method);

    if (method === 'tools/call') {
      const params = isRecord(msg['params']) ? msg['params'] : {};
      const toolName = typeof params['name'] === 'string' ? (params['name'] as string) : '(unknown)';
      const decision = evaluateToolCall(this.sp, toolName, params['arguments']);

      this.audit({ kind: 'tool-call', tool: toolName, decision: decision.deny ? 'deny' : 'allow', ...(decision.reason ? { reason: decision.reason } : {}) });

      if (decision.deny && !this.opts.dryRun) {
        this.audit({ kind: 'blocked', tool: toolName, ...(decision.reason ? { reason: decision.reason } : {}) });
        return { toClient: errorResponse(id, POLICY_DENY_CODE, `Blocked by sealpin policy: ${decision.reason ?? 'denied'}`) };
      }
    }
    return { toServer: msg };
  }

  /** A message travelling server → client. */
  handleServerMessage(msg: JsonRpcMessage): ServerOutcome {
    const id = msg['id'] as string | number | undefined;
    const isResponse = id !== undefined && ('result' in msg || 'error' in msg);
    if (!isResponse) return { toClient: msg };

    const method = this.pending.get(id);
    if (method !== undefined) this.pending.delete(id);
    if (method !== 'tools/list' || !this.lockedByName) return { toClient: msg };

    const result = isRecord(msg['result']) ? msg['result'] : undefined;
    const liveTools = result && Array.isArray(result['tools']) ? (result['tools'] as unknown[]) : undefined;
    if (!liveTools) return { toClient: msg };

    const { drifted, safe } = this.driftCheck(liveTools);
    if (drifted.length === 0) return { toClient: msg };

    this.audit({ kind: 'drift', reason: `${drifted.length} tool(s) changed since lock`, detail: drifted.join(', ') });

    if (!this.blockOnDrift() || this.opts.dryRun) return { toClient: msg };

    // Serve only the tools that still match the lock; the model never sees the drifted ones.
    for (const name of drifted) this.audit({ kind: 'blocked', tool: name, reason: 'tool definition drifted from lockfile' });
    return { toClient: { ...msg, result: { ...result, tools: safe } } };
  }

  private blockOnDrift(): boolean {
    return this.sp.blockOnDrift === true;
  }

  private driftCheck(liveTools: unknown[]): { drifted: string[]; safe: unknown[] } {
    const locked = this.lockedByName!;
    const drifted: string[] = [];
    const safe: unknown[] = [];
    for (const raw of liveTools) {
      const name = isRecord(raw) && typeof raw['name'] === 'string' ? (raw['name'] as string) : '(unnamed)';
      const lockedCanon = locked.get(name);
      if (lockedCanon === undefined) {
        drifted.push(`${name} (new)`);
        continue;
      }
      let canon: string;
      try {
        canon = canonicalizeTool(raw as Tool);
      } catch {
        drifted.push(name);
        continue;
      }
      if (canon === lockedCanon) safe.push(raw);
      else drifted.push(name);
    }
    return { drifted, safe };
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function errorResponse(id: string | number | undefined, code: number, message: string): JsonRpcMessage {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}
