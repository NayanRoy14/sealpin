/**
 * Minimal JSON-RPC 2.0 over MCP's stdio transport: each message is a single
 * line of UTF-8 JSON terminated by '\n', with no embedded newlines. We
 * hand-roll this rather than depend on the MCP SDK so the probe stays a small,
 * auditable surface with full control over byte caps and framing — the probe
 * is the one place sealpin runs third-party code, so its dependencies matter.
 */

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: JsonRpcError;
}

export function encodeRequest(id: number, method: string, params?: unknown): string {
  const msg: JsonRpcRequest = { jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) };
  return JSON.stringify(msg) + '\n';
}

export function encodeNotification(method: string, params?: unknown): string {
  const msg: JsonRpcNotification = { jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) };
  return JSON.stringify(msg) + '\n';
}

/** A JSON-RPC response must carry the '2.0' tag, a numeric id, and result xor error. */
export function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return v['jsonrpc'] === '2.0' && typeof v['id'] === 'number' && ('result' in v || 'error' in v);
}

/**
 * Splits a growing buffer into complete lines, returning parsed JSON values
 * and the unconsumed remainder. Non-JSON lines (e.g. a server that logs to
 * stdout instead of stderr) are dropped rather than crashing the parse.
 */
export function drainLines(buffer: string): { messages: unknown[]; rest: string } {
  const messages: unknown[] = [];
  let rest = buffer;
  let nl: number;
  while ((nl = rest.indexOf('\n')) !== -1) {
    const line = rest.slice(0, nl).trim();
    rest = rest.slice(nl + 1);
    if (line.length === 0) continue;
    try {
      messages.push(JSON.parse(line));
    } catch {
      // not a protocol line; ignore
    }
  }
  return { messages, rest };
}
