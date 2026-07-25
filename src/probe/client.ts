import { spawn } from 'node:child_process';
import { z } from 'zod';
import { ToolSchema, type Tool } from '../types/manifest.js';
import { drainLines, encodeNotification, encodeRequest, isJsonRpcResponse, type JsonRpcResponse } from './jsonrpc.js';
import { killTree } from './kill-tree.js';

/** Protocol version we advertise. Servers negotiate down if they must. */
export const PROTOCOL_VERSION = '2024-11-05';

/** Hard ceiling on bytes read from the child, to stop a server flooding us into OOM. */
export const DEFAULT_MAX_OUTPUT_BYTES = 5 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 10_000;

export interface ProbeClientOptions {
  command: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

const ToolsListResult = z.object({
  tools: z.array(z.unknown()),
  nextCursor: z.string().optional(),
});

interface Pending {
  resolve(res: JsonRpcResponse): void;
  reject(err: Error): void;
}

/**
 * Runs the MCP stdio handshake (initialize → initialized → tools/list, with
 * pagination) against an already-sandbox-wrapped command, and returns the
 * validated tools. Enforces a hard timeout and an output byte cap; kills the
 * whole process tree on completion, timeout, or error.
 */
export async function handshakeToolsList(opts: ProbeClientOptions): Promise<Tool[]> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  const child = spawn(opts.command, opts.args, {
    env: opts.env,
    cwd: opts.cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
    // detached so we can signal the whole group on POSIX; killTree handles win32.
    detached: process.platform !== 'win32',
  });

  const pending = new Map<number, Pending>();
  let nextId = 1;
  let stdoutBuf = '';
  let stderrTail = '';
  let bytesRead = 0;
  let settled = false;

  return await new Promise<Tool[]>((resolve, reject) => {
    const timer = setTimeout(() => {
      finish(new Error(`probe timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref?.();

    function finish(err: Error): void;
    function finish(err: null, value: Tool[]): void;
    function finish(err: Error | null, value?: Tool[]): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const p of pending.values()) p.reject(err ?? new Error('probe ended'));
      pending.clear();
      killTree(child);
      if (err) reject(err);
      else resolve(value ?? []);
    }

    function request(method: string, params?: unknown): Promise<JsonRpcResponse> {
      const id = nextId++;
      return new Promise<JsonRpcResponse>((res, rej) => {
        pending.set(id, { resolve: res, reject: rej });
        write(encodeRequest(id, method, params));
      });
    }

    function write(line: string): void {
      if (child.stdin && !child.stdin.destroyed) child.stdin.write(line);
    }

    // Surface the child's stderr tail on failure — otherwise a sandbox that
    // refuses to start (e.g. "bwrap: Creating new namespace failed") is an
    // undiagnosable "exited code 1".
    const withStderr = (msg: string): string => (stderrTail.trim() ? `${msg} — stderr: ${stderrTail.trim()}` : msg);

    child.on('error', (err) => finish(new Error(withStderr(`failed to launch server: ${err.message}`))));
    child.on('exit', (code, signal) => {
      if (!settled) finish(new Error(withStderr(`server exited before handshake completed (code=${code}, signal=${signal})`)));
    });

    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      bytesRead += Buffer.byteLength(chunk, 'utf-8');
      if (bytesRead > maxBytes) {
        finish(new Error(`server exceeded output cap of ${maxBytes} bytes`));
        return;
      }
      stdoutBuf += chunk;
      const { messages, rest } = drainLines(stdoutBuf);
      stdoutBuf = rest;
      for (const msg of messages) {
        if (!isJsonRpcResponse(msg)) continue; // notifications/requests from server: ignore
        const p = pending.get(msg.id);
        if (!p) continue;
        pending.delete(msg.id);
        p.resolve(msg);
      }
    });
    // stderr is protocol-agnostic logging; drain it so the pipe can't fill and
    // block the child, but count it toward the byte cap.
    child.stderr.setEncoding('utf-8');
    child.stderr.on('data', (chunk: string) => {
      bytesRead += Buffer.byteLength(chunk, 'utf-8');
      stderrTail = (stderrTail + chunk).slice(-2048); // keep a bounded tail for diagnostics
      if (bytesRead > maxBytes) finish(new Error(`server exceeded output cap of ${maxBytes} bytes`));
    });

    void run();

    async function run(): Promise<void> {
      try {
        const init = await request('initialize', {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: 'sealpin', version: '0.1.0' },
        });
        if (init.error) throw new Error(`initialize failed: ${init.error.message}`);

        write(encodeNotification('notifications/initialized'));

        const tools: Tool[] = [];
        let cursor: string | undefined;
        do {
          const res = await request('tools/list', cursor ? { cursor } : {});
          if (res.error) throw new Error(`tools/list failed: ${res.error.message}`);
          const parsed = ToolsListResult.parse(res.result);
          for (const raw of parsed.tools) {
            // Each tool is hostile input — validate before it reaches any rule.
            tools.push(ToolSchema.parse(raw));
          }
          cursor = parsed.nextCursor;
        } while (cursor);

        finish(null, tools);
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)));
      }
    }
  });
}
