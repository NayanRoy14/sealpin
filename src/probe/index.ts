import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import type { ManifestSource } from '../scan/manifest-source.js';
import { handshakeToolsList, DEFAULT_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES } from './client.js';
import { buildProbeEnv, makeTempCwd, wrapWithSandbox, type Isolation } from './sandbox.js';

export interface ProbeOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Refuse to probe unless an OS-level sandbox (network isolation) is available. */
  requireSandbox?: boolean;
  /** Called once with the isolation actually in effect, for surfacing to the user. */
  onIsolation?: (isolation: Isolation) => void;
}

export class ProbeError extends Error {}

/**
 * Extracts a live tool manifest from one server by spawning it and running the
 * MCP handshake inside the strongest sandbox available on this platform.
 *
 * Safety invariants:
 *  - The server's *launch command* is run directly. Install scripts are never
 *    executed (sealpin never runs `npm install`).
 *  - The ambient environment is scrubbed to an operational allowlist plus the
 *    server's own declared env — unrelated shell secrets never leak in.
 *  - cwd is a fresh empty temp directory, not the user's project.
 *  - Network/filesystem are OS-isolated where a sandbox exists; otherwise the
 *    probe is process-only and `requireSandbox` can hard-fail instead.
 *  - A hard timeout and output byte cap bound resource use; the process tree is
 *    always killed and the temp dir removed.
 */
export async function probeServer(server: ServerConfig, opts: ProbeOptions = {}): Promise<ToolManifest> {
  const cwd = await makeTempCwd();
  try {
    const wrapped = wrapWithSandbox(server.command, server.args, cwd.path);

    if (opts.requireSandbox && !wrapped.isolation.network) {
      throw new ProbeError(
        `--require-sandbox set but no OS network sandbox is available on ${process.platform}. ` +
          'Refusing to probe "' + server.name + '" without network isolation.',
      );
    }

    opts.onIsolation?.(wrapped.isolation);

    const env = buildProbeEnv(server.env);
    const tools = await handshakeToolsList({
      command: wrapped.command,
      args: wrapped.args,
      env,
      cwd: cwd.path,
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxOutputBytes: opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
    });

    return { server: server.name, tools };
  } catch (err) {
    if (err instanceof ProbeError) throw err;
    throw new ProbeError(`probe of "${server.name}" failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    await cwd.cleanup();
  }
}

/**
 * A ManifestSource backed by live probing. Drops into the same slot as
 * FileManifestSource, so scan/lock/verify/diff work against live servers with
 * no downstream changes. A server that fails to probe yields null (skipped)
 * rather than aborting the whole scan; the failure is reported via onError.
 */
export class ProbeManifestSource implements ManifestSource {
  constructor(
    private readonly opts: ProbeOptions & { onError?: (server: string, message: string) => void } = {},
  ) {}

  async load(server: ServerConfig): Promise<ToolManifest | null> {
    try {
      return await probeServer(server, this.opts);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (this.opts.requireSandbox && err instanceof ProbeError && message.includes('require-sandbox')) {
        throw err; // a hard policy failure must not be silently swallowed
      }
      this.opts.onError?.(server.name, message);
      return null;
    }
  }
}

export { buildProbeEnv, wrapWithSandbox, type Isolation } from './sandbox.js';
export { DEFAULT_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES } from './client.js';
