import type { McpClient, ServerConfig } from '../types/config.js';
import { discoverClaudeDesktop } from './claude-desktop.js';
import { discoverClaudeCode } from './claude-code.js';
import { discoverCursor } from './cursor.js';
import { readJsonIfExists } from './fs-utils.js';
import { normalize } from './normalize.js';

export interface DiscoverOptions {
  cwd?: string;
  /** Called when one client's config can't be read/parsed; discovery continues for the rest. */
  onWarn?: (client: McpClient, message: string) => void;
}

/**
 * Discovers servers across all supported clients. A malformed config for one
 * client (bad JSON, schema violation) is isolated: it is reported via `onWarn`
 * and the other clients' servers are still returned, rather than aborting the
 * whole scan.
 */
export async function discoverServers(options: DiscoverOptions = {}): Promise<ServerConfig[]> {
  const cwd = options.cwd ?? process.cwd();
  const sources: Array<[McpClient, () => Promise<ServerConfig[]>]> = [
    ['claude-desktop', () => discoverClaudeDesktop()],
    ['claude-code', () => discoverClaudeCode(cwd)],
    ['cursor', () => discoverCursor(cwd)],
  ];

  const results = await Promise.all(
    sources.map(async ([client, run]) => {
      try {
        return await run();
      } catch (err) {
        options.onWarn?.(client, err instanceof Error ? err.message : String(err));
        return [];
      }
    }),
  );
  return results.flat();
}

/**
 * Parses a single explicitly-provided config file (the `--config` flag). All
 * three supported clients share the `{ mcpServers: {...} }` shape, so the
 * client label is caller-provided and defaults to claude-desktop.
 */
export async function discoverFromFile(path: string, client: McpClient = 'claude-desktop'): Promise<ServerConfig[]> {
  const raw = await readJsonIfExists(path);
  if (raw === null) {
    throw new Error(`Config file not found: ${path}`);
  }
  return normalize(raw, client, path);
}

export { discoverClaudeDesktop } from './claude-desktop.js';
export { discoverClaudeCode } from './claude-code.js';
export { discoverCursor } from './cursor.js';
export type { ServerConfig };
