import type { McpClient, ServerConfig } from '../types/config.js';
import { discoverClaudeDesktop } from './claude-desktop.js';
import { discoverClaudeCode } from './claude-code.js';
import { discoverCursor } from './cursor.js';
import { readJsonIfExists } from './fs-utils.js';
import { normalize } from './normalize.js';

export async function discoverServers(cwd = process.cwd()): Promise<ServerConfig[]> {
  const [desktop, code, cursor] = await Promise.all([
    discoverClaudeDesktop(),
    discoverClaudeCode(cwd),
    discoverCursor(cwd),
  ]);
  return [...desktop, ...code, ...cursor];
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
