import type { ServerConfig } from '../types/config.js';
import { discoverClaudeDesktop } from './claude-desktop.js';
import { discoverClaudeCode } from './claude-code.js';
import { discoverCursor } from './cursor.js';

export async function discoverServers(cwd = process.cwd()): Promise<ServerConfig[]> {
  const [desktop, code, cursor] = await Promise.all([
    discoverClaudeDesktop(),
    discoverClaudeCode(cwd),
    discoverCursor(cwd),
  ]);
  return [...desktop, ...code, ...cursor];
}

export { discoverClaudeDesktop } from './claude-desktop.js';
export { discoverClaudeCode } from './claude-code.js';
export { discoverCursor } from './cursor.js';
export type { ServerConfig };
