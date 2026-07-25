import { homedir } from 'node:os';
import { join } from 'node:path';
import type { ServerConfig } from '../types/config.js';
import { readJsonIfExists } from './fs-utils.js';
import { normalize } from './normalize.js';

/**
 * Cursor reads MCP servers from a project-level .cursor/mcp.json and a
 * global ~/.cursor/mcp.json, both in the same mcpServers shape.
 */
export async function discoverCursor(
  cwd = process.cwd(),
  globalPath = join(homedir(), '.cursor', 'mcp.json'),
): Promise<ServerConfig[]> {
  const projectPath = join(cwd, '.cursor', 'mcp.json');

  const [projectRaw, globalRaw] = await Promise.all([
    readJsonIfExists(projectPath),
    readJsonIfExists(globalPath),
  ]);

  const servers: ServerConfig[] = [];
  if (projectRaw !== null) {
    servers.push(...normalize(projectRaw, 'cursor', projectPath));
  }
  if (globalRaw !== null) {
    servers.push(...normalize(globalRaw, 'cursor', globalPath));
  }
  return servers;
}
