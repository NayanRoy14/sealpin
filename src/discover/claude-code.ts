import { homedir } from 'node:os';
import { join } from 'node:path';
import type { ServerConfig } from '../types/config.js';
import { readJsonIfExists } from './fs-utils.js';
import { normalize } from './normalize.js';

/**
 * Claude Code reads MCP servers from a project-level .mcp.json (checked into
 * the repo, shared with the team) and a user-level ~/.claude.json (personal,
 * cross-project). Both use the same mcpServers shape. v1 only checks the
 * current working directory for the project file — no walking up to find a
 * repo root yet.
 */
export async function discoverClaudeCode(
  cwd = process.cwd(),
  userPath = join(homedir(), '.claude.json'),
): Promise<ServerConfig[]> {
  const projectPath = join(cwd, '.mcp.json');

  const [projectRaw, userRaw] = await Promise.all([
    readJsonIfExists(projectPath),
    readJsonIfExists(userPath),
  ]);

  const servers: ServerConfig[] = [];
  if (projectRaw !== null) {
    servers.push(...normalize(projectRaw, 'claude-code', projectPath));
  }
  if (userRaw !== null) {
    servers.push(...normalize(userRaw, 'claude-code', userPath));
  }
  return servers;
}
