import { homedir } from 'node:os';
import { join } from 'node:path';
import type { ServerConfig } from '../types/config.js';
import { readJsonIfExists } from './fs-utils.js';
import { normalize } from './normalize.js';

function configPath(): string {
  switch (process.platform) {
    case 'win32':
      return join(process.env['APPDATA'] ?? join(homedir(), 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
    case 'darwin':
      return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    default:
      return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
  }
}

export async function discoverClaudeDesktop(path = configPath()): Promise<ServerConfig[]> {
  const raw = await readJsonIfExists(path);
  if (raw === null) return [];
  return normalize(raw, 'claude-desktop', path);
}
