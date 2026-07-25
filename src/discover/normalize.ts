import type { McpClient, ServerConfig } from '../types/config.js';
import { RawMcpConfigSchema } from './raw-schema.js';

export function normalize(raw: unknown, client: McpClient, configPath: string): ServerConfig[] {
  const parsed = RawMcpConfigSchema.parse(raw);
  return Object.entries(parsed.mcpServers).map(([name, entry]) => ({
    name,
    command: entry.command,
    args: entry.args ?? [],
    env: entry.env ?? {},
    client,
    configPath,
  }));
}
