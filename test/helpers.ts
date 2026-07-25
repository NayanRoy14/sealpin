import type { ServerConfig } from '../src/types/config.js';
import type { Tool, ToolManifest } from '../src/types/manifest.js';
import type { ScanContext } from '../src/types/rule.js';

export function server(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    name: 'test-server',
    command: 'npx',
    args: [],
    env: {},
    client: 'claude-desktop',
    configPath: '/fake/config.json',
    ...overrides,
  };
}

export function tool(name: string, description?: string, extra: Partial<Tool> = {}): Tool {
  return {
    name,
    ...(description !== undefined ? { description } : {}),
    inputSchema: { type: 'object', properties: {} },
    ...extra,
  };
}

export function manifest(name: string, tools: Tool[]): ToolManifest {
  return { server: name, tools };
}

export function context(
  cfg: Partial<ServerConfig>,
  tools: Tool[],
  workspace: ToolManifest[] = [],
): ScanContext {
  const s = server(cfg);
  const m = manifest(s.name, tools);
  return { server: s, manifest: m, workspace: workspace.length ? workspace : [m] };
}
