import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import { FileManifestSource } from '../scan/index.js';

export interface LoadedManifests {
  manifests: ToolManifest[];
  missing: string[]; // server names with no manifest file in the dir
}

/**
 * Loads a manifest for every server from a `--manifest-dir`. Servers without a
 * manifest file are reported in `missing` rather than silently dropped, so the
 * caller can warn that lock/verify only cover the servers it could read.
 */
export async function loadManifests(servers: ServerConfig[], dir: string): Promise<LoadedManifests> {
  const source = new FileManifestSource(dir);
  const manifests: ToolManifest[] = [];
  const missing: string[] = [];
  for (const server of servers) {
    const manifest = await source.load(server);
    if (manifest) manifests.push(manifest);
    else missing.push(server.name);
  }
  return { manifests, missing };
}
