import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import type { ManifestSource } from '../scan/index.js';

export interface LoadedManifests {
  manifests: ToolManifest[];
  missing: string[]; // server names the source could not produce a manifest for
}

/**
 * Loads a manifest for every server from any ManifestSource (a --manifest-dir
 * directory or a live --probe). Servers the source can't produce a manifest
 * for are reported in `missing` rather than silently dropped.
 */
export async function loadManifests(servers: ServerConfig[], source: ManifestSource): Promise<LoadedManifests> {
  const manifests: ToolManifest[] = [];
  const missing: string[] = [];
  for (const server of servers) {
    const manifest = await source.load(server);
    if (manifest) manifests.push(manifest);
    else missing.push(server.name);
  }
  return { manifests, missing };
}
