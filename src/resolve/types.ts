import type { ServerConfig } from '../types/config.js';

export interface SourceFile {
  /** Absolute path on disk. */
  path: string;
  /** Path relative to the source root, for display in findings. */
  relPath: string;
  content: string;
}

export interface ServerSource {
  /** Directory the source was resolved from. */
  root: string;
  /** Parsed package.json if one was found at the root, else null. */
  packageJson: unknown | null;
  /** JS/TS source files under the root (node_modules excluded, bounded). */
  files: SourceFile[];
}

/**
 * Where a server's *source code* comes from. v1 ships a local-filesystem
 * resolver; a registry/tarball resolver (download + unpack, never execute)
 * slots into this same interface later — the source rule pack does not change
 * when it does.
 */
export interface SourceResolver {
  resolve(server: ServerConfig): Promise<ServerSource | null>;
}
