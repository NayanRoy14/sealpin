import { createHash } from 'node:crypto';
import type { ToolManifest } from '../types/manifest.js';
import { canonicalize } from './canonicalize.js';

export function hashManifest(manifest: ToolManifest): string {
  return createHash('sha256').update(canonicalize(manifest)).digest('hex');
}
