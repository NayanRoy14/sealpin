import { z } from 'zod';
import { ToolManifestSchema } from '../types/manifest.js';

export const LockEntrySchema = z.object({
  server: z.string(),
  hash: z.string(),
  manifest: ToolManifestSchema,
  lockedAt: z.string(), // ISO 8601
});

export type LockEntry = z.infer<typeof LockEntrySchema>;

export const LockFileSchema = z.object({
  version: z.literal(1),
  entries: z.array(LockEntrySchema),
});

export type LockFile = z.infer<typeof LockFileSchema>;
