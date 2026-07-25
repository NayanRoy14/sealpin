import { z } from 'zod';

/**
 * A single MCP tool definition, as returned by a server's tools/list response
 * (or extracted statically). This is the thing prompt-injection payloads hide
 * inside — every field here is untrusted input.
 */
export const ToolSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.record(z.string(), z.unknown()),
  annotations: z
    .object({
      title: z.string().optional(),
      readOnlyHint: z.boolean().optional(),
      destructiveHint: z.boolean().optional(),
      idempotentHint: z.boolean().optional(),
      openWorldHint: z.boolean().optional(),
    })
    .partial()
    .optional(),
});

export type Tool = z.infer<typeof ToolSchema>;

/**
 * The full set of tools a single server exposes, plus enough metadata to
 * canonicalize and hash it for the lockfile.
 */
export const ToolManifestSchema = z.object({
  server: z.string(),
  tools: z.array(ToolSchema),
});

export type ToolManifest = z.infer<typeof ToolManifestSchema>;
