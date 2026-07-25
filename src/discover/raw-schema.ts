import { z } from 'zod';

/**
 * Claude Desktop, Claude Code (.mcp.json), and Cursor all currently use the
 * same `{ mcpServers: { <name>: { command, args, env } } }` shape on disk.
 * One shared schema for the raw file; discover/ still keeps a separate
 * module per client because *locating* the file differs and the shape is
 * expected to drift as MCP clients evolve independently.
 */
export const RawMcpConfigSchema = z.object({
  mcpServers: z
    .record(
      z.string(),
      z.object({
        command: z.string(),
        args: z.array(z.string()).optional(),
        env: z.record(z.string(), z.string()).optional(),
      }),
    )
    .default({}),
});

export type RawMcpConfig = z.infer<typeof RawMcpConfigSchema>;
