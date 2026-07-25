import { z } from 'zod';

/**
 * The MCP client that a server config was discovered in. New clients get a
 * new literal here plus a parser in discover/ — nothing else needs to change.
 */
export const McpClientSchema = z.enum(['claude-desktop', 'claude-code', 'cursor']);

export type McpClient = z.infer<typeof McpClientSchema>;

/**
 * A single MCP server entry, normalized out of whatever shape the source
 * client's config file uses. This is the common currency between discover/,
 * resolve/, probe/, and lockfile/.
 */
export const ServerConfigSchema = z.object({
  name: z.string(),
  command: z.string(),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  client: McpClientSchema,
  configPath: z.string(),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;
