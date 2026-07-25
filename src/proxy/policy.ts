import { z } from 'zod';

/**
 * Runtime enforcement policy for the MCP proxy. Declares, per server, which
 * tools may be called and what arguments are forbidden — evaluated live on
 * every tools/call, not just observed statically.
 */
export const ArgPatternSchema = z.object({
  /** Restrict this rule to one tool (else it applies to every tool). */
  tool: z.string().optional(),
  /** Check one named argument (else the whole argument object, JSON-encoded). */
  arg: z.string().optional(),
  /** A denied pattern (JS regex, case-insensitive). */
  pattern: z.string(),
});
export type ArgPattern = z.infer<typeof ArgPatternSchema>;

export const ServerPolicySchema = z.object({
  /** If present, ONLY these tools may be called. */
  allowTools: z.array(z.string()).optional(),
  /** These tools are always blocked. */
  denyTools: z.array(z.string()).default([]),
  /** Calls whose arguments match are blocked (e.g. filesystem paths into ~/.ssh). */
  denyArgumentPatterns: z.array(ArgPatternSchema).default([]),
  /** Remove tools from tools/list whose definition drifted from the lockfile. */
  blockOnDrift: z.boolean().optional(),
});
export type ServerPolicy = z.infer<typeof ServerPolicySchema>;

export const PolicySchema = z.object({
  version: z.literal(1),
  /** Applied to every server, then overlaid by a server-specific entry. */
  default: ServerPolicySchema.optional(),
  servers: z.record(z.string(), ServerPolicySchema).default({}),
});
export type Policy = z.infer<typeof PolicySchema>;

export const EMPTY_SERVER_POLICY: ServerPolicy = { denyTools: [], denyArgumentPatterns: [] };

/** Merge the default and server-specific policy into the effective policy for one server. */
export function resolveServerPolicy(policy: Policy | undefined, serverName: string): ServerPolicy {
  if (!policy) return EMPTY_SERVER_POLICY;
  const def = policy.default;
  const specific = policy.servers[serverName];
  if (!def && !specific) return EMPTY_SERVER_POLICY;
  return {
    allowTools: specific?.allowTools ?? def?.allowTools,
    denyTools: [...(def?.denyTools ?? []), ...(specific?.denyTools ?? [])],
    denyArgumentPatterns: [...(def?.denyArgumentPatterns ?? []), ...(specific?.denyArgumentPatterns ?? [])],
    blockOnDrift: specific?.blockOnDrift ?? def?.blockOnDrift,
  };
}

export interface Decision {
  deny: boolean;
  reason?: string;
}

/** Evaluate a single tools/call against a resolved server policy. */
export function evaluateToolCall(sp: ServerPolicy, toolName: string, args: unknown): Decision {
  if (sp.denyTools.includes(toolName)) {
    return { deny: true, reason: `tool "${toolName}" is denied by policy` };
  }
  if (sp.allowTools && !sp.allowTools.includes(toolName)) {
    return { deny: true, reason: `tool "${toolName}" is not in the allowlist` };
  }
  for (const p of sp.denyArgumentPatterns) {
    if (p.tool && p.tool !== toolName) continue;
    let re: RegExp;
    try {
      re = new RegExp(p.pattern, 'i');
    } catch {
      continue; // a malformed pattern never silently allows; it just doesn't match
    }
    const record = isRecord(args) ? args : {};
    const haystack = p.arg ? stringifyArg(record[p.arg]) : JSON.stringify(record);
    if (re.test(haystack)) {
      return { deny: true, reason: `argument ${p.arg ? `"${p.arg}" ` : ''}matches denied pattern /${p.pattern}/` };
    }
  }
  return { deny: false };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function stringifyArg(v: unknown): string {
  return typeof v === 'string' ? v : JSON.stringify(v ?? '');
}
