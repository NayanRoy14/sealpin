/**
 * Capability model for cross-server (composition-level) analysis. Individually
 * safe servers can form an attack path when loaded in the same agent context;
 * capabilities are the vocabulary for reasoning about that. Each server is
 * tagged with what it can *do*, inferred from its config, manifest, and
 * per-server findings, with provenance for every tag.
 */

export type Capability =
  | 'data.secrets' // holds or can read credentials (env secrets, ~/.ssh, ~/.aws)
  | 'data.filesystem' // reads local files
  | 'data.private' // reads a private user store (notes, email, calendar, repo, db, messages)
  | 'content.untrusted' // pulls in attacker-controllable external content (web/search/fetch/scrape)
  | 'sink.egress' // makes outbound network requests
  | 'sink.messaging' // sends messages/email/issues (an exfiltration channel)
  | 'sink.filesystem' // writes local files
  | 'exec'; // runs commands / arbitrary code

export const ALL_CAPABILITIES: readonly Capability[] = [
  'data.secrets',
  'data.filesystem',
  'data.private',
  'content.untrusted',
  'sink.egress',
  'sink.messaging',
  'sink.filesystem',
  'exec',
];

/**
 * Which leg of the "lethal trifecta" a capability contributes, if any.
 * `exec` is tracked separately (it drives the untrusted-content → RCE path).
 * `sink.filesystem` is intentionally NOT an exfil leg — writing a local file is
 * only exfiltration if the location is shared, so it stays informational.
 */
export type TrifectaLeg = 'private-data' | 'untrusted-content' | 'exfil';

export const CAPABILITY_LEG: Record<Capability, TrifectaLeg | 'exec' | null> = {
  'data.secrets': 'private-data',
  'data.filesystem': 'private-data',
  'data.private': 'private-data',
  'content.untrusted': 'untrusted-content',
  'sink.egress': 'exfil',
  'sink.messaging': 'exfil',
  'sink.filesystem': null,
  exec: 'exec',
};

export interface CapabilityEvidence {
  capability: Capability;
  /** Where the tag came from. */
  via: 'config' | 'env' | 'tool' | 'finding';
  /** Human-readable reason the capability was assigned. */
  reason: string;
  /** The specific tool name / env key / rule id, when applicable. */
  detail?: string;
}

export interface CapabilitySet {
  server: string;
  capabilities: Set<Capability>;
  evidence: CapabilityEvidence[];
}

export function hasCapability(set: CapabilitySet, cap: Capability): boolean {
  return set.capabilities.has(cap);
}

/** Evidence entries that justify a specific capability (for explaining findings). */
export function evidenceFor(set: CapabilitySet, cap: Capability): CapabilityEvidence[] {
  return set.evidence.filter((e) => e.capability === cap);
}
