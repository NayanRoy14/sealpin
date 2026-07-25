/**
 * Human-facing documentation for each rule, keyed by id. Kept separate from
 * the Rule objects so the Rule interface stays exactly as specified (id,
 * severity, confidence, category, check) while `sealpin explain`/`rules` still
 * have something to print.
 */
export interface RuleDoc {
  title: string;
  attack: string; // which attack class from the threat model (A1..A9)
  summary: string;
}

export const RULE_DOCS: Record<string, RuleDoc> = {
  'MCP-P001': {
    title: 'Model-directed instructions in tool description',
    attack: 'A1 Tool poisoning',
    summary:
      'Flags tool descriptions that instruct the model (rather than document the tool), especially instructions to read credentials, exfiltrate data, or ignore prior instructions. The description is trusted context the user never sees.',
  },
  'MCP-P002': {
    title: 'Hidden / invisible Unicode in description',
    attack: 'A4 Hidden characters',
    summary:
      'Detects zero-width, bidirectional-override, and Unicode-tag characters that are invisible to a human reviewer but are still tokenized and read by the model.',
  },
  'MCP-P003': {
    title: 'ANSI escape sequences in description',
    attack: 'A4 Hidden characters',
    summary: 'Detects terminal control sequences that can hide or overwrite text shown to a reviewer in a console.',
  },
  'MCP-P004': {
    title: 'HTML comment in description',
    attack: 'A4 Hidden characters',
    summary: 'Detects HTML comments, which are hidden when a description is rendered as markdown but still read by the model.',
  },
  'MCP-P005': {
    title: 'Base64 blob in description',
    attack: 'A4 Hidden characters',
    summary: 'Flags long opaque base64 strings in a human-readable description that may encode a hidden payload. Weak signal (low severity).',
  },
  'MCP-P006': {
    title: 'Cross-server tool-name collision',
    attack: 'A3 Tool shadowing',
    summary: 'Flags tools sharing a name across servers in the same scan, where one server can shadow or influence how the model uses another.',
  },
  'MCP-C001': {
    title: 'Over-broad filesystem root',
    attack: 'A5 Over-broad capability',
    summary: 'Flags a filesystem server rooted at the filesystem root, a drive root, or the home directory — far broader than any specific task needs.',
  },
  'MCP-C002': {
    title: 'Unrestricted command execution',
    attack: 'A5 Over-broad capability',
    summary: 'Flags a shell/command server with no visible command allowlist, i.e. model-directed arbitrary code execution on the host.',
  },
  'MCP-C003': {
    title: 'Plaintext secret in config',
    attack: 'A6 Secret exfiltration',
    summary: 'Flags live credentials stored in plaintext in the MCP config env block, which is often world-readable, cloud-synced, or committed to a repo.',
  },
};
