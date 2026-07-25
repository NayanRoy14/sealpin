import type { Rule } from '../types/rule.js';
import { injectionRule } from './prompt/injection.js';
import { hiddenUnicodeRule } from './prompt/hidden-unicode.js';
import { ansiEscapeRule, htmlCommentRule, base64BlobRule } from './prompt/concealment.js';
import { shadowingRule } from './prompt/shadowing.js';
import { filesystemRootRule } from './capability/filesystem-root.js';
import { unrestrictedExecRule } from './capability/unrestricted-exec.js';
import { plaintextSecretsRule } from './capability/plaintext-secrets.js';

/** Every rule sealpin ships. Order here is the order rules run and list in. */
export const ALL_RULES: readonly Rule[] = [
  // prompt layer (A1, A3, A4)
  injectionRule,
  hiddenUnicodeRule,
  ansiEscapeRule,
  htmlCommentRule,
  base64BlobRule,
  shadowingRule,
  // capability (A5, A6)
  filesystemRootRule,
  unrestrictedExecRule,
  plaintextSecretsRule,
];

export function getRule(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id.toLowerCase() === id.toLowerCase());
}
