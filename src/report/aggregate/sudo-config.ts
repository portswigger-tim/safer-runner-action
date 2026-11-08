/**
 * The suggested sudo-config (analyze): what proxy/sudo_suggest.py builds from the workflow's own
 * sudo commands, and its YAML, written with the same library that reads the input back.
 */

import { stringify } from 'yaml';

export interface SudoConfigSuggestion {
  /** exact command lines, sorted; never a `*` */
  rules: string[];
  /** distinct command lines left out, by reason */
  omitted: { secret: number; unrepresentable: number; other_user: number; over_cap: number };
}

/** The suggestion as the sudo-config input value: a YAML list, read back by parseSudoConfig. */
export function sudoConfigYaml(rules: string[]): string {
  return stringify(rules, { lineWidth: 0 });
}
