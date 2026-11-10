/**
 * What each service's report() returns: its part of the job summary, from its own observations.
 * The composer (compose.ts) only places the parts; it never reads a log or decides a verdict.
 */

import type { Mode } from '../policy';

export interface ReportContext {
  mode: Mode;
  enforce: boolean;
}

/** One row of the Blocked table: the reason as its log writes it, and what it blocked. */
export interface BlockedRow {
  /** the log's own word (`sni-not-allowed`, `BLOCK`, `Drop`), or the input that decided it */
  reason: string;
  /** where it was decided: the flow log's layer, or dns, firewall, http-filter, sudo, docker */
  layer: string;
  /** attempts; undefined when the log does not count them (a DNS name) */
  tries?: number;
  /** the name and its data, as a Markdown cell (untrusted parts already redacted and in code spans) */
  what: string;
}

/** A top-level alert paragraph (alerts don't render inside <details>). */
export interface Alert {
  kind: 'CAUTION' | 'WARNING';
  text: string;
}

/** One input of the suggested enforce step (analyze only). Report only, never applied. */
export interface Suggestion {
  input: 'allowed-domains' | 'http-filter' | 'sudo-config' | 'docker';
  /** the input's value, as the input reads it */
  value: string;
  /** using it makes enforce ADVISORY: said in a comment on its line */
  advisory?: string;
  /** anything else to say on its line (a YAML comment, which the input ignores) */
  comment?: string;
}

/** Enforce: what made it ADVISORY, as a short label and a sentence. */
export interface Advisory {
  label: string;
  text: string;
}

/** A collapsed part: what went as expected, its numbers in the summary line. */
export interface Details {
  summary: string;
  body: string;
}

/** One row of the Safer Runner table: a setup check, or something the action itself did. */
export interface CheckRow {
  ok: boolean;
  check: string;
  detail: string;
}

export interface Section {
  blocked: BlockedRow[];
  alerts: Alert[];
  suggestions: Suggestion[];
  /** short notes under the suggested block: what was left out of it */
  notes: string[];
  advisory: Advisory[];
  /** collapsed parts: what the job did that was allowed */
  details: Details[];
  /** what the action did (its own sudo, the docker change), for the Safer Runner table */
  checks: CheckRow[];
  /** this part's cell in the row of numbers (sudo, docker) */
  stat?: string;
}

export function emptySection(): Section {
  return { blocked: [], alerts: [], suggestions: [], notes: [], advisory: [], details: [], checks: [] };
}
