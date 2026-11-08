/**
 * What each service's report() returns: its part of the job summary, from its own observations.
 * The composer (compose.ts) only places the parts; it never reads a log or decides a verdict.
 */

import type { Mode } from '../policy';

export interface ReportContext {
  mode: Mode;
  enforce: boolean;
}

/** The verdict column: ✅ allowed · 🟠 would be blocked (analyze) · ⛔ blocked (enforce) · ⚠️ advisory. */
export type Verdict = 'allowed' | 'would-block' | 'blocked' | 'advisory';

export const VERDICT_ICON: Record<Verdict, string> = {
  allowed: '✅',
  'would-block': '🟠',
  blocked: '⛔',
  advisory: '⚠️'
};

/** How a refusal shows in this mode. */
export function refusedVerdict(ctx: ReportContext): Verdict {
  return ctx.enforce ? 'blocked' : 'would-block';
}

/** One scorecard row in the Summary. */
export interface ScoreRow {
  verdict: Verdict;
  area: string;
  text: string;
}

/** A top-level alert paragraph (alerts don't render inside <details>). */
export interface Alert {
  kind: 'CAUTION' | 'IMPORTANT';
  text: string;
}

/** One input of the Suggested Enforce Configuration (analyze). Report only, never applied. */
export interface Suggestion {
  input: 'allowed-domains' | 'http-filter' | 'sudo-config' | 'docker';
  /** the input's value, as the input reads it */
  value: string;
  /** using it makes enforce ADVISORY: said in a comment on its line */
  advisory?: string;
  /** shown under the block as an option, not in it */
  optional?: boolean;
  /** what it was built from, for an optional one's summary line */
  label?: string;
}

/** Enforce: what made it ADVISORY, as a chip and a sentence. */
export interface Advisory {
  chip: string;
  text: string;
}

/** What the action did, and the GitHub baseline it trusts: collapsed, its result in the summary line. */
export interface RunnerSystem {
  summary: string;
  body: string;
}

export interface Section {
  score: ScoreRow[];
  alerts: Alert[];
  suggestions: Suggestion[];
  /** short notes under the Suggested block (analyze): what was left out, what analyze cannot see */
  notes: string[];
  advisory: Advisory[];
  /** what the job did */
  body: string;
  runnerSystem: RunnerSystem[];
}

export function emptySection(): Section {
  return { score: [], alerts: [], suggestions: [], notes: [], advisory: [], body: '', runnerSystem: [] };
}
