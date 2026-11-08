/**
 * What each service's report() returns: its part of the job summary, from its own observations.
 * The composer (compose.ts) only places the parts; it never reads a log or decides a verdict.
 */

import type { Mode } from '../policy';

export interface ReportContext {
  mode: Mode;
  enforce: boolean;
  /** the ref the workflow used in `uses:` (GITHUB_ACTION_REF) */
  actionRef?: string;
}

/**
 * One item of a top-level alert (alerts don't render inside <details>). `text` is one paragraph,
 * quoted by the composer; `quoted` text already carries its `> ` lines and ends with a newline.
 */
export interface Alert {
  kind: 'CAUTION' | 'WARNING' | 'IMPORTANT';
  text: string;
  quoted?: boolean;
}

/** A part of the collapsed Diagnostics: its result for the <summary> line, and its body. */
export interface Diagnostic {
  summary: string;
  body: string;
}

export interface Section {
  /** status chips for the header */
  chips: string[];
  alerts: Alert[];
  /** scorecard rows */
  score: string[][];
  /** something here was (or would be) blocked: the summary is not an all-clear */
  blocking: boolean;
  /** what the job did */
  body: string;
  diagnostics: Diagnostic[];
  /** full lists for the job log, redacted like the summary */
  jobLog: string[];
  /** enforce: what made it ADVISORY ('' when nothing) */
  advisory: string;
}

export function emptySection(): Section {
  return { chips: [], alerts: [], score: [], blocking: false, body: '', diagnostics: [], jobLog: [], advisory: '' };
}
