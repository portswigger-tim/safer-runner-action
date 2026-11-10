/**
 * The setup checks in the job summary: the live self-tests (src/setup/selftest.ts) and the
 * post-run tamper check (src/integrity/check.ts). Neither is a service: they check all of them.
 */

import { code } from './markdown';
import type { Alert, CheckRow } from './section';

export type SelfTest = { name: string; ok: boolean; detail: string };
export type IntegrityDetails = { status: 'verified' | 'tampered' | 'unavailable'; body: string };

export interface Checks {
  /** the collapsed part's summary line */
  summary: string;
  rows: CheckRow[];
  alerts: Alert[];
  /** the tamper check's own tables, under the rows */
  body: string;
}

const TAMPER_TEXT: Record<IntegrityDetails['status'], string> = {
  verified: 'no change seen',
  tampered: 'CHANGED',
  unavailable: 'no baseline'
};

/**
 * The self-tests and the tamper check: one row each, failures also as alerts. A tamper check that
 * could not run is unknown, never a pass.
 */
export function setupChecks(selfTests: SelfTest[], integrity: IntegrityDetails | undefined): Checks {
  const ok = selfTests.filter(t => t.ok).length;
  const failed = selfTests.filter(t => !t.ok);
  const s = integrity?.status;
  const alerts: Alert[] = [];
  if (failed.length) {
    alerts.push({
      kind: 'CAUTION',
      text: `**Self-test failed:** ${failed.map(t => code(t.name)).join(', ')}.`
    });
  }
  if (s === 'tampered') alerts.push({ kind: 'CAUTION', text: '**Tamper check: Safer Runner configuration CHANGED.**' });

  const rows: CheckRow[] = selfTests.length
    ? selfTests.map(t => ({ ok: t.ok, check: code(t.name), detail: t.detail.replace(/[<>|`*_[\]]/g, '\\$&') }))
    : [{ ok: false, check: 'self-tests', detail: 'not run' }];
  rows.push({ ok: s === 'verified', check: 'tamper check', detail: s ? TAMPER_TEXT[s] : 'not run' });

  const tests = selfTests.length ? `self-tests ${ok}/${selfTests.length}` : 'self-tests not run';
  return {
    summary: `${tests} · tamper check: ${s ? TAMPER_TEXT[s] : 'not run'}`,
    rows,
    alerts,
    body: integrity ? integrity.body : ''
  };
}
