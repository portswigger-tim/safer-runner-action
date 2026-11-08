/**
 * The setup checks in the job summary: the live self-tests (src/setup/selftest.ts) and the
 * post-run tamper check (src/integrity/check.ts). Neither is a service: they check all of them.
 */

import { code } from './markdown';
import type { Alert, RunnerSystem, ScoreRow } from './section';

export type SelfTest = { name: string; ok: boolean; detail: string };
export type IntegrityDetails = { status: 'verified' | 'tampered' | 'unavailable'; body: string };

/**
 * The post step (this report, the tamper check, fail-on-tampering) runs as the runner user from
 * the action's files on the runner, which the job's own steps can write to. Say so in the report.
 */
export const ADVISORY_REPORT_NOTE =
  '<sub>The tamper check and this summary come from the post step, which runs as the runner user from ' +
  "files the job's steps can modify: an advisory tripwire, not tamper-proof evidence. The egress controls " +
  "themselves are root-owned and don't depend on it.</sub>";

export interface Checks {
  score: ScoreRow;
  alerts: Alert[];
  runnerSystem: RunnerSystem;
}

/**
 * The self-tests and the tamper check: one scorecard row, failures as alerts, the details under
 * Runner System. A tamper check that could not run is unknown, never a pass (ADVISORY_REPORT_NOTE).
 */
export function setupChecks(selfTests: SelfTest[], integrity: IntegrityDetails | undefined): Checks {
  const ok = selfTests.filter(t => t.ok).length;
  const failed = selfTests.filter(t => !t.ok);
  const s = integrity?.status;
  const alerts: Alert[] = [];
  if (failed.length) {
    alerts.push({
      kind: 'CAUTION',
      text: `**Self-test failed:** ${failed.map(t => `\`${t.name}\``).join(', ')}: the proxy may not be enforcing as designed on this runner.`
    });
  }
  if (s === 'tampered') {
    alerts.push({
      kind: 'CAUTION',
      text: '**Safer Runner configuration changed during the job**: see the setup checks under Runner System.'
    });
  }
  const tests = selfTests.length ? `self-tests ${ok}/${selfTests.length}` : 'self-tests not run';
  const config =
    s === 'verified' ? 'no config change seen (advisory)' : s === 'tampered' ? 'config CHANGED' : 'config not verified';
  const text = `${tests} · ${config}`;

  let body = '';
  if (selfTests.length) {
    body +=
      '**Self-tests**\n\n' +
      selfTests
        .map(t => `- ${t.ok ? '✅' : '⚠️'} ${code(t.name)}: ${t.detail.replace(/[<>|`*_[\]]/g, '\\$&')}`)
        .join('\n') +
      '\n\n';
  }
  if (integrity) {
    body += `**Config file tamper check** (advisory): ${s === 'verified' ? 'all verified' : s === 'tampered' ? '⚠️ CHANGED' : 'no baseline'}\n\n`;
    body += integrity.body + '\n\n';
  }
  body += `${ADVISORY_REPORT_NOTE}\n\n`;
  return {
    score: { verdict: failed.length || s !== 'verified' ? 'advisory' : 'allowed', area: 'Setup', text },
    alerts,
    runnerSystem: { summary: `setup checks: ${text}`, body }
  };
}
