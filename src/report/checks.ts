/**
 * The setup checks in the job summary: the live self-tests (src/setup/selftest.ts) and the
 * post-run tamper check (src/integrity/check.ts). Neither is a service: they check all of them.
 */

import { code } from './markdown';
import type { Alert, Diagnostic } from './section';

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

export interface Check {
  /** '' for no chip */
  chip: string;
  alerts: Alert[];
  diagnostic?: Diagnostic;
}

export function selfTestCheck(selfTests: SelfTest[]): Check {
  const ok = selfTests.filter(t => t.ok).length;
  const failed = selfTests.filter(t => !t.ok);
  if (!selfTests.length) return { chip: '', alerts: [], diagnostic: { summary: 'self-tests not run', body: '' } };
  return {
    chip: `${failed.length ? '❌' : '🧪'} self-tests ${ok}/${selfTests.length}`,
    alerts: failed.length
      ? [
          {
            kind: 'CAUTION',
            text: `**Self-test failed:** ${failed.map(t => `\`${t.name}\``).join(', ')} — the proxy may not be enforcing as designed on this runner.`
          }
        ]
      : [],
    diagnostic: {
      summary: `self-tests ${ok}/${selfTests.length} ${failed.length ? '✗' : '✓'}`,
      body:
        '**Self-tests**\n\n' +
        selfTests
          .map(t => `- ${t.ok ? '✅' : '❌'} ${code(t.name)} — ${t.detail.replace(/[<>|`*_[\]]/g, '\\$&')}`)
          .join('\n') +
        '\n\n'
    }
  };
}

/**
 * The post-run tamper check. Its chip is advisory (ADVISORY_REPORT_NOTE), and a check that could
 * not run is unknown, never a pass.
 */
export function integrityCheck(integrity: IntegrityDetails | undefined): Check {
  const s = integrity?.status;
  const chip =
    s === 'tampered'
      ? '🚨 config tampered'
      : s === 'verified'
        ? '🔎 no config change seen (advisory)'
        : '❔ config unverified';
  const alerts: Alert[] =
    s === 'tampered'
      ? [
          {
            kind: 'CAUTION',
            text: '**Safer Runner configuration changed during the job** — see the config file check under Diagnostics.'
          }
        ]
      : [];
  if (!integrity) return { chip, alerts };
  let body = `**Config file tamper check** (advisory) — ${s === 'verified' ? 'all verified' : s === 'tampered' ? '⚠️ CHANGED' : 'no baseline'}\n\n`;
  body += integrity.body + '\n\n';
  body += `${ADVISORY_REPORT_NOTE}\n\n`;
  return {
    chip,
    alerts,
    diagnostic: {
      summary: s === 'verified' ? 'config unchanged ✓' : s === 'tampered' ? 'config CHANGED ⚠️' : 'config: no baseline',
      body
    }
  };
}
