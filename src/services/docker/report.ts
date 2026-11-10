/**
 * Docker's part of the job summary: the containers' egress, the docker policy as applied
 * (enforce), and in analyze the docker policy against the job's use of docker (observeDocker,
 * evaluateDocker). Only kinds and counts and image names are shown: never an exec command line, a
 * container name, a label or the environment (free-form, and they can hold secrets).
 */

import type { DockerEvaluation, DockerObserved, DockerUse } from './config';
import { DOCKER_USES } from './config';
import { containerBlocked, containerDetails, type ContainerSummary } from './containers';
import { MAX_LIST } from '../mitmproxy/flows';
import { REDACTED, looksEncoded } from '../../report/redact';
import { code, plural, table } from '../../report/markdown';
import type { Advisory, BlockedRow, CheckRow, Details, ReportContext, Section, Suggestion } from '../../report/section';

export interface DockerPolicyReport {
  /** the docker policy setup recorded (the input, or remove-group when unset) */
  policy: string;
  observed: DockerObserved;
  evaluation: DockerEvaluation;
}

/** The recording did not cover the whole job. */
export const DOCKER_PARTIAL =
  'the docker recording did not cover the whole job (dockerd stopped, restarted or was not running at setup)';

const USE_TEXT: Record<DockerUse, [string, string]> = {
  container: ['container action', 'container actions'],
  exec: ['exec into a container', 'execs into containers'],
  image: ['image action', 'image actions'],
  build: ['build', 'builds'],
  network: ['network change', 'network changes'],
  volume: ['volume change', 'volume changes'],
  other: ['other docker API call', 'other docker API calls']
};

/** `3 container actions, 1 image action`; '' for none. */
export function dockerUseText(uses: Partial<Record<DockerUse, number>>): string {
  return DOCKER_USES.filter(k => uses[k])
    .map(k => plural(uses[k]!, ...USE_TEXT[k]))
    .join(', ');
}

/** Total docker events in `uses`. */
export function dockerUseCount(uses: Partial<Record<DockerUse, number>>): number {
  return DOCKER_USES.reduce((a, k) => a + (uses[k] ?? 0), 0);
}

const IMAGE_REF = /^[A-Za-z0-9._/:@-]{1,200}$/;

/**
 * An image name for the summary: only the characters an image reference can hold, and every
 * part of it (each label of the registry, each path segment, each dot-separated piece of the tag,
 * the digest) through the label check, as redactName does for a hostname. A part that looks
 * encoded prints as REDACTED.
 */
export function imageLabel(ref: string): string {
  if (!IMAGE_REF.test(ref)) return REDACTED;
  return ref
    .split(/([/:@.])/)
    .map(p => (/^[/:@.]$/.test(p) || !looksEncoded(p) ? p : REDACTED))
    .join('');
}

export interface DockerReportObserved {
  /** the runner user kept docker access (root-equivalent): as verified at setup, not the input */
  retained: boolean;
  /** the docker input, the access verified after applying it (G4), and the dockerd CA restart (F1) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running'; caRestart?: boolean };
  /** analyze: the job's use of docker, what the docker policy would break, and the suggestion */
  policy?: DockerPolicyReport;
  /** per-container egress (P2); empty / undefined: no container traffic */
  containers?: ContainerSummary[];
}

const DOCKER_ACCESS_TEXT: Record<string, string> = {
  retained: 'runner user can use docker',
  'group-removed': 'runner user removed from the docker group, socket root-only',
  'not-running': 'docker daemon not running'
};

/** The cell in the row of numbers. */
function stat(o: DockerReportObserved, ctx: ReportContext): string {
  if (ctx.enforce) {
    if (!o.docker) return 'not recorded';
    const { access, requested } = o.docker;
    if (access === 'retained') return '⚠️ kept';
    if (access === 'group-removed') return 'removed';
    return requested === 'stop' ? 'stopped' : 'not running';
  }
  const d = o.policy;
  if (!d) return o.docker?.access === 'not-running' ? 'not running' : 'not recorded';
  const n = String(dockerUseCount(d.observed.uses));
  if (d.observed.partial) return `⚠️ ${n}, partial`;
  // docker: keep, set or suggested: enforce would be ADVISORY
  return d.policy === 'keep' || d.evaluation.suggestion.advisory ? `⚠️ ${n}` : n;
}

/** Analyze: the job's use of docker that the policy would block, and service containers `stop` would stop. */
function blocked(o: DockerReportObserved, ctx: ReportContext): BlockedRow[] {
  const rows: BlockedRow[] = [];
  const e = ctx.enforce ? undefined : o.policy?.evaluation;
  if (e && dockerUseCount(e.wouldBlock)) {
    rows.push({
      reason: code(`docker: ${o.policy!.policy}`),
      layer: 'docker',
      tries: dockerUseCount(e.wouldBlock),
      what: dockerUseText(e.wouldBlock)
    });
  } else if (e?.wouldStop) {
    rows.push({
      reason: code('docker: stop'),
      layer: 'docker',
      tries: e.wouldStop,
      what: e.wouldStop === 1 ? 'service container' : 'service containers'
    });
  }
  return [...rows, ...containerBlocked(o.containers ?? [])];
}

function advisory(o: DockerReportObserved, ctx: ReportContext): Advisory[] {
  if (!ctx.enforce || !o.retained) return [];
  return [
    {
      label: 'docker kept',
      text: '`docker: keep` kept docker, which is root-equivalent: any step could have removed the egress controls.'
    }
  ];
}

function suggestions(o: DockerReportObserved, ctx: ReportContext): Suggestion[] {
  const s = o.policy?.evaluation.suggestion;
  if (ctx.enforce || !s?.change) return [];
  return [{ input: 'docker', value: s.value, ...(s.advisory ? { advisory: 'ADVISORY' } : {}) }];
}

function notes(o: DockerReportObserved, ctx: ReportContext): string[] {
  const d = o.policy;
  if (ctx.enforce || !d) return [];
  const out: string[] = [];
  if (d.evaluation.wouldStop && !dockerUseCount(d.evaluation.wouldBlock)) {
    out.push('`docker: remove-group` keeps service containers running, where `docker: stop` would stop them');
  }
  if (d.observed.partial) out.push(DOCKER_PARTIAL);
  return out;
}

/** Analyze: the job's use of docker after setup, by kind, and the images. */
function useDetails(o: DockerReportObserved, ctx: ReportContext): Details | undefined {
  const d = ctx.enforce ? undefined : o.policy;
  if (!d) return undefined;
  const kinds = DOCKER_USES.filter(k => d.observed.uses[k]);
  let body = kinds.length
    ? table(
        ['Use after setup', 'Events'],
        [':--', '--:'],
        kinds.map(k => [dockerUseText({ [k]: 1 }).replace(/^1 /, ''), String(d.observed.uses[k])])
      ) + '\n\n'
    : '';
  if (d.observed.services) body += `Service containers running at setup: ${d.observed.services}\n\n`;
  if (d.observed.images.length) {
    const shown = d.observed.images.slice(0, MAX_LIST).map(i => code(imageLabel(i)));
    const more = d.observed.images.length - shown.length;
    body += `Images: ${shown.join(', ')}${more > 0 ? ` +${more} more` : ''}\n\n`;
  }
  if (!body) return undefined;
  return { summary: `Docker use after setup: ${dockerUseText(d.observed.uses) || 'none'}`, body };
}

/** What the action did to docker. */
function checks(o: DockerReportObserved, ctx: ReportContext): CheckRow[] {
  if (!o.docker) return [];
  const { requested, access, caRestart } = o.docker;
  const rows: CheckRow[] = [
    {
      ok: !ctx.enforce || access !== 'retained',
      check: code(`docker: ${requested}`),
      detail: ctx.enforce
        ? (DOCKER_ACCESS_TEXT[access] ?? access)
        : `not applied (analyze); ${DOCKER_ACCESS_TEXT[access] ?? access}`
    }
  ];
  if (caRestart) rows.push({ ok: true, check: 'dockerd restart', detail: 'restarted so it trusts the proxy CA' });
  return rows;
}

export function report(o: DockerReportObserved, ctx: ReportContext): Section {
  const details = [useDetails(o, ctx), containerDetails(o.containers ?? [])].filter((x): x is Details => !!x);
  return {
    blocked: blocked(o, ctx),
    alerts: [],
    suggestions: suggestions(o, ctx),
    notes: notes(o, ctx),
    advisory: advisory(o, ctx),
    details,
    checks: checks(o, ctx),
    stat: stat(o, ctx)
  };
}

/** The uses enforce would block, for the job log. */
export function jobLog(policy: DockerPolicyReport | undefined): string[] {
  return DOCKER_USES.flatMap(k => {
    const n = policy?.evaluation.wouldBlock[k];
    return n ? [`docker WOULD_BLOCK ${k} x${n}`] : [];
  });
}
