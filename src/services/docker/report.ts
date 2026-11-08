/**
 * Docker's part of the job summary: the containers' egress, the docker policy as applied
 * (enforce), and in analyze the docker policy against the job's use of docker (observeDocker,
 * evaluateDocker). Only kinds and counts and image names are shown: never an exec command line, a
 * container name, a label or the environment (free-form, and they can hold secrets).
 */

import type { DockerEvaluation, DockerObserved, DockerUse } from './config';
import { DOCKER_USES } from './config';
import { containerSection, type ContainerSummary } from './containers';
import { MAX_LIST } from '../mitmproxy/flows';
import { REDACTED, looksEncoded } from '../../report/redact';
import { code, plural, table } from '../../report/markdown';
import {
  VERDICT_ICON,
  refusedVerdict,
  type Advisory,
  type ReportContext,
  type RunnerSystem,
  type ScoreRow,
  type Section,
  type Suggestion
} from '../../report/section';

export interface DockerPolicyReport {
  /** the docker policy setup recorded (the input, or remove-group when unset) */
  policy: string;
  observed: DockerObserved;
  evaluation: DockerEvaluation;
}

/** Fixed caveat for every suggested `docker: keep`. */
export const DOCKER_KEEP_CAVEAT =
  'Docker access is root-equivalent: any step can use it to remove the egress controls, so enforce with ' +
  '`docker: keep` is ADVISORY.';

/** What analyze cannot see. */
export const DOCKER_BEST_EFFORT =
  'Best effort: read-only docker calls (`docker ps`, `logs`, `inspect`, `login`) leave no event and are not ' +
  "seen, docker use outside the runner's dockerd (rootless docker, podman) is not seen either, and in analyze " +
  'the job can use docker (root) to stop the recording.';

/** The recording did not cover the whole job. */
export const DOCKER_PARTIAL =
  'The recording did not cover the whole job (dockerd stopped, restarted or was not running at setup), ' +
  'so some use of docker may be missing.';

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

function score(o: DockerReportObserved, ctx: ReportContext): ScoreRow[] {
  const area = 'Docker';
  const rows: ScoreRow[] = [];
  const d = o.policy;
  if (ctx.enforce && o.docker) {
    const { access, requested } = o.docker;
    if (access === 'retained') rows.push({ verdict: 'advisory', area, text: 'kept (`docker: keep`)' });
    else if (access === 'group-removed')
      rows.push({ verdict: 'allowed', area, text: 'runner user removed from the docker group' });
    else rows.push({ verdict: 'allowed', area, text: requested === 'stop' ? 'daemon stopped' : 'daemon not running' });
  } else if (d) {
    const uses = dockerUseText(d.observed.uses);
    const e = d.evaluation;
    if (dockerUseCount(e.wouldBlock)) {
      rows.push({ verdict: 'would-block', area, text: `used after setup (${uses}): enforce would block it` });
    } else if (e.wouldStop) {
      rows.push({
        verdict: 'would-block',
        area,
        text: `\`docker: stop\` would stop ${plural(e.wouldStop, 'service container')}`
      });
    } else if (d.policy === 'keep') {
      rows.push({
        verdict: 'advisory',
        area,
        text: uses
          ? `used after setup (${uses}); \`docker: keep\` keeps it (ADVISORY)`
          : '`docker: keep` keeps docker, though no use was seen (ADVISORY)'
      });
    } else if (d.observed.partial) {
      rows.push({ verdict: 'advisory', area, text: 'no use seen, but the recording did not cover the whole job' });
    } else {
      const alsoStop = d.evaluation.fits === 'stop' && d.policy !== 'stop' ? ' (`docker: stop` would too)' : '';
      rows.push({ verdict: 'allowed', area, text: `no use after setup: \`docker: ${d.policy}\` fits${alsoStop}` });
    }
  } else if (o.docker) {
    rows.push({
      verdict: 'allowed',
      area,
      text: o.docker.access === 'not-running' ? 'daemon not running' : 'not evaluated'
    });
  }
  const refused = (o.containers ?? []).reduce((a, c) => a + c.denied.length + c.firewall.length, 0);
  if (refused) {
    rows.push({
      verdict: refusedVerdict(ctx),
      area,
      text: `container egress: ${plural(refused, 'destination')} ${ctx.enforce ? 'blocked' : 'would be blocked'}`
    });
  }
  return rows;
}

function advisory(o: DockerReportObserved, ctx: ReportContext): Advisory[] {
  if (!ctx.enforce || !o.retained) return [];
  return [
    {
      chip: '⚠️ docker retained',
      text:
        '`docker: keep` kept docker (verified on the runner), which is root-equivalent: any step could have removed ' +
        'the egress controls. Use `docker: remove-group` (the default) or `docker: stop` unless the job needs docker.'
    }
  ];
}

function suggestions(o: DockerReportObserved, ctx: ReportContext): Suggestion[] {
  const s = o.policy?.evaluation.suggestion;
  if (ctx.enforce || !s?.change) return [];
  return [
    {
      input: 'docker',
      value: s.value,
      ...(s.advisory ? { advisory: 'docker is root-equivalent: enforce is ADVISORY' } : {})
    }
  ];
}

function notes(o: DockerReportObserved, ctx: ReportContext): string[] {
  const d = o.policy;
  if (ctx.enforce || !d) return [];
  const out: string[] = [];
  if (d.evaluation.wouldStop && !dockerUseCount(d.evaluation.wouldBlock)) {
    out.push(
      '`docker: stop` would stop service containers: `remove-group` keeps them running and still takes docker from the job'
    );
  }
  if (d.evaluation.suggestion.value === 'keep' || d.policy === 'keep') out.push(DOCKER_KEEP_CAVEAT);
  if (d.observed.partial) out.push(DOCKER_PARTIAL);
  if (dockerUseCount(d.observed.uses) || d.observed.partial) out.push(DOCKER_BEST_EFFORT);
  return out;
}

function body(o: DockerReportObserved, ctx: ReportContext): string {
  let md = '';
  const d = ctx.enforce ? undefined : o.policy;
  if (d) {
    const blocks = dockerUseCount(d.evaluation.wouldBlock) > 0;
    const kinds = DOCKER_USES.filter(k => d.observed.uses[k]);
    if (kinds.length) {
      md +=
        table(
          ['', 'Use after setup', 'Events'],
          [':-:', ':--', '--:'],
          kinds.map(k => [
            VERDICT_ICON[blocks ? 'would-block' : 'advisory'],
            dockerUseText({ [k]: 1 }).replace(/^1 /, ''),
            String(d.observed.uses[k])
          ])
        ) + '\n\n';
    } else {
      md += 'No use of docker after setup was seen.\n\n';
    }
    if (d.observed.services)
      md += `${plural(d.observed.services, 'container')} already ran at setup (service containers).\n\n`;
    if (d.observed.images.length) {
      const shown = d.observed.images.slice(0, MAX_LIST).map(i => code(imageLabel(i)));
      const more = d.observed.images.length - shown.length;
      md += `Images: ${shown.join(', ')}${more > 0 ? ` +${more} more` : ''}\n\n`;
    }
  }
  md += containerSection(o.containers ?? [], ctx);
  return md || 'No container traffic.\n\n';
}

function runnerSystem(o: DockerReportObserved, ctx: ReportContext): RunnerSystem[] {
  if (!o.docker) return [];
  const { requested, access, caRestart } = o.docker;
  const rows: string[][] = [
    ctx.enforce
      ? [
          VERDICT_ICON[access === 'retained' ? 'advisory' : 'allowed'],
          code(`docker: ${requested}`),
          DOCKER_ACCESS_TEXT[access] ?? access
        ]
      : [
          VERDICT_ICON.allowed,
          code(`docker: ${requested}`),
          `evaluated, not applied (analyze); ${DOCKER_ACCESS_TEXT[access] ?? access}`
        ]
  ];
  if (caRestart) rows.push([VERDICT_ICON.allowed, 'dockerd restart', 'restarted so it trusts the proxy CA']);
  const summary =
    (ctx.enforce
      ? access === 'retained'
        ? 'docker kept'
        : access === 'group-removed'
          ? 'docker removed from the runner user'
          : 'docker daemon not running'
      : 'docker access unchanged (analyze)') + (caRestart ? ' · dockerd restarted to trust the CA' : '');
  return [{ summary, body: table(['', 'Action', 'Result'], [':-:', ':--', ':--'], rows) + '\n\n' }];
}

export function report(o: DockerReportObserved, ctx: ReportContext): Section {
  return {
    score: score(o, ctx),
    alerts: [],
    suggestions: suggestions(o, ctx),
    notes: notes(o, ctx),
    advisory: advisory(o, ctx),
    body: body(o, ctx),
    runnerSystem: runnerSystem(o, ctx)
  };
}

/** The uses enforce would block, for the job log. */
export function jobLog(policy: DockerPolicyReport | undefined): string[] {
  return DOCKER_USES.flatMap(k => {
    const n = policy?.evaluation.wouldBlock[k];
    return n ? [`docker WOULD_BLOCK ${k} x${n}`] : [];
  });
}
