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
import { code, codeBlock, plural } from '../../report/markdown';
import type { Alert, ReportContext, Section } from '../../report/section';

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
  /** the docker input and the access verified after applying it (G4) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running' };
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

/**
 * Analyze: what the docker policy would break in enforce, and the docker setting to run the job
 * under enforce (in an alert); '' when there is nothing to say. Report only.
 */
function dockerAlert(d: DockerPolicyReport): string {
  const { policy, observed, evaluation: e } = d;
  const uses = dockerUseText(observed.uses);
  const caveat = observed.partial ? `${DOCKER_PARTIAL} ${DOCKER_BEST_EFFORT}` : DOCKER_BEST_EFFORT;
  const blocked = dockerUseCount(e.wouldBlock);
  let md: string;
  if (blocked) {
    md =
      `> **Enforce would block docker, which this job used after setup** (\`docker: ${policy}\`: ${uses}; ` +
      'listed under Diagnostics). Move the docker work to a job that does not run under enforce, or keep docker ' +
      '(review first):\n>\n' +
      codeBlock('yaml', 'docker: keep')
        .split('\n')
        .map(l => `> ${l}`)
        .join('\n') +
      `\n>\n> ${DOCKER_KEEP_CAVEAT}`;
  } else if (e.wouldStop) {
    md =
      `> **\`docker: stop\` would stop this job's ${plural(e.wouldStop, 'service container')}.** Leave \`docker\` ` +
      'unset: `remove-group` keeps them running and still takes docker from the job.';
  } else if (policy === 'keep' && dockerUseCount(observed.uses)) {
    md =
      `> **This job used docker after setup (${uses}), and \`docker: keep\` keeps it**, so enforce would be ` +
      `ADVISORY. ${DOCKER_KEEP_CAVEAT}`;
  } else if (policy === 'keep') {
    md =
      '> **No use of docker after setup was seen, but `docker: keep` keeps it**, so enforce would be ADVISORY ' +
      '(docker is root-equivalent). Remove `docker: keep` to make enforce a boundary.';
  } else if (observed.partial) {
    // nothing seen is not nothing used: enforce would block a use the recording missed
    return (
      `> **No use of docker after setup was seen, but the recording did not cover the whole job**, and enforce ` +
      `(\`docker: ${policy}\`) would block any use it missed. Check the job under enforce.\n>\n> ${caveat}`
    );
  } else {
    return '';
  }
  return md + `\n>\n> ${caveat}`;
}

function chips(o: DockerReportObserved, ctx: ReportContext): string[] {
  if (ctx.enforce) return o.retained ? ['⚠️ docker retained'] : [];
  const out: string[] = [];
  const wouldBlock = dockerUseCount(o.policy?.evaluation.wouldBlock ?? {});
  const wouldStop = o.policy?.evaluation.wouldStop ?? 0;
  if (wouldBlock) out.push(`${plural(wouldBlock, 'docker use')} would be blocked`);
  if (wouldStop) out.push(`${plural(wouldStop, 'service container')} would be stopped`);
  // a partial docker recording can have missed a use enforce would block: never "nothing"
  if (o.policy?.observed.partial === true) out.push('⚠️ docker use partly unseen');
  return out;
}

function alerts(o: DockerReportObserved, ctx: ReportContext, alert: string): Alert[] {
  if (ctx.enforce) {
    if (!o.retained) return [];
    return [
      {
        kind: 'WARNING',
        text:
          '**ADVISORY: docker was retained** (`docker: keep`; verified on the runner). Docker access is ' +
          'root-equivalent, so any step could have used it to remove the egress controls. Use `docker: remove-group` ' +
          '(what enforce does) or `docker: stop` unless the job needs docker.'
      }
    ];
  }
  return alert ? [{ kind: 'IMPORTANT', text: alert + '\n', quoted: true }] : [];
}

function diagnostics(o: DockerReportObserved, ctx: ReportContext): Section['diagnostics'] {
  if (!o.docker) return [];
  const { enforce } = ctx;
  const { requested, access } = o.docker;
  const summary = enforce
    ? access === 'retained'
      ? 'docker retained'
      : access === 'group-removed'
        ? 'docker removed ✓'
        : 'docker stopped ✓'
    : 'docker unchanged (analyze)';
  // analyze never changes docker access: the policy is only evaluated
  const policy = enforce
    ? `\`docker: ${requested}\``
    : `policy \`docker: ${requested}\` (analyze: evaluated, not applied)`;
  let body = `**Docker** — ${policy}; verified at setup: ${DOCKER_ACCESS_TEXT[access] ?? access}\n\n`;
  const d = enforce ? undefined : o.policy;
  if (d) {
    const uses = dockerUseText(d.observed.uses);
    body += uses ? `Used after setup: ${uses}.` : 'No use of docker after setup was seen.';
    if (d.observed.services)
      body += ` ${plural(d.observed.services, 'container')} already ran at setup (service containers).`;
    if (!uses && !d.observed.partial && d.evaluation.fits === 'stop' && d.policy !== 'stop') {
      body += ' `docker: stop` would also fit.';
    }
    body += '\n\n';
    if (d.observed.images.length) {
      const shown = d.observed.images.slice(0, MAX_LIST).map(i => code(imageLabel(i)));
      const more = d.observed.images.length - shown.length;
      body += `Images: ${shown.join(', ')}${more > 0 ? ` +${more} more` : ''}\n\n`;
    }
    if (d.observed.partial) body += `${DOCKER_PARTIAL}\n\n`;
  }
  return [{ summary, body }];
}

export function report(o: DockerReportObserved, ctx: ReportContext): Section {
  const alert = ctx.enforce || !o.policy ? '' : dockerAlert(o.policy);
  return {
    chips: chips(o, ctx),
    alerts: alerts(o, ctx, alert),
    score: [],
    blocking: alert !== '',
    body: containerSection(o.containers ?? [], ctx.mode),
    diagnostics: diagnostics(o, ctx),
    jobLog: DOCKER_USES.flatMap(k => {
      const n = o.policy?.evaluation.wouldBlock[k];
      return n ? [`docker WOULD_BLOCK ${k} x${n}`] : [];
    }),
    advisory: ctx.enforce && o.retained ? 'docker' : ''
  };
}
