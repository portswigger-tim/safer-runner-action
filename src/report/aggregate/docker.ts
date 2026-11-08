/**
 * Analyze: the docker policy against the job's use of docker (services/docker: observeDocker,
 * evaluateDocker), for the summary. Only kinds and counts and image names are shown: never an
 * exec command line, a container name, a label or the environment (free-form, and they can hold
 * secrets).
 */

import type { DockerEvaluation, DockerObserved, DockerUse } from '../../services/docker/config';
import { DOCKER_USES } from '../../services/docker/config';
import { REDACTED, looksEncoded } from '../redact';
import { plural } from '../render/markdown';

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
  'Best effort: in analyze the job can use docker (root) to stop the recording, and docker use outside the ' +
  "runner's dockerd (rootless docker, podman) is not seen.";

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
 * part of it (registry, path, tag, digest) through the label check, so a digest or an encoded
 * tag prints as REDACTED.
 */
export function imageLabel(ref: string): string {
  if (!IMAGE_REF.test(ref)) return REDACTED;
  return ref
    .split(/([/:@])/)
    .map(p => (/^[/:@]$/.test(p) || !looksEncoded(p) ? p : REDACTED))
    .join('');
}
