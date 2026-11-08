/**
 * Docker's pure parts: the access plan (what the docker input changes, by mode), the
 * observed-access classification, the daemon.json merge for the CA restart (F1), and the
 * container address parser for the report. No I/O.
 */

import type { DockerPolicy } from '../../config/inputs';
import type { Mode } from '../../policy';

export const RUNNER_USERNAME = 'runner';
export const DOCKER_GROUP = 'docker';
export const DOCKER_SOCKET = '/var/run/docker.sock';

declare const applyingDocker: unique symbol;
/**
 * A change to docker access that setup makes: only in enforce, and only for a policy that
 * removes access. Minted only by planDocker(), so analyze changing docker access does not
 * compile (the functions that change it take one).
 */
export type ApplyingDocker = { readonly removal: Exclude<DockerPolicy, 'keep'>; readonly [applyingDocker]: true };

export interface DockerPlan {
  /** the docker policy: the input, or remove-group when unset */
  policy: DockerPolicy;
  /** what setup leaves in place: the policy in enforce; analyze never changes docker (keep) */
  applied: DockerPolicy;
  /** the change setup makes (enforce, policy not keep); null: none */
  apply: ApplyingDocker | null;
}

/**
 * The docker policy as setup applies it. enforce applies it; analyze never changes docker access
 * (it evaluates the policy in the post step instead), so docker stays usable and is treated as
 * `keep` (the CA restart and the container rules follow from that).
 */
export function planDocker(mode: Mode, policy: DockerPolicy): DockerPlan {
  if (mode !== 'enforce' || policy === 'keep') return { policy, applied: 'keep', apply: null };
  return { policy, applied: policy, apply: Object.freeze({ removal: policy }) as ApplyingDocker };
}

/** Docker access as observed on the runner (not as requested). */
export interface DockerState {
  /** docker.service is active */
  daemonActive: boolean;
  /** docker.socket (socket activation) is active */
  socketUnitActive: boolean;
  /** a new runner session would get the docker group */
  runnerInGroup: boolean;
  /** this process (the runner user's current credentials) can read+write the docker socket */
  socketAccessible: boolean;
}

/**
 * Verified docker access for the runner user:
 * - not-running: neither the daemon nor its socket unit is active
 * - group-removed: the daemon runs, but the runner is out of the group and cannot use the socket
 * - retained: the runner can use docker (root-equivalent)
 */
export type DockerAccess = 'retained' | 'group-removed' | 'not-running';

export function dockerAccess(s: DockerState): DockerAccess {
  if (!s.daemonActive && !s.socketUnitActive) return 'not-running';
  if (!s.runnerInGroup && !s.socketAccessible) return 'group-removed';
  return 'retained';
}

/**
 * Merge `live-restore: true` into a daemon.json body. Returns null when the existing file is
 * not a JSON object (never overwrite a config we can't parse - dockerd would refuse to start).
 */
export function mergeLiveRestore(existing: string): { json: string; changed: boolean } | null {
  let cfg: Record<string, unknown> = {};
  if (existing.trim() !== '') {
    try {
      const parsed = JSON.parse(existing);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      cfg = parsed as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  if (cfg['live-restore'] === true) return { json: existing, changed: false };
  return { json: JSON.stringify({ ...cfg, 'live-restore': true }, null, 2) + '\n', changed: true };
}

/**
 * Parse `docker inspect --format '{{.Name}}{{range .NetworkSettings.Networks}} {{.IPAddress}}{{end}}'`
 * output into container IP -> name.
 */
export function parseContainerAddresses(output: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of output.split('\n')) {
    const [rawName, ...ips] = line.trim().split(/\s+/);
    if (!rawName) continue;
    const name = rawName.replace(/^\//, '');
    for (const ip of ips) if (ip && !out.has(ip)) out.set(ip, name);
  }
  return out;
}
