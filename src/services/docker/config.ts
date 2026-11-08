/**
 * Docker's pure parts: the access plan (what the docker input changes, by mode), the
 * observed-access classification, the daemon.json merge for the CA restart (F1), and the
 * container address parser for the report. No I/O.
 */

import type { DockerPolicy } from '../../config/inputs';
import { DOCKER_EVENTS_LOG, DOCKER_EVENTS_UNIT, LOG_DIR } from '../../constants';
import type { Mode } from '../../policy';
import type { DockerEvent } from '../../report/logs/docker-events';
import type { UnitSpec } from '../../system/types';
import { HARDENING } from '../../system/unit';

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

/**
 * analyze: the docker events recorder. It only subscribes (`docker events`) and appends each
 * event to DOCKER_EVENTS_LOG, so the post step sees every use of docker after setup (dockerd
 * itself keeps only the latest events). Never restarted: reconnecting to a stopped daemon
 * would start it through socket activation. No network, no capabilities; the docker CLI reads no
 * config (no context can point it elsewhere) and talks to the socket named here.
 */
export function eventRecorderUnit(): UnitSpec {
  return {
    unit: DOCKER_EVENTS_UNIT,
    description: 'safer-runner docker events recorder (analyze)',
    user: 'root',
    restart: 'no',
    props: [
      ...HARDENING,
      'PrivateNetwork=yes',
      'CapabilityBoundingSet=',
      `ReadWritePaths=${LOG_DIR}`,
      `StandardOutput=append:${DOCKER_EVENTS_LOG}`
    ],
    env: { DOCKER_CONFIG: '/run/safer-runner/docker-cli-none' },
    argv: ['/usr/bin/docker', '-H', `unix://${DOCKER_SOCKET}`, 'events', '--format', '{{json .}}']
  };
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

/** A kind of docker use the job made after setup: each one fails once enforce removes docker. */
export type DockerUse = 'container' | 'exec' | 'image' | 'build' | 'network' | 'volume' | 'other';
export const DOCKER_USES: DockerUse[] = ['container', 'exec', 'image', 'build', 'network', 'volume', 'other'];

/** Container actions dockerd makes on its own (no client asked): not a use of docker. */
const DAEMON_ACTIONS = new Set(['die', 'oom', 'exec_die', 'exec_detach', 'health_status']);

/**
 * The commands a container's healthcheck runs, as dockerd names them in its exec events
 * (`exec_create: <entrypoint> <args>`). `test` and `shell` are the container's
 * Config.Healthcheck.Test and Config.Shell.
 */
export function healthcheckCommands(test: unknown, shell: unknown): string[] {
  if (!Array.isArray(test) || !test.every(t => typeof t === 'string')) return [];
  const [kind, ...rest] = test as string[];
  if (kind === 'CMD') return [rest.join(' ').trim()];
  if (kind !== 'CMD-SHELL' || rest.length !== 1) return [];
  const sh =
    Array.isArray(shell) && shell.length && shell.every(t => typeof t === 'string') ? shell : ['/bin/sh', '-c'];
  return [[...sh, rest[0]].join(' ').trim()];
}

export interface DockerObserved {
  /** the job's use of docker after setup: kind -> events */
  uses: Partial<Record<DockerUse, number>>;
  /** images the job used (as docker names them; the report sanitises them) */
  images: string[];
  /** containers already running at setup (service containers) */
  services: number;
  /** some use may be missing: the recording did not cover the whole job */
  partial: boolean;
}

/**
 * The job's use of docker in the events after setup. Not a use: what dockerd does on its own
 * (a container exiting, its healthcheck and health status, its own reload). `healthchecks` maps
 * a container to its healthcheck commands (healthcheckCommands): an exec of exactly that is the
 * healthcheck, any other exec (a step's `docker exec`) is a use.
 */
export function classifyDockerEvents(
  events: readonly DockerEvent[],
  healthchecks: ReadonlyMap<string, readonly string[]> = new Map()
): Pick<DockerObserved, 'uses' | 'images'> {
  const uses: Partial<Record<DockerUse, number>> = {};
  const images: string[] = [];
  const add = (k: DockerUse) => (uses[k] = (uses[k] ?? 0) + 1);
  for (const e of events) {
    if (e.type === 'daemon') continue;
    if (e.type === 'container') {
      if (DAEMON_ACTIONS.has(e.action)) continue;
      if (e.action.startsWith('exec_')) {
        if (e.command !== undefined && healthchecks.get(e.id)?.includes(e.command.trim())) continue;
        add('exec');
      } else add('container');
    } else if (e.type === 'image') add('image');
    else if (e.type === 'builder') add('build');
    else if (e.type === 'network') add('network');
    else if (e.type === 'volume') add('volume');
    else add('other');
    if (e.image && !images.includes(e.image)) images.push(e.image);
  }
  return { uses, images };
}

/** The docker setting to run this job under enforce: report only, never applied. */
export interface DockerSuggestion {
  input: 'docker';
  value: DockerPolicy;
  /** the value keeps docker (root-equivalent): enforce would be ADVISORY */
  advisory: boolean;
  /** the value differs from the job's policy */
  change: boolean;
}

export interface DockerEvaluation {
  /** the uses the policy would block in enforce (remove-group, stop): kind -> events */
  wouldBlock: Partial<Record<DockerUse, number>>;
  /** stop: the service containers it would stop */
  wouldStop: number;
  /** the least docker access that breaks nothing observed */
  fits: DockerPolicy;
  suggestion: DockerSuggestion;
}

/**
 * Analyze: what the docker policy would break in enforce, and the setting to suggest. Any use of
 * docker after setup needs `keep` (docker has no allowlist), which makes enforce ADVISORY; a
 * policy that would break nothing is kept as it is. Never suggests `stop` over the default:
 * `remove-group` already takes docker from the job.
 */
export function evaluateDocker(policy: DockerPolicy, observed: DockerObserved): DockerEvaluation {
  const used = DOCKER_USES.some(k => (observed.uses[k] ?? 0) > 0);
  const wouldBlock = policy === 'keep' ? {} : { ...observed.uses };
  const wouldStop = policy === 'stop' ? observed.services : 0;
  const fits: DockerPolicy = used ? 'keep' : observed.services ? 'remove-group' : 'stop';
  const value: DockerPolicy = used
    ? 'keep'
    : policy === 'keep' || (policy === 'stop' && observed.services)
      ? 'remove-group'
      : policy;
  return {
    wouldBlock,
    wouldStop,
    fits,
    suggestion: { input: 'docker', value, advisory: value === 'keep', change: value !== policy }
  };
}
