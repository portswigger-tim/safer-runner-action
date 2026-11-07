/**
 * Docker's pure parts: the observed-access classification, the daemon.json merge for the CA
 * restart (F1), and the container address parser for the report. No I/O.
 */

export const RUNNER_USERNAME = 'runner';
export const DOCKER_GROUP = 'docker';
export const DOCKER_SOCKET = '/var/run/docker.sock';

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
