/**
 * Docker access control (the `docker` input) and dockerd handling for the proxy CA.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { DOCKER_DAEMON_JSON } from './constants';

// Constants
export const RUNNER_USERNAME = 'runner';
export const DOCKER_GROUP = 'docker';
export const DOCKER_SOCKET = '/var/run/docker.sock';

async function run(args: string[]): Promise<string | null> {
  const rc = await exec.exec('sudo', args, { ignoreReturnCode: true });
  return rc === 0 ? null : `sudo ${args.join(' ')} exited ${rc}`;
}

/**
 * docker: remove-group. Removes the runner user from the docker group (new sessions) and locks
 * the socket to root:root 0600 (the current session keeps the group in its credentials, so
 * the group change alone would not stop it). Idempotent: a runner already outside the group,
 * or without a socket, is left alone.
 *
 * Returns the steps that failed. Whether access is really gone is decided by readDockerState()
 * afterwards - the caller fails closed on that, not on these messages.
 */
export async function disableDockerForRunner(socket: string = DOCKER_SOCKET): Promise<string[]> {
  core.info('Removing the runner user from the docker group and locking the docker socket...');
  const failed: string[] = [];
  if (await isRunnerInDockerGroup()) {
    const err = await run(['gpasswd', '-d', RUNNER_USERNAME, DOCKER_GROUP]);
    if (err) failed.push(err);
  }
  if (fs.existsSync(socket)) {
    for (const args of [
      ['chown', 'root:root', socket],
      ['chmod', '600', socket]
    ]) {
      const err = await run(args);
      if (err) failed.push(err);
    }
  }
  return failed;
}

/**
 * docker: stop. Stops and disables the docker daemon and its socket unit (this also stops any
 * running containers). Returns the steps that failed; readDockerState() is the verdict.
 */
export async function stopDockerService(): Promise<string[]> {
  core.info('Stopping and disabling the docker daemon...');
  const failed: string[] = [];
  for (const verb of ['stop', 'disable']) {
    for (const unit of ['docker.socket', 'docker.service']) {
      const err = await run(['systemctl', verb, unit]);
      if (err) failed.push(err);
    }
  }
  return failed;
}

/**
 * Whether the runner user is in the docker group (`id -nG runner`, i.e. what a new session
 * gets). Fails closed: if membership cannot be read, it is assumed.
 */
export async function isRunnerInDockerGroup(): Promise<boolean> {
  const { stdout, exitCode } = await exec.getExecOutput('id', ['-nG', RUNNER_USERNAME], {
    ignoreReturnCode: true,
    silent: true
  });
  if (exitCode !== 0) {
    core.warning(`Could not read the groups of ${RUNNER_USERNAME} (id exit ${exitCode}); assuming docker membership`);
    return true;
  }
  return stdout.trim().split(/\s+/).includes(DOCKER_GROUP);
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

function canUseSocket(socket: string): boolean {
  try {
    fs.accessSync(socket, fs.constants.R_OK | fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

async function unitActive(unit: string): Promise<boolean> {
  return (await exec.exec('systemctl', ['is-active', '--quiet', unit], { ignoreReturnCode: true, silent: true })) === 0;
}

export async function readDockerState(socket: string = DOCKER_SOCKET): Promise<DockerState> {
  return {
    daemonActive: await unitActive('docker.service'),
    socketUnitActive: await unitActive('docker.socket'),
    runnerInGroup: await isRunnerInDockerGroup(),
    socketAccessible: canUseSocket(socket)
  };
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

/** `systemctl is-active docker`. */
export async function isDockerActive(): Promise<boolean> {
  const rc = await exec.exec('systemctl', ['is-active', '--quiet', 'docker'], { ignoreReturnCode: true, silent: true });
  return rc === 0;
}

/** IDs of running containers (empty when docker is not reachable). */
export async function runningContainers(): Promise<string[]> {
  const { stdout, exitCode } = await exec.getExecOutput('sudo', ['docker', 'ps', '-q', '--no-trunc'], {
    ignoreReturnCode: true,
    silent: true
  });
  return exitCode === 0 ? stdout.split('\n').filter(Boolean) : [];
}

async function waitForDocker(timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rc = await exec.exec('sudo', ['docker', 'info', '--format', '{{.ServerVersion}}'], {
      ignoreReturnCode: true,
      silent: true
    });
    if (rc === 0) return true;
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

/**
 * F1: dockerd is Go and caches the system roots on its first TLS handshake. When the runner
 * pulled a service/job container image before the action ran, those roots predate our CA and
 * every later `docker pull` through the proxy fails with x509 - in every mode. Restarting
 * dockerd reloads the roots; live-restore (reloadable by SIGHUP) keeps the running service
 * containers alive across the restart. Must run after the CA is in the system store and
 * before the firewall (Docker rebuilds its own chains on restart).
 *
 * Returns true when daemon.json was written (it then belongs in the integrity baseline).
 */
export async function restartDockerForCaTrust(): Promise<boolean> {
  const before = await runningContainers();
  const { stdout: existing } = await exec.getExecOutput('sudo', ['cat', DOCKER_DAEMON_JSON], {
    ignoreReturnCode: true,
    silent: true
  });
  const merged = mergeLiveRestore(existing);
  if (merged === null) {
    core.warning(
      `${DOCKER_DAEMON_JSON} is not a JSON object: dockerd not restarted, so a dockerd that pulled images ` +
        'before this action may not trust the proxy CA (docker pull: x509 errors)'
    );
    return false;
  }
  if (merged.changed) {
    await exec.exec('sudo', ['install', '-d', '-m', '0755', '/etc/docker']);
    await exec.exec('sudo', ['tee', DOCKER_DAEMON_JSON], { input: Buffer.from(merged.json), silent: true });
    // live-restore is one of the options dockerd reloads on SIGHUP (ExecReload)
    await exec.exec('sudo', ['systemctl', 'reload', 'docker']);
    await new Promise(r => setTimeout(r, 500));
  }
  const t0 = Date.now();
  await exec.exec('sudo', ['systemctl', 'restart', 'docker']);
  if (!(await waitForDocker(30000))) {
    throw new Error('dockerd did not come back within 30s after restart (F1 CA trust reload)');
  }
  const after = new Set(await runningContainers());
  const lost = before.filter(id => !after.has(id));
  core.info(
    `dockerd restarted to trust the proxy CA in ${((Date.now() - t0) / 1000).toFixed(1)}s ` +
      `(${before.length} running container(s) kept: ${before.length - lost.length})`
  );
  if (lost.length > 0) {
    core.warning(
      `${lost.length} container(s) stopped across the dockerd restart: ${lost.map(i => i.slice(0, 12)).join(', ')}`
    );
  }
  return true;
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

/**
 * Container IP -> name for the report. Without sudo: under the default enforce the runner has
 * lost docker access, and the report then shows addresses only. Containers already removed
 * (`docker run --rm`) are not listed either.
 */
export async function containerAddresses(): Promise<Map<string, string>> {
  const opts = { ignoreReturnCode: true, silent: true };
  const ids = await exec.getExecOutput('docker', ['ps', '-aq'], opts);
  const list = ids.exitCode === 0 ? ids.stdout.split('\n').filter(Boolean) : [];
  if (!list.length) return new Map();
  const fmt = '{{.Name}}{{range .NetworkSettings.Networks}} {{.IPAddress}}{{end}}';
  const { stdout, exitCode } = await exec.getExecOutput('docker', ['inspect', '--format', fmt, ...list], opts);
  return exitCode === 0 ? parseContainerAddresses(stdout) : new Map();
}
