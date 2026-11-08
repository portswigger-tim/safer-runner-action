/**
 * Docker access control (the `docker` input) and dockerd handling for the proxy CA. Pure parts
 * are in ./config.ts.
 */

import * as core from '@actions/core';
import * as fs from 'fs';
import type { DockerPolicy } from '../../config/inputs';
import type { Mode } from '../../policy';
import { DOCKER_DAEMON_JSON, DOCKER_EVENTS_LOG, DOCKER_EVENTS_UNIT } from '../../constants';
import type { SelfTestsRun } from '../../setup/selftest';
import { realHost, sleep, sudo, timed, type Host } from '../../system/host';
import { startUnit } from '../../system/unit';
import type { TrustInstalled } from '../mitmproxy/trust';
import {
  DOCKER_GROUP,
  DOCKER_SOCKET,
  RUNNER_USERNAME,
  dockerAccess,
  eventRecorderUnit,
  mergeLiveRestore,
  parseContainerAddresses,
  type ApplyingDocker,
  type DockerAccess,
  type DockerPlan,
  type DockerState
} from './config';

export * from './config';

declare const dockerPrepared: unique symbol;
/**
 * dockerd is ready for the firewall: restarted to trust the CA if it had done TLS already (F1),
 * or not in play. Minted only by prepare().
 */
export type DockerPrepared = { readonly [dockerPrepared]: true };

/** A sudo step whose failure is collected, not thrown: the verified state decides. */
async function step(h: Host, args: string[]): Promise<string | null> {
  const rc = await sudo(args, { ignoreReturnCode: true }, h);
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
export async function disableDockerForRunner(
  h: Host,
  _apply: ApplyingDocker,
  socket: string = DOCKER_SOCKET
): Promise<string[]> {
  core.info('Removing the runner user from the docker group and locking the docker socket...');
  const failed: string[] = [];
  if (await isRunnerInDockerGroup(h)) {
    const err = await step(h, ['gpasswd', '-d', RUNNER_USERNAME, DOCKER_GROUP]);
    if (err) failed.push(err);
  }
  if (fs.existsSync(socket)) {
    for (const args of [
      ['chown', 'root:root', socket],
      ['chmod', '600', socket]
    ]) {
      const err = await step(h, args);
      if (err) failed.push(err);
    }
  }
  return failed;
}

/**
 * docker: stop. Stops and disables the docker daemon and its socket unit (this also stops any
 * running containers). Returns the steps that failed; readDockerState() is the verdict.
 */
export async function stopDockerService(h: Host, _apply: ApplyingDocker): Promise<string[]> {
  core.info('Stopping and disabling the docker daemon...');
  const failed: string[] = [];
  for (const verb of ['stop', 'disable']) {
    for (const unit of ['docker.socket', 'docker.service']) {
      const err = await step(h, ['systemctl', verb, unit]);
      if (err) failed.push(err);
    }
  }
  return failed;
}

/**
 * Whether the runner user is in the docker group (`id -nG runner`, i.e. what a new session
 * gets). Fails closed: if membership cannot be read, it is assumed.
 */
export async function isRunnerInDockerGroup(h: Host): Promise<boolean> {
  const { stdout, exitCode } = await h.output('id', ['-nG', RUNNER_USERNAME], {
    ignoreReturnCode: true,
    silent: true
  });
  if (exitCode !== 0) {
    core.warning(`Could not read the groups of ${RUNNER_USERNAME} (id exit ${exitCode}); assuming docker membership`);
    return true;
  }
  return stdout.trim().split(/\s+/).includes(DOCKER_GROUP);
}

function canUseSocket(socket: string): boolean {
  try {
    fs.accessSync(socket, fs.constants.R_OK | fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

async function unitActive(h: Host, unit: string): Promise<boolean> {
  return (await h.run('systemctl', ['is-active', '--quiet', unit], { ignoreReturnCode: true, silent: true })) === 0;
}

export async function readDockerState(h: Host, socket: string = DOCKER_SOCKET): Promise<DockerState> {
  return {
    daemonActive: await unitActive(h, 'docker.service'),
    socketUnitActive: await unitActive(h, 'docker.socket'),
    runnerInGroup: await isRunnerInDockerGroup(h),
    socketAccessible: canUseSocket(socket)
  };
}

/** `systemctl is-active docker`. */
async function isDockerActive(h: Host): Promise<boolean> {
  const rc = await h.run('systemctl', ['is-active', '--quiet', 'docker'], { ignoreReturnCode: true, silent: true });
  return rc === 0;
}

/** IDs of running containers (empty when docker is not reachable). */
async function runningContainers(h: Host): Promise<string[]> {
  const { stdout, exitCode } = await h.output('sudo', ['docker', 'ps', '-q', '--no-trunc'], {
    ignoreReturnCode: true,
    silent: true
  });
  return exitCode === 0 ? stdout.split('\n').filter(Boolean) : [];
}

async function waitForDocker(h: Host, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rc = await h.run('sudo', ['docker', 'info', '--format', '{{.ServerVersion}}'], {
      ignoreReturnCode: true,
      silent: true
    });
    if (rc === 0) return true;
    await sleep(500);
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
async function restartForCaTrust(h: Host): Promise<boolean> {
  const before = await runningContainers(h);
  const { stdout: existing } = await h.output('sudo', ['cat', DOCKER_DAEMON_JSON], {
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
    await sudo(['install', '-d', '-m', '0755', '/etc/docker'], {}, h);
    await sudo(['tee', DOCKER_DAEMON_JSON], { input: Buffer.from(merged.json), silent: true }, h);
    // live-restore is one of the options dockerd reloads on SIGHUP (ExecReload)
    await sudo(['systemctl', 'reload', 'docker'], {}, h);
    await sleep(500);
  }
  const t0 = Date.now();
  await sudo(['systemctl', 'restart', 'docker'], {}, h);
  if (!(await waitForDocker(h, 30000))) {
    throw new Error('dockerd did not come back within 30s after restart (F1 CA trust reload)');
  }
  const after = new Set(await runningContainers(h));
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
 * Get dockerd ready for the firewall, once the CA is trusted: when docker runs (and is not about
 * to be stopped) and dockerd may already have done TLS (`keep`, or service containers running),
 * restart it so it trusts the CA (F1). Returns whether docker is active (the firewall adds the
 * container rules) and whether daemon.json was written (it joins the integrity baseline).
 */
export async function prepare(
  h: Host,
  policy: DockerPolicy,
  _trust: TrustInstalled
): Promise<{ active: boolean; configWritten: boolean; prepared: DockerPrepared }> {
  const active = policy !== 'stop' && (await isDockerActive(h));
  let configWritten = false;
  if (active) {
    const services = await runningContainers(h);
    if (policy === 'keep' || services.length > 0) {
      configWritten = await timed('Restart dockerd (CA trust)', () => restartForCaTrust(h));
    }
  }
  return { active, configWritten, prepared: Object.freeze({}) as DockerPrepared };
}

/** Where the docker events recording starts: the post step reads the use of docker after it. */
export interface DockerEventsStart {
  /** when the recorder started */
  since: string;
  /** containers already running then (service containers): not the job's use of docker */
  containers: string[];
}

/**
 * analyze: start the docker events recorder (eventRecorderUnit), once dockerd has settled (it
 * restarts for the CA first). Only when docker.service is already running: `docker events`
 * against a socket-activated daemon would start it. Best effort: analyze never fails on it, and
 * the post step then calls its docker evaluation partial. Returns null when not recording.
 */
export async function startEventRecorder(h: Host, _prepared: DockerPrepared): Promise<DockerEventsStart | null> {
  if (!(await unitActive(h, 'docker.service'))) {
    core.info('docker events: docker.service is not running, so nothing is recorded (analyze never starts it)');
    return null;
  }
  const containers = await runningContainers(h);
  const since = new Date().toISOString();
  try {
    await sudo(['touch', DOCKER_EVENTS_LOG], {}, h);
    await sudo(['chmod', '0644', DOCKER_EVENTS_LOG], {}, h);
    await startUnit(h, eventRecorderUnit(), {
      ready: () => unitActive(h, DOCKER_EVENTS_UNIT),
      pollMs: 200,
      timeoutMs: 5000,
      diagnostics: [
        ['systemctl', 'status', DOCKER_EVENTS_UNIT, '--no-pager', '-l'],
        ['journalctl', '-u', DOCKER_EVENTS_UNIT, '--no-pager', '-n', '20']
      ],
      timeoutError: () => new Error('the recorder did not start within 5s')
    });
  } catch (error) {
    core.warning(`docker events: not recorded (${error}); the summary's docker evaluation will be partial`);
    return null;
  }
  core.info(`docker events: recording to ${DOCKER_EVENTS_LOG} (${containers.length} container(s) already running)`);
  return { since, containers };
}

/** What the setup marker (and so the report) records about docker: requested AND verified. */
export interface DockerOutcome {
  /** the docker policy (the input, or remove-group when unset); applied only in enforce */
  requested: DockerPolicy;
  access: DockerAccess;
  state: DockerState;
}

/**
 * Apply the docker plan (enforce only: see planDocker), then verify the runner user's real docker
 * access (G4). Docker is root-equivalent, so a removal that did not take fails setup closed
 * instead of leaving a reversible boundary. `keep` in enforce is ADVISORY, like sudo. analyze
 * only reads the state.
 */
export async function applyAccessPolicy(
  h: Host,
  mode: Mode,
  plan: DockerPlan,
  _selfTests: SelfTestsRun
): Promise<DockerOutcome> {
  const { apply } = plan;
  const docker = plan.applied;
  const failures = !apply
    ? []
    : apply.removal === 'stop'
      ? await stopDockerService(h, apply)
      : await disableDockerForRunner(h, apply);
  const state = await readDockerState(h);
  const access = dockerAccess(state);
  core.info(
    `docker: ${plan.policy}${mode === 'analyze' ? ' (analyze: not applied)' : ''} -> verified ${access} ` +
      `(daemon ${state.daemonActive ? 'active' : 'inactive'}, ` +
      `runner in docker group: ${state.runnerInGroup}, socket usable: ${state.socketAccessible})`
  );
  if (apply && access === 'retained') {
    throw new Error(
      `docker: ${apply.removal} did not take effect - the runner user can still use docker (root-equivalent)` +
        (failures.length ? `: ${failures.join('; ')}` : '')
    );
  } else if (failures.length) {
    core.warning(`docker: ${docker}: ${failures.join('; ')} (verified: ${access})`);
  }
  if (mode === 'enforce' && access === 'retained') {
    core.warning(
      'enforce is ADVISORY in this job: docker is retained (docker: keep), and docker access is root-equivalent, ' +
        'so any step can use it to remove the egress controls. Use docker: remove-group (the enforce default) ' +
        'or docker: stop unless the job needs docker.',
      { title: 'safer-runner: enforce (ADVISORY - docker retained)' }
    );
  }
  return { requested: plan.policy, access, state };
}

/**
 * Container IP -> name for the report. Without sudo: under the default enforce the runner has
 * lost docker access, and the report then shows addresses only. Containers already removed
 * (`docker run --rm`) are not listed either.
 */
export async function containerAddresses(h: Host = realHost): Promise<Map<string, string>> {
  const opts = { ignoreReturnCode: true, silent: true };
  const ids = await h.output('docker', ['ps', '-aq'], opts);
  const list = ids.exitCode === 0 ? ids.stdout.split('\n').filter(Boolean) : [];
  if (!list.length) return new Map();
  const fmt = '{{.Name}}{{range .NetworkSettings.Networks}} {{.IPAddress}}{{end}}';
  const { stdout, exitCode } = await h.output('docker', ['inspect', '--format', fmt, ...list], opts);
  return exitCode === 0 ? parseContainerAddresses(stdout) : new Map();
}
