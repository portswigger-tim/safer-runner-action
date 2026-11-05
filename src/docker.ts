/**
 * Docker access control module
 * Handles Docker group membership and container access restrictions
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { DOCKER_DAEMON_JSON } from './constants';

// Constants
export const RUNNER_USERNAME = 'runner';
export const DOCKER_GROUP = 'docker';

/**
 * Disable Docker access for the runner user
 * This prevents container escape attacks, docker socket abuse, and privileged container execution
 *
 * Strategy:
 * 1. Remove runner from docker group (prevents new sessions from getting access)
 * 2. Change docker socket permissions to block current session
 *
 * Note: Simply removing group membership doesn't affect the current process's
 * credential cache, so we must also restrict the docker socket directly.
 */
export async function disableDockerForRunner(): Promise<void> {
  core.info('Disabling Docker access for runner user...');

  try {
    // Step 1: Remove runner from docker group (for future sessions)
    await exec.exec('sudo', ['gpasswd', '-d', RUNNER_USERNAME, DOCKER_GROUP]);
    core.info(`✅ Removed ${RUNNER_USERNAME} from ${DOCKER_GROUP} group`);

    // Step 2: Restrict docker socket permissions to block current session
    // Change ownership to root:root and set permissions to 600 (owner-only access)
    core.info('Restricting docker socket permissions...');
    await exec.exec('sudo', ['chown', 'root:root', '/var/run/docker.sock']);
    await exec.exec('sudo', ['chmod', '600', '/var/run/docker.sock']);

    core.info('✅ Docker socket access restricted to root only');
    core.info('🔒 Docker commands will no longer be available to the runner user');
    core.info('ℹ️  This prevents container escape attacks and docker socket abuse');
  } catch (error) {
    core.warning(`Could not fully disable Docker access: ${error}`);
  }
}

/**
 * Stop and disable the Docker service completely
 * This provides stronger protection than disableDockerForRunner by preventing
 * all Docker usage system-wide, not just for the runner user.
 *
 * Strategy:
 * 1. Stop the Docker service (kills all running containers)
 * 2. Disable the Docker service (prevents automatic restart)
 *
 * Note: This affects the entire system and will terminate any running containers.
 */
export async function stopDockerService(): Promise<void> {
  core.info('Stopping and disabling Docker service...');

  try {
    // Step 1: Stop the Docker service
    core.info('Stopping Docker service...');
    await exec.exec('sudo', ['systemctl', 'stop', 'docker.socket']);
    await exec.exec('sudo', ['systemctl', 'stop', 'docker.service']);
    core.info('✅ Docker service stopped');

    // Step 2: Disable the Docker service (prevents restart)
    core.info('Disabling Docker service...');
    await exec.exec('sudo', ['systemctl', 'disable', 'docker.socket']);
    await exec.exec('sudo', ['systemctl', 'disable', 'docker.service']);
    core.info('✅ Docker service disabled');

    core.info('🔒 Docker has been completely stopped and disabled');
    core.info('ℹ️  This prevents all Docker usage system-wide');
  } catch (error) {
    core.warning(`Could not stop Docker service: ${error}`);
  }
}

/**
 * Check if the runner user is a member of the docker group
 * @returns Promise<boolean> - true if runner is in docker group
 */
export async function isRunnerInDockerGroup(): Promise<boolean> {
  try {
    let output = '';
    await exec.exec('groups', [RUNNER_USERNAME], {
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        }
      }
    });
    return output.includes(DOCKER_GROUP);
  } catch (error) {
    core.warning(`Could not check docker group membership: ${error}`);
    return false;
  }
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
