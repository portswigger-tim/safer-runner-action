/**
 * Docker access control module
 * Handles Docker group membership and container access restrictions
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

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
