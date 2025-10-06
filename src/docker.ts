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
 * Removes the runner user from the 'docker' group while preserving other group memberships.
 * The runner user will be unable to execute docker commands after this is applied.
 */
export async function disableDockerForRunner(): Promise<void> {
  core.info('Removing runner user from docker group...');

  try {
    // Remove runner from docker group
    await exec.exec('sudo', ['gpasswd', '-d', RUNNER_USERNAME, DOCKER_GROUP]);

    core.info(`✅ Removed ${RUNNER_USERNAME} from ${DOCKER_GROUP} group`);
    core.info('🔒 Docker commands will no longer be available to the runner user');
    core.info('ℹ️  This prevents container escape attacks and docker socket abuse');
  } catch (error) {
    // gpasswd returns non-zero if user isn't in the group - this is fine
    core.warning(`Could not remove ${RUNNER_USERNAME} from ${DOCKER_GROUP} group (may not be a member): ${error}`);
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
