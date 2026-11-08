import * as core from '@actions/core';
import { readInputs } from './config/inputs';
import { runSetup, setupCompleted } from './setup/run';

/**
 * Main step: normally a no-op because the pre step already applied everything. If pre did
 * not run (e.g. a local `uses: ./` action) or failed in analyze mode, set up here.
 */
async function run(): Promise<void> {
  try {
    if (setupCompleted()) {
      core.info('✅ safer-runner v2 already active (configured in the pre step)');
      return;
    }
    core.info('Pre step did not complete setup - configuring now');
    await runSetup(readInputs());
  } catch (error) {
    core.setFailed(`safer-runner setup failed: ${error}`);
  }
}

run();
