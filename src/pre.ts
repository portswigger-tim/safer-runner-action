import * as core from '@actions/core';
import { parseMode, readInputs } from './config/inputs';
import { runSetup, setupCompleted } from './setup/run';

/**
 * Pre step: apply the full policy (not just monitoring) before any other step - including
 * later actions' own pre-hooks - can run (review H2).
 */
async function run(): Promise<void> {
  let mode: string;
  try {
    // resolved first and on its own, so a bad value in any other input still fails closed in enforce
    mode = parseMode(core.getInput('mode'));
  } catch (error) {
    core.setFailed(`safer-runner setup failed: ${error}`);
    return;
  }
  try {
    await runSetup(readInputs());
  } catch (error) {
    if (mode === 'enforce') {
      // Fail closed: never let an enforce-mode job run without the controls.
      core.setFailed(`safer-runner setup failed in enforce mode: ${error}`);
    } else if (setupCompleted()) {
      // The setup marker is written before the sudo logging and integrity steps (they come last),
      // so main sees it and will not retry what failed after it. Analyze never changes sudo, so
      // nothing is left half-applied.
      core.warning(
        `safer-runner setup failed in analyze mode, after the setup marker: ${error}. The main step will not retry.`
      );
    } else {
      core.warning(`safer-runner setup failed in analyze mode: ${error}. The main step will retry.`);
    }
  }
}

run();
