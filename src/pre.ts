import * as core from '@actions/core';
import { parseMode, readInputs, type Inputs } from './config/inputs';
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
  let inputs: Inputs | undefined;
  try {
    inputs = readInputs();
    await runSetup(inputs);
  } catch (error) {
    if (mode === 'enforce') {
      // Fail closed: never let an enforce-mode job run without the controls.
      core.setFailed(`safer-runner setup failed in enforce mode: ${error}`);
    } else if (setupCompleted()) {
      // The setup marker is written before the sudo steps (they must come last, and the marker
      // needs sudo), so main sees it and will not retry what failed after it.
      if (inputs?.disableSudo) {
        core.setFailed(`safer-runner setup failed before sudo was removed (disable-sudo: true): ${error}`);
      } else {
        core.warning(`safer-runner setup failed in analyze mode, after the setup marker: ${error}`);
      }
    } else {
      core.warning(`safer-runner setup failed in analyze mode: ${error}. The main step will retry.`);
    }
  }
}

run();
