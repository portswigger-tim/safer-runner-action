import * as core from '@actions/core';
import { readInputs } from './inputs';
import { runSetup } from './egress';

/**
 * Pre step: apply the full policy (not just monitoring) before any other step - including
 * later actions' own pre-hooks - can run (review H2).
 */
async function run(): Promise<void> {
  let mode = 'analyze';
  try {
    const inputs = readInputs();
    mode = inputs.mode;
    await runSetup(inputs);
  } catch (error) {
    if (mode === 'enforce') {
      // Fail closed: never let an enforce-mode job run without the controls.
      core.setFailed(`safer-runner setup failed in enforce mode: ${error}`);
    } else {
      core.warning(`safer-runner setup failed in analyze mode: ${error}. The main step will retry.`);
    }
  }
}

run();
