/**
 * Sudo: logging the job's sudo use, and removing the runner user's sudo (disable-sudo). Pure
 * parts are in ./config.ts.
 *
 * Order (each step takes the previous one's token): setupSudoLogging() -> the integrity baseline
 * (integrity/baseline.ts) -> restrictSudo(), the last privileged step of setup.
 */

import * as core from '@actions/core';
import * as fs from 'fs';
import { parseSudoLogsFromString, classifySudoCommands, type SudoUsage } from './log';
import type { BaselineCaptured } from '../../integrity/baseline';
import { sudo, type Host } from '../../system/host';
import {
  INTERNAL_SUDO_COMMANDS,
  RUNNER_SUDOERS_FILE,
  RUNNER_USERNAME,
  SUDOERS_TEMP_FILE,
  SUDO_LOGGING_TEMP_FILE,
  parseSudoFlavour,
  type RestrictingSudo,
  type SudoFlavour,
  type SudoRendered
} from './config';

export * from './config';
// Re-export SudoCommand type for convenience
export type { SudoCommand, SudoUsage } from './log';

declare const sudoLogging: unique symbol;
/**
 * Sudo logging is on: every later sudo command lands in the sudo log. Minted only by
 * setupSudoLogging(); the integrity baseline takes it.
 */
export type SudoLogging = { readonly [sudoLogging]: true };

/**
 * Detect which sudo implementation is active on the runner
 */
export async function detectSudoFlavour(h: Host): Promise<SudoFlavour> {
  try {
    const { stdout } = await h.output('sudo', ['--version'], { silent: true, ignoreReturnCode: true });
    return parseSudoFlavour(stdout);
  } catch {
    return 'sudo';
  }
}

/**
 * Configure sudo logging to capture all sudo usage
 * Logs to specified file for visibility and auditability
 *
 * - Classic sudo: `Defaults logfile=<logFile>` sudoers drop-in
 * - sudo-rs: rsyslog rule filtering sudo's syslog messages into <logFile>
 *
 * Must run while the runner still has unrestricted sudo (i.e. before restrictSudo).
 */
export async function setupSudoLogging(h: Host, r: SudoRendered): Promise<SudoLogging> {
  core.info(`Configuring sudo logging to ${r.logFile} (${r.flavour})...`);

  // Create the log file and make it readable by the runner
  await sudo(['touch', r.logFile], {}, h);
  await sudo(['chmod', '0644', r.logFile], {}, h);

  if (r.flavour === 'sudo-rs') {
    // sudo-rs has no logfile setting - capture its syslog output with rsyslog instead
    await sudo(['chown', 'syslog:adm', r.logFile], {}, h);
    await sudo(['tee', r.logging.path], { input: Buffer.from(r.logging.content), silent: true }, h);
    await sudo(['systemctl', 'restart', 'rsyslog'], {}, h);
  } else {
    // Stage the drop-in and move it into place last, so logging starts with no
    // further setup commands to capture (sudoers files must be 0440 root:root)
    await sudo(['tee', SUDO_LOGGING_TEMP_FILE], { input: Buffer.from(r.logging.content), silent: true }, h);
    await sudo(['chmod', '0440', SUDO_LOGGING_TEMP_FILE], {}, h);
    await sudo(['chown', 'root:root', SUDO_LOGGING_TEMP_FILE], {}, h);
    await sudo(['mv', SUDO_LOGGING_TEMP_FILE, r.logging.path], {}, h);
  }

  core.info(`✅ Sudo logging configured to ${r.logFile}`);
  return Object.freeze({}) as SudoLogging;
}

/**
 * Disable sudo access for the runner user (disable-sudo). The last privileged step of setup:
 * it takes the baseline's token, which takes sudo logging's.
 *
 * Replaces the sudoers file with only the read-only commands needed for post-action integrity
 * validation (see getValidationSudoCommands()). The file is checked with the active visudo
 * (visudo-rs on sudo-rs systems) before it is moved into place; a rejected file fails setup.
 */
export async function restrictSudo(h: Host, r: RestrictingSudo, _baseline: BaselineCaptured): Promise<void> {
  core.info('Restricting sudo access to validation commands only');

  await sudo(['tee', SUDOERS_TEMP_FILE], { input: Buffer.from(r.restrict.sudoers) }, h);

  // the exit code is checked here, not ignored: a rejected file is never installed
  const visudo = await h.output('sudo', ['visudo', '-c', '-f', SUDOERS_TEMP_FILE], { ignoreReturnCode: true });
  if (visudo.exitCode !== 0) {
    await sudo(['rm', '-f', SUDOERS_TEMP_FILE], { ignoreReturnCode: true }, h);
    throw new Error(`Generated sudoers rejected by visudo (${r.flavour}): ${(visudo.stderr || visudo.stdout).trim()}`);
  }

  // Set permissions before moving into place
  await sudo(['chmod', '0440', SUDOERS_TEMP_FILE], {}, h);
  await sudo(['chown', 'root:root', SUDOERS_TEMP_FILE], {}, h);
  await sudo(['mv', SUDOERS_TEMP_FILE, RUNNER_SUDOERS_FILE], {}, h);

  core.info(`🔒 ${RUNNER_USERNAME} user can only execute commands needed for integrity validation`);
}

/**
 * Read the sudo log and split it into the workflow's own commands, refused attempts and the
 * action's own commands (so the report never counts the action's sudo as the workflow's).
 */
export function readSudoUsage(logFile: string): SudoUsage {
  try {
    if (fs.existsSync(logFile)) {
      return classifySudoCommands(parseSudoLogsFromString(fs.readFileSync(logFile, 'utf-8')), INTERNAL_SUDO_COMMANDS);
    }
  } catch (error) {
    core.warning(`Could not parse sudo logs from ${logFile}: ${error}`);
  }
  return { ran: [], refused: [], internal: [] };
}
