/**
 * Sudo logging and configuration module
 * Handles sudo logging setup and removing the runner user's sudo (disable-sudo)
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { parseSudoLogsFromString, classifySudoCommands, type SudoUsage } from './parsers/sudo-parser';
import { BASELINE_WRITE_COMMANDS, CRITICAL_FILES, IPTABLES_CHAINS, iptablesListArgs } from './validation';
import { DOCKER_DAEMON_JSON, TEARDOWN_BIN, VALIDATION_STATE_FILE } from './constants';

// Re-export SudoCommand type for convenience
export type { SudoCommand, SudoUsage } from './parsers/sudo-parser';

// Constants
export const RUNNER_USERNAME = 'runner';

/**
 * Sudo implementation in use on the runner
 * - 'sudo'    : classic sudo (sudo.ws) - Ubuntu 24.04 and earlier
 * - 'sudo-rs' : Rust sudo - default `sudo` on Ubuntu 25.10+ (including 26.04)
 *
 * sudo-rs only supports a subset of sudoers: no wildcards embedded among command
 * arguments (a lone trailing `*` is fine), no `Defaults logfile=` and no `log_allowed`. It always logs to syslog (auth facility).
 */
export type SudoFlavour = 'sudo' | 'sudo-rs';

/** Classic sudo: sudoers drop-in enabling `Defaults logfile=` */
export const SUDO_LOGGING_SUDOERS_FILE = '/etc/sudoers.d/00-sudo-logging';
/** sudo-rs: rsyslog rule copying sudo's syslog messages into the safer-runner log file */
export const SUDO_LOGGING_RSYSLOG_FILE = '/etc/rsyslog.d/10-sudo-safer-runner.conf';

const SUDOERS_TEMP_FILE = `/tmp/${RUNNER_USERNAME}-sudoers.tmp`;
const SUDO_LOGGING_TEMP_FILE = '/tmp/safer-runner-sudo-logging.tmp';

/**
 * Determine the sudo implementation from `sudo --version` output
 * sudo-rs prints "sudo-rs 0.2.13-0ubuntu1.2", classic sudo prints "Sudo version 1.9.15p5"
 */
export function parseSudoFlavour(versionOutput: string): SudoFlavour {
  return /^\s*sudo-rs\b/im.test(versionOutput) ? 'sudo-rs' : 'sudo';
}

/**
 * Detect which sudo implementation is active on the runner
 */
export async function detectSudoFlavour(): Promise<SudoFlavour> {
  try {
    const { stdout } = await exec.getExecOutput('sudo', ['--version'], { silent: true, ignoreReturnCode: true });
    return parseSudoFlavour(stdout);
  } catch {
    return 'sudo';
  }
}

/**
 * Path of the config file that enables sudo logging for the given sudo implementation
 * This file is added to the integrity validation baseline
 */
export function getSudoLoggingConfigFile(flavour: SudoFlavour): string {
  return flavour === 'sudo-rs' ? SUDO_LOGGING_RSYSLOG_FILE : SUDO_LOGGING_SUDOERS_FILE;
}

/**
 * Build the rsyslog rule used on sudo-rs to capture sudo usage into a dedicated log file
 *
 * sudo-rs logs "runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/id" to syslog.
 * The template prefixes it with an RFC3164 timestamp so the file matches the
 * classic sudo logfile format understood by parsers/sudo-parser.ts.
 */
export function buildSudoRsyslogConfig(logFile: string): string {
  return `template(name="SaferRunnerSudo" type="string" string="%timereported:::date-rfc3164% :%msg%\\n")
if $programname == 'sudo' and $msg contains 'COMMAND=' then {
  action(type="omfile" file="${logFile}" template="SaferRunnerSudo")
}
`;
}

/**
 * Configure sudo logging to capture all sudo usage
 * Logs to specified file for visibility and auditability
 *
 * - Classic sudo: `Defaults logfile=<logFile>` sudoers drop-in
 * - sudo-rs: rsyslog rule filtering sudo's syslog messages into <logFile>
 *
 * Must run while the runner still has unrestricted sudo (i.e. before
 * disableSudoForRunner).
 *
 * @param logFile - Path to sudo log file (e.g., /var/log/safer-runner/main-sudo.log)
 * @param flavour - Sudo implementation (detected if omitted)
 */
export async function setupSudoLogging(logFile: string, flavour?: SudoFlavour): Promise<void> {
  const sudoFlavour = flavour ?? (await detectSudoFlavour());
  core.info(`Configuring sudo logging to ${logFile} (${sudoFlavour})...`);

  // Create the log file and make it readable by the runner
  await exec.exec('sudo', ['touch', logFile]);
  await exec.exec('sudo', ['chmod', '0644', logFile]);

  if (sudoFlavour === 'sudo-rs') {
    // sudo-rs has no logfile setting - capture its syslog output with rsyslog instead
    await exec.exec('sudo', ['chown', 'syslog:adm', logFile]);
    await exec.exec('sudo', ['tee', SUDO_LOGGING_RSYSLOG_FILE], {
      input: Buffer.from(buildSudoRsyslogConfig(logFile)),
      silent: true
    });
    await exec.exec('sudo', ['systemctl', 'restart', 'rsyslog']);
  } else {
    // Stage the drop-in and move it into place last, so logging starts with no
    // further setup commands to capture (sudoers files must be 0440 root:root)
    await exec.exec('sudo', ['tee', SUDO_LOGGING_TEMP_FILE], {
      input: Buffer.from(`Defaults logfile=${logFile}\nDefaults loglinelen=0\n`),
      silent: true
    });
    await exec.exec('sudo', ['chmod', '0440', SUDO_LOGGING_TEMP_FILE]);
    await exec.exec('sudo', ['chown', 'root:root', SUDO_LOGGING_TEMP_FILE]);
    await exec.exec('sudo', ['mv', SUDO_LOGGING_TEMP_FILE, SUDO_LOGGING_SUDOERS_FILE]);
  }

  core.info(`✅ Sudo logging configured to ${logFile}`);
}

/**
 * Commands run by post-action integrity validation (see validation.ts)
 * These are the only sudo commands the runner keeps after sudo is restricted.
 */
export function getValidationSudoCommands(): string[] {
  const files = [
    ...CRITICAL_FILES,
    DOCKER_DAEMON_JSON,
    SUDO_LOGGING_SUDOERS_FILE,
    SUDO_LOGGING_RSYSLOG_FILE,
    VALIDATION_STATE_FILE
  ];
  return [
    ...files.map(file => `/usr/bin/cat ${file}`),
    ...IPTABLES_CHAINS.map(chain => `/usr/sbin/iptables ${iptablesListArgs(chain).join(' ')}`),
    // post-step teardown (destroys the CA key). `""` = no arguments allowed.
    `${TEARDOWN_BIN} ""`
  ];
}

/**
 * Sudo commands run by the action itself while sudo logging is active
 * Filtered out of sudo reports - they are internal operations, not workflow activity.
 * Paths are matched by basename so /usr/sbin vs /usr/bin resolution doesn't matter.
 */
export const INTERNAL_SUDO_COMMANDS: string[] = [
  ...getValidationSudoCommands(),
  // disableSudoForRunner()
  `tee ${SUDOERS_TEMP_FILE}`,
  `visudo -c -f ${SUDOERS_TEMP_FILE}`,
  `chmod 0440 ${SUDOERS_TEMP_FILE}`,
  `chown root:root ${SUDOERS_TEMP_FILE}`,
  `mv ${SUDOERS_TEMP_FILE} /etc/sudoers.d/${RUNNER_USERNAME}`,
  `rm -f ${SUDOERS_TEMP_FILE}`,
  // setupSudoLogging() on sudo-rs
  'systemctl restart rsyslog',
  // SystemValidator.writeBaseline()
  ...BASELINE_WRITE_COMMANDS.map(args => args.join(' ')),
  TEARDOWN_BIN
].map(cmd => cmd.replace(/^\/usr\/s?bin\//, ''));

/**
 * Generate the sudoers rules the action always needs for post-action validation
 *
 * Only exact read-only commands are allowed: no wildcards (embedded wildcards are
 * unsupported by sudo-rs, and any wildcard matches arbitrary extra arguments), and nothing that can
 * write files or modify sudo/syslog configuration.
 *
 * @param username - The username to generate rules for
 * @returns Sudoers configuration string with required commands
 */
export function getRequiredSudoCommands(username: string = RUNNER_USERNAME): string {
  const commands = getValidationSudoCommands();
  return `
# Required commands for post-action validation
# These are automatically added by safer-runner-action
Cmnd_Alias SAFER_RUNNER_VALIDATION = ${commands.join(', \\\n    ')}

${username} ALL=(ALL) NOPASSWD: SAFER_RUNNER_VALIDATION
`;
}

/**
 * Disable sudo access for the runner user
 * This prevents malicious code from using sudo to bypass security controls
 *
 * Replaces the sudoers file with only the read-only commands needed for
 * post-action integrity validation (see getValidationSudoCommands()). The file is checked
 * with the active visudo (visudo-rs on sudo-rs systems) before it is moved into place.
 */
export async function disableSudoForRunner(flavour?: SudoFlavour): Promise<void> {
  core.info('Restricting sudo access to validation commands only');

  const sudoersFile = `/etc/sudoers.d/${RUNNER_USERNAME}`;
  const tempFile = SUDOERS_TEMP_FILE;
  const config = `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation.
# All other sudo commands will be denied.
${getRequiredSudoCommands(RUNNER_USERNAME)}`;

  await exec.exec('sudo', ['tee', tempFile], { input: Buffer.from(config + '\n') });

  const visudo = await exec.getExecOutput('sudo', ['visudo', '-c', '-f', tempFile], { ignoreReturnCode: true });
  if (visudo.exitCode !== 0) {
    await exec.exec('sudo', ['rm', '-f', tempFile], { ignoreReturnCode: true });
    const sudoFlavour = flavour ?? (await detectSudoFlavour());
    throw new Error(
      `Generated sudoers rejected by visudo (${sudoFlavour}): ${(visudo.stderr || visudo.stdout).trim()}`
    );
  }

  // Set permissions before moving into place
  await exec.exec('sudo', ['chmod', '0440', tempFile]);
  await exec.exec('sudo', ['chown', 'root:root', tempFile]);
  await exec.exec('sudo', ['mv', tempFile, sudoersFile]);

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
