/**
 * Sudo's pure config: the sudo-logging config for each sudo implementation, the restricted
 * sudoers file, and the list of the action's own sudo commands. No I/O.
 *
 * Sudoers text must be valid for BOTH implementations: no wildcards among command arguments
 * (sudo-rs accepts only a lone trailing `*`), no `Defaults!<alias>`, no `log_allowed`.
 */

import { BASELINE_WRITE_COMMANDS, CRITICAL_FILES, IPTABLES_CHAINS, iptablesListArgs } from '../../integrity/baseline';
import { DOCKER_DAEMON_JSON, VALIDATION_STATE_FILE } from '../../constants';

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
/** The runner's own sudoers file, replaced by the restricted one (disable-sudo) */
export const RUNNER_SUDOERS_FILE = `/etc/sudoers.d/${RUNNER_USERNAME}`;

export const SUDOERS_TEMP_FILE = `/tmp/${RUNNER_USERNAME}-sudoers.tmp`;
export const SUDO_LOGGING_TEMP_FILE = '/tmp/safer-runner-sudo-logging.tmp';

/**
 * Determine the sudo implementation from `sudo --version` output
 * sudo-rs prints "sudo-rs 0.2.13-0ubuntu1.2", classic sudo prints "Sudo version 1.9.15p5"
 */
export function parseSudoFlavour(versionOutput: string): SudoFlavour {
  return /^\s*sudo-rs\b/im.test(versionOutput) ? 'sudo-rs' : 'sudo';
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
 * classic sudo logfile format understood by report/logs/sudo-log.ts.
 */
export function buildSudoRsyslogConfig(logFile: string): string {
  return `template(name="SaferRunnerSudo" type="string" string="%timereported:::date-rfc3164% :%msg%\\n")
if $programname == 'sudo' and $msg contains 'COMMAND=' then {
  action(type="omfile" file="${logFile}" template="SaferRunnerSudo")
}
`;
}

/** Classic sudo: the `Defaults logfile=` drop-in */
export function buildSudoLoggingDropIn(logFile: string): string {
  return `Defaults logfile=${logFile}\nDefaults loglinelen=0\n`;
}

/**
 * Commands run by post-action integrity validation (see src/integrity/baseline.ts)
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
    ...IPTABLES_CHAINS.map(chain => `/usr/sbin/iptables ${iptablesListArgs(chain).join(' ')}`)
  ];
}

/**
 * Sudo commands run by the action itself while sudo logging is active
 * Filtered out of sudo reports - they are internal operations, not workflow activity.
 * Paths are matched by basename so /usr/sbin vs /usr/bin resolution doesn't matter.
 */
export const INTERNAL_SUDO_COMMANDS: string[] = [
  ...getValidationSudoCommands(),
  // restrictSudo()
  `tee ${SUDOERS_TEMP_FILE}`,
  `visudo -c -f ${SUDOERS_TEMP_FILE}`,
  `chmod 0440 ${SUDOERS_TEMP_FILE}`,
  `chown root:root ${SUDOERS_TEMP_FILE}`,
  `mv ${SUDOERS_TEMP_FILE} ${RUNNER_SUDOERS_FILE}`,
  `rm -f ${SUDOERS_TEMP_FILE}`,
  // setupSudoLogging() on sudo-rs
  'systemctl restart rsyslog',
  // captureBaseline() (integrity/baseline.ts)
  ...BASELINE_WRITE_COMMANDS.map(args => args.join(' '))
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

/** The restricted sudoers file that replaces RUNNER_SUDOERS_FILE (disable-sudo). */
export function buildRestrictedSudoers(): string {
  return `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation.
# All other sudo commands will be denied.
${getRequiredSudoCommands(RUNNER_USERNAME)}
`;
}

export interface SudoFacts {
  flavour: SudoFlavour;
  /** where sudo usage is logged (SUDO_LOG) */
  logFile: string;
}

/** What the sudo steps write. None of it is inert: each write is a named step in ./index.ts. */
export interface SudoRendered {
  flavour: SudoFlavour;
  logFile: string;
  /** the sudo-logging config: a sudoers drop-in (classic) or an rsyslog rule (sudo-rs) */
  logging: { path: string; content: string };
  /** the restricted sudoers file (disable-sudo) */
  sudoers: string;
}

export function render(f: SudoFacts): SudoRendered {
  return {
    flavour: f.flavour,
    logFile: f.logFile,
    logging: {
      path: getSudoLoggingConfigFile(f.flavour),
      content: f.flavour === 'sudo-rs' ? buildSudoRsyslogConfig(f.logFile) : buildSudoLoggingDropIn(f.logFile)
    },
    sudoers: buildRestrictedSudoers()
  };
}
