/**
 * Sudo logging and configuration module
 * Handles sudo logging setup, custom sudo configuration, and permission management
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import {
  parseSudoLogsFromString,
  generateSudoersConfig,
  filterInternalSudoCommands,
  type SudoCommand
} from './parsers/sudo-parser';
import { CRITICAL_FILES, IPTABLES_CHAINS } from './validation';

// Re-export SudoCommand type for convenience
export type { SudoCommand } from './parsers/sudo-parser';

// Constants
export const RUNNER_USERNAME = 'runner';

/**
 * Default sudoers configuration for GitHub Actions runner user
 * This is the standard unrestricted sudo access that exists by default
 */
export const DEFAULT_RUNNER_SUDO_CONFIG = `${RUNNER_USERNAME} ALL=(ALL) NOPASSWD: ALL`;

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
 * disableSudoForRunner/applyCustomSudoConfig).
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
 * Remove sudo logging configuration
 * Used to stop capturing sudo commands between pre-hook and main action
 */
export async function removeSudoLogging(): Promise<void> {
  core.info('Removing sudo logging configuration...');
  await exec.exec('sudo', ['rm', '-f', SUDO_LOGGING_SUDOERS_FILE]);

  if (fs.existsSync(SUDO_LOGGING_RSYSLOG_FILE)) {
    await exec.exec('sudo', ['rm', '-f', SUDO_LOGGING_RSYSLOG_FILE]);
    await exec.exec('sudo', ['systemctl', 'restart', 'rsyslog']);
  }
  core.info('✅ Sudo logging removed');
}

/**
 * Commands run by post-action integrity validation (see validation.ts)
 * These are the only sudo commands the runner keeps after sudo is restricted.
 */
export function getValidationSudoCommands(): string[] {
  const files = [...CRITICAL_FILES, SUDO_LOGGING_SUDOERS_FILE, SUDO_LOGGING_RSYSLOG_FILE];
  return [
    ...files.map(file => `/usr/bin/cat ${file}`),
    ...IPTABLES_CHAINS.map(chain => `/usr/sbin/iptables -L ${chain} -n --line-numbers`)
  ];
}

/**
 * Sudo commands run by the action itself while sudo logging is active
 * Filtered out of sudo reports - they are internal operations, not workflow activity.
 * Paths are matched by basename so /usr/sbin vs /usr/bin resolution doesn't matter.
 */
export const INTERNAL_SUDO_COMMANDS: string[] = [
  ...getValidationSudoCommands(),
  // applyCustomSudoConfig()
  `tee ${SUDOERS_TEMP_FILE}`,
  `visudo -c -f ${SUDOERS_TEMP_FILE}`,
  `chmod 0440 ${SUDOERS_TEMP_FILE}`,
  `chown root:root ${SUDOERS_TEMP_FILE}`,
  `mv ${SUDOERS_TEMP_FILE} /etc/sudoers.d/${RUNNER_USERNAME}`,
  `rm -f ${SUDOERS_TEMP_FILE}`,
  // removeSudoLogging() / setupSudoLogging()
  `rm -f ${SUDO_LOGGING_SUDOERS_FILE}`,
  `rm -f ${SUDO_LOGGING_RSYSLOG_FILE}`,
  'systemctl restart rsyslog'
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
 * Apply custom sudoers configuration for the runner user
 * This rewrites the /etc/sudoers.d/runner file with the specified configuration
 *
 * If no config is provided, defaults to the standard GitHub Actions runner config.
 * Always appends required commands for post-action validation.
 * The config is checked with the active visudo, so it must be valid for sudo-rs on Ubuntu 25.10+.
 *
 * @param sudoConfig - The custom sudoers configuration (defaults to unrestricted sudo)
 * @param flavour - Sudo implementation (detected if omitted), used for error guidance
 */
export async function applyCustomSudoConfig(
  sudoConfig: string = DEFAULT_RUNNER_SUDO_CONFIG,
  flavour?: SudoFlavour
): Promise<void> {
  const isDefaultConfig = sudoConfig === DEFAULT_RUNNER_SUDO_CONFIG;

  if (isDefaultConfig) {
    core.info(`Applying default sudo configuration for user: ${RUNNER_USERNAME}`);
  } else {
    core.info(`Applying custom sudo configuration for user: ${RUNNER_USERNAME}`);
  }

  const sudoersFile = `/etc/sudoers.d/${RUNNER_USERNAME}`;
  const tempFile = SUDOERS_TEMP_FILE;

  // Build complete config: user config + required validation commands
  const requiredCommands = getRequiredSudoCommands(RUNNER_USERNAME);
  const fullConfig = sudoConfig + '\n' + requiredCommands;

  // Write custom config + required commands to temp file
  await exec.exec('sudo', ['tee', tempFile], {
    input: Buffer.from(fullConfig + '\n')
  });

  // Validate with the active visudo (visudo-rs on sudo-rs systems)
  const visudo = await exec.getExecOutput('sudo', ['visudo', '-c', '-f', tempFile], { ignoreReturnCode: true });
  if (visudo.exitCode !== 0) {
    const sudoFlavour = flavour ?? (await detectSudoFlavour());
    await exec.exec('sudo', ['rm', '-f', tempFile], { ignoreReturnCode: true });
    core.error('Invalid sudoers syntax. Please check your sudo-config input.');
    if (sudoFlavour === 'sudo-rs') {
      core.error(
        'This runner uses sudo-rs (the default sudo on Ubuntu 25.10+ / 26.04), which supports a subset of sudoers: ' +
          'a wildcard may only be the whole argument list (`/usr/bin/apt-get *`), not embedded among other arguments ' +
          '(`/usr/bin/chmod * /tmp/x`), ' +
          'and many Defaults settings are not recognised.'
      );
    }
    throw new Error(`Invalid sudoers configuration: ${(visudo.stderr || visudo.stdout).trim()}`);
  }

  // Set permissions before moving into place
  await exec.exec('sudo', ['chmod', '0440', tempFile]);
  await exec.exec('sudo', ['chown', 'root:root', tempFile]);
  await exec.exec('sudo', ['mv', tempFile, sudoersFile]);

  if (isDefaultConfig) {
    core.info(`✅ Default sudo configuration rewritten to ${sudoersFile}`);
  } else {
    core.info(`✅ Custom sudo configuration applied to ${sudoersFile}`);
    core.info(`🔒 ${RUNNER_USERNAME} user now has restricted sudo access`);
  }
  core.info('ℹ️  Required validation commands automatically added');
}

/**
 * Disable sudo access for the runner user
 * This prevents malicious code from using sudo to bypass security controls
 *
 * Replaces the sudoers file with only the read-only commands needed for
 * post-action integrity validation (see getValidationSudoCommands()).
 */
export async function disableSudoForRunner(flavour?: SudoFlavour): Promise<void> {
  core.info('Restricting sudo access to validation commands only');

  // Rewrite with only a comment header - the required validation commands will be added
  const validationOnlyHeader = `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation.
# All other sudo commands will be denied.
`;

  await applyCustomSudoConfig(validationOnlyHeader, flavour);

  core.info(`🔒 ${RUNNER_USERNAME} user can only execute commands needed for integrity validation`);
}

/**
 * Parse sudo logs from a file
 *
 * @param logFile - Path to sudo log file
 * @returns Array of parsed sudo commands
 */
export function parseSudoLogs(logFile: string): SudoCommand[] {
  try {
    if (fs.existsSync(logFile)) {
      const logContent = fs.readFileSync(logFile, 'utf-8');
      return filterInternalSudoCommands(parseSudoLogsFromString(logContent), INTERNAL_SUDO_COMMANDS);
    }
    return [];
  } catch (error) {
    core.warning(`Could not parse sudo logs from ${logFile}: ${error}`);
    return [];
  }
}

/**
 * Generate a job summary section for sudo commands
 *
 * @param commands - Array of sudo commands to display
 * @param title - Section title (e.g., "Workflow Sudo Commands" or "Pre-Hook Sudo Commands")
 * @returns Markdown string for job summary
 */
export function generateSudoSummarySection(commands: SudoCommand[], title: string): string {
  if (commands.length === 0) {
    return '';
  }

  let report = `## ${title}\n\n`;
  report += `Workflow executed **${commands.length}** sudo command${commands.length === 1 ? '' : 's'}:\n\n`;
  report += `| Command | Arguments |\n`;
  report += `|---------|----------|\n`;

  for (const cmd of commands.slice(0, 50)) {
    report += `| \`${cmd.command}\` | \`${cmd.args || '(none)'}\` |\n`;
  }

  if (commands.length > 50) {
    report += `\n*Showing first 50 of ${commands.length} commands*\n`;
  }

  report += `\n`;
  return report;
}

/**
 * Generate sudoers configuration advice from captured sudo commands
 *
 * @param commands - Array of sudo commands to analyze
 * @returns Markdown string with sudoers configuration advice
 */
export function generateSudoConfigAdvice(commands: SudoCommand[]): string {
  if (commands.length === 0) {
    return '';
  }

  const sudoersConfig = generateSudoersConfig(commands, RUNNER_USERNAME);

  let advice = `### Sudo Configuration\n\n`;
  advice += `Based on observed sudo usage, you can restrict sudo access with this configuration:\n\n`;
  advice += `\`\`\`yaml\n`;
  advice += `- uses: portswigger-tim/safer-runner-action@v1\n`;
  advice += `  with:\n`;
  advice += `    sudo-config: |\n`;

  // Indent each line of the sudoers config
  const lines = sudoersConfig.split('\n');
  for (const line of lines) {
    if (line.trim()) {
      advice += `      ${line}\n`;
    }
  }

  advice += `\`\`\`\n\n`;
  advice += `This configuration:\n`;
  advice += `- ✅ Allows only the commands your workflow actually needs\n`;
  advice += `- ✅ Prevents malicious code from running arbitrary sudo commands\n`;
  advice += `- ✅ Automatically includes required validation commands\n\n`;

  return advice;
}
