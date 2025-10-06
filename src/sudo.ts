/**
 * Sudo logging and configuration module
 * Handles sudo logging setup, custom sudo configuration, and permission management
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { parseSudoLogsFromString, generateSudoersConfig, type SudoCommand } from './parsers/sudo-parser';

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
 * Configure sudo logging to capture all sudo usage
 * Logs to specified file for visibility and auditability
 *
 * @param logFile - Path to sudo log file (e.g., /tmp/pre-sudo.log or /tmp/main-sudo.log)
 */
export async function setupSudoLogging(logFile: string): Promise<void> {
  core.info(`Configuring sudo logging to ${logFile}...`);

  // Create a sudoers.d file to enable logging
  const logConfig = `Defaults logfile=${logFile}\n`;

  await exec.exec('sudo', ['tee', '/etc/sudoers.d/00-sudo-logging'], {
    input: Buffer.from(logConfig)
  });

  // Set appropriate permissions (must be 0440 or 0400 for sudoers files)
  await exec.exec('sudo', ['chmod', '0440', '/etc/sudoers.d/00-sudo-logging']);
  await exec.exec('sudo', ['chown', 'root:root', '/etc/sudoers.d/00-sudo-logging']);

  // Create the log file and make it readable by the runner
  await exec.exec('sudo', ['touch', logFile]);
  await exec.exec('sudo', ['chmod', '0644', logFile]);

  core.info(`✅ Sudo logging configured to ${logFile}`);
}

/**
 * Remove sudo logging configuration
 * Used to stop capturing sudo commands between pre-hook and main action
 */
export async function removeSudoLogging(): Promise<void> {
  core.info('Removing sudo logging configuration...');
  await exec.exec('sudo', ['rm', '-f', '/etc/sudoers.d/00-sudo-logging']);
  core.info('✅ Sudo logging removed');
}

/**
 * Generate required sudo commands for validation and log parsing
 * These commands are needed by the post-action to:
 * - Read protected configuration files for integrity validation
 * - Query iptables rules for firewall validation
 * - Parse DNS and network logs for reporting
 *
 * Also includes commands used by applyCustomSudoConfig() to avoid logging
 * internal sudo configuration operations.
 *
 * Uses Cmnd_Alias and Defaults!<alias> !log_allowed to exclude these commands
 * from sudo logging (they're internal operations, not user workflow commands).
 *
 * @param username - The username to generate rules for
 * @returns Sudoers configuration string with required commands
 */
function getRequiredSudoCommands(username: string): string {
  return `
# Required commands for post-action validation and reporting
# These are automatically added by safer-runner-action

# Define command alias for validation commands
Cmnd_Alias SAFER_RUNNER_VALIDATION = /usr/bin/cat /etc/dnsmasq.conf, \\
                                      /usr/bin/cat /etc/resolv.conf, \\
                                      /usr/bin/cat /etc/systemd/resolved.conf.d/no-stub.conf, \\
                                      /usr/sbin/iptables -L * -n --line-numbers

# Define command alias for sudo configuration commands (used by applyCustomSudoConfig, setupSudoLogging, and removeSudoLogging)
Cmnd_Alias SAFER_RUNNER_CONFIG = /usr/bin/tee /tmp/${username}-sudoers.tmp, \\
                                 /usr/bin/tee /etc/sudoers.d/00-sudo-logging, \\
                                 /usr/bin/visudo -c -f /tmp/${username}-sudoers.tmp, \\
                                 /usr/bin/chmod * /tmp/${username}-sudoers.tmp, \\
                                 /usr/bin/chmod * /etc/sudoers.d/00-sudo-logging, \\
                                 /usr/bin/chmod * /var/log/safer-runner/*.log, \\
                                 /usr/bin/chown * /tmp/${username}-sudoers.tmp, \\
                                 /usr/bin/chown * /etc/sudoers.d/00-sudo-logging, \\
                                 /usr/bin/touch /var/log/safer-runner/*.log, \\
                                 /usr/bin/mv /tmp/${username}-sudoers.tmp /etc/sudoers.d/${username}, \\
                                 /usr/bin/rm -f /tmp/${username}-sudoers.tmp, \\
                                 /usr/bin/rm -f /etc/sudoers.d/00-sudo-logging

# Exclude validation and config commands from sudo logging
Defaults!SAFER_RUNNER_VALIDATION !log_allowed
Defaults!SAFER_RUNNER_CONFIG !log_allowed

# Allow validation and config commands without password
${username} ALL=(ALL) NOPASSWD: SAFER_RUNNER_VALIDATION, SAFER_RUNNER_CONFIG
`;
}

/**
 * Apply custom sudoers configuration for the runner user
 * This rewrites the /etc/sudoers.d/runner file with the specified configuration
 *
 * If no config is provided, defaults to the standard GitHub Actions runner config.
 * Always appends required commands for post-action validation and log parsing.
 *
 * @param sudoConfig - The custom sudoers configuration (defaults to unrestricted sudo)
 */
export async function applyCustomSudoConfig(sudoConfig: string = DEFAULT_RUNNER_SUDO_CONFIG): Promise<void> {
  const isDefaultConfig = sudoConfig === DEFAULT_RUNNER_SUDO_CONFIG;

  if (isDefaultConfig) {
    core.info(`Applying default sudo configuration for user: ${RUNNER_USERNAME}`);
  } else {
    core.info(`Applying custom sudo configuration for user: ${RUNNER_USERNAME}`);
  }

  // Validate the sudo config using visudo
  const sudoersFile = `/etc/sudoers.d/${RUNNER_USERNAME}`;
  const tempFile = `/tmp/${RUNNER_USERNAME}-sudoers.tmp`;

  // Build complete config: user config + required validation commands
  const requiredCommands = getRequiredSudoCommands(RUNNER_USERNAME);
  const fullConfig = sudoConfig + '\n' + requiredCommands;

  try {
    // Write custom config + required commands to temp file
    await exec.exec('sudo', ['tee', tempFile], {
      input: Buffer.from(fullConfig + '\n')
    });

    // Validate with visudo
    await exec.exec('sudo', ['visudo', '-c', '-f', tempFile]);

    // If validation passes, set permissions before moving
    await exec.exec('sudo', ['chmod', '0440', tempFile]);
    await exec.exec('sudo', ['chown', 'root:root', tempFile]);
    await exec.exec('sudo', ['mv', tempFile, sudoersFile]);

    if (isDefaultConfig) {
      core.info(`✅ Default sudo configuration rewritten to ${sudoersFile}`);
      core.info('ℹ️  Required validation and log parsing commands automatically added');
    } else {
      core.info(`✅ Custom sudo configuration applied to ${sudoersFile}`);
      core.info(`🔒 ${RUNNER_USERNAME} user now has restricted sudo access`);
      core.info('ℹ️  Required validation and log parsing commands automatically added');
    }
  } catch (error) {
    core.error(`Failed to apply custom sudo config: ${error}`);
    core.error('Invalid sudoers syntax. Please check your sudo-config input.');
    // Clean up temp file
    await exec.exec('sudo', ['rm', '-f', tempFile], { ignoreReturnCode: true });
    throw new Error('Invalid sudoers configuration');
  }
}

/**
 * Disable sudo access for the runner user
 * This prevents malicious code from using sudo to bypass security controls
 *
 * Replaces the sudoers file with only the commands needed for post-action operations:
 * - sudo cat <file> - to read protected configuration files for integrity checks
 * - sudo iptables -L <chain> -n --line-numbers - to verify firewall rules
 * - sudo grep -E <pattern> <file> - to parse DNS and network logs for reporting
 */
export async function disableSudoForRunner(): Promise<void> {
  core.info('Restricting sudo access to validation commands only');

  // Rewrite with only a comment header - the required validation commands will be added
  const validationOnlyHeader = `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation
# and log parsing. All other sudo commands will be denied.
`;

  await applyCustomSudoConfig(validationOnlyHeader);

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
      return parseSudoLogsFromString(logContent);
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
