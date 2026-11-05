/**
 * Parser for sudo log files
 * Extracts command execution patterns from /tmp/runner-sudo.log
 */

export interface SudoCommand {
  timestamp: string;
  user: string;
  targetUser: string;
  command: string;
  args: string;
  /** Set when sudo refused the command (classic sudo logs refusals; sudo-rs does not) */
  denied?: boolean;
}

/**
 * Classic sudo prefixes refused commands with a reason, e.g.
 * "runner : command not allowed ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id"
 */
const DENIED_PATTERN = /command not allowed|password is required|incorrect password|NOT in sudoers/i;

/**
 * Parse a single sudo log entry
 * Format: "Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf"
 */
export function parseSudoLogLine(line: string): SudoCommand | null {
  // Match sudo log format with timestamp
  const match = line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s*:\s*(\w+)\s*:.*USER=(\w+)\s*;\s*COMMAND=(.+)$/);

  if (!match) {
    return null;
  }

  const [, timestamp, user, targetUser, fullCommand] = match;

  // Split command and args
  const commandParts = fullCommand.trim().split(/\s+/);
  const command = commandParts[0];
  const args = commandParts.slice(1).join(' ');

  return {
    timestamp,
    user,
    targetUser,
    command,
    args,
    ...(DENIED_PATTERN.test(line) && { denied: true })
  };
}

/**
 * Deduplicate sudo commands by command+args combination
 */
export function deduplicateSudoCommands(commands: SudoCommand[]): SudoCommand[] {
  const seen = new Set<string>();
  const deduplicated: SudoCommand[] = [];

  for (const cmd of commands) {
    const key = `${cmd.command} ${cmd.args}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(cmd);
    }
  }

  return deduplicated;
}

/**
 * Join wrapped log entries back into single lines
 * Classic sudo wraps logfile entries (loglinelen, default 80) with indented
 * continuation lines, which can split a command from its arguments:
 *   Nov  3 16:24:32 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/cat
 *       /etc/resolv.conf
 */
function joinContinuationLines(content: string): string[] {
  const joined: string[] = [];

  for (const line of content.split('\n')) {
    if (/^\s+\S/.test(line) && joined.length > 0) {
      joined[joined.length - 1] = `${joined[joined.length - 1].trimEnd()} ${line.trim()}`;
    } else {
      joined.push(line);
    }
  }

  return joined;
}

/**
 * Parse sudo logs from string content
 * Handles both single-line and multi-line log formats
 */
export function parseSudoLogsFromString(content: string): SudoCommand[] {
  const lines = joinContinuationLines(content);
  const commands: SudoCommand[] = [];

  // First try single-line format (older sudo versions)
  for (const line of lines) {
    const cmd = parseSudoLogLine(line);
    if (cmd) {
      commands.push(cmd);
    }
  }

  // If no commands found, try multi-line format (newer sudo versions)
  if (commands.length === 0) {
    const multiLineCommands = parseMultiLineSudoLogs(content);
    commands.push(...multiLineCommands);
  }

  // Deduplicate and limit to 1000 commands
  const deduplicated = deduplicateSudoCommands(commands);
  return deduplicated.slice(0, 1000);
}

/**
 * Parse multi-line sudo log format (newer sudo versions)
 * Format:
 *   Oct  3 14:36:19 : runner :
 *       *** ; USER=root ;
 *       COMMAND=/usr/bin/docker --version
 */
function parseMultiLineSudoLogs(content: string): SudoCommand[] {
  const commands: SudoCommand[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Look for timestamp line
    const timestampMatch = line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s*:\s*(\w+)\s*:/);
    if (!timestampMatch) continue;

    const [, timestamp, user] = timestampMatch;

    // Look for USER= line (should be next line or within next few lines)
    let targetUser = '';
    let fullCommand = '';

    for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
      const nextLine = lines[j].trim();

      // Extract USER
      const userMatch = nextLine.match(/USER=(\w+)/);
      if (userMatch) {
        targetUser = userMatch[1];
      }

      // Extract COMMAND
      const commandMatch = nextLine.match(/COMMAND=(.+)$/);
      if (commandMatch) {
        fullCommand = commandMatch[1].trim();
        break;
      }
    }

    if (targetUser && fullCommand) {
      // Split command and args
      const commandParts = fullCommand.split(/\s+/);
      const command = commandParts[0];
      const args = commandParts.slice(1).join(' ');

      commands.push({
        timestamp,
        user,
        targetUser,
        command,
        args
      });
    }
  }

  return commands;
}

/**
 * Remove the action's own (successful) sudo commands from parsed logs
 *
 * @param commands - Parsed sudo commands
 * @param internalCommands - Internal commands as "<basename> <args>" (e.g. "cat /etc/resolv.conf")
 * @returns Commands that were not run by the action itself
 */
export function filterInternalSudoCommands(commands: SudoCommand[], internalCommands: string[]): SudoCommand[] {
  const internal = new Set(internalCommands);

  return commands.filter(cmd => {
    // Refused attempts are always reported, even if they mimic an internal command
    if (cmd.denied) {
      return true;
    }
    return !isInternal(cmd, internal);
  });
}

/**
 * Whether a (successful) command is one of the action's own. System binaries match by
 * basename ("cat /etc/resolv.conf"); anything else only by its exact absolute path, so a
 * same-named binary elsewhere (e.g. /home/runner/cat) is still reported.
 */
function isInternal(cmd: SudoCommand, internal: Set<string>): boolean {
  const withArgs = (c: string) => (cmd.args ? `${c} ${cmd.args}` : c);
  const match = cmd.command.match(/^\/(?:usr\/)?s?bin\/([^/]+)$/);
  if (match) {
    return internal.has(withArgs(match[1]));
  }
  return cmd.command.startsWith('/') && internal.has(withArgs(cmd.command));
}

export interface SudoUsage {
  /** commands the workflow ran with sudo */
  ran: SudoCommand[];
  /** commands sudo refused (classic sudo only - sudo-rs does not log refusals) */
  refused: SudoCommand[];
  /** commands the action ran itself (setup, validation, teardown) */
  internal: SudoCommand[];
}

/** Split parsed sudo log entries by who ran them and whether they were allowed. */
export function classifySudoCommands(commands: SudoCommand[], internalCommands: string[]): SudoUsage {
  const internal = new Set(internalCommands);
  const usage: SudoUsage = { ran: [], refused: [], internal: [] };
  for (const cmd of commands) {
    if (cmd.denied) usage.refused.push(cmd);
    else if (isInternal(cmd, internal)) usage.internal.push(cmd);
    else usage.ran.push(cmd);
  }
  return usage;
}

/**
 * Convert sudo commands to sudoers config format
 * Groups commands by executable and generates appropriate rules
 *
 * Note: No filtering needed - commands are captured after setup is complete
 */
/**
 * Binaries that can typically be escalated to full root even when "restricted" via
 * sudoers - because they run arbitrary code (shells, interpreters, package/service
 * managers), write arbitrary files as root (tee/dd/cp/chmod/...), or offer a shell
 * escape (editors/pagers). Matched by basename so the path doesn't matter.
 *
 * When one of these appears in observed usage we emit the suggested rule COMMENTED OUT
 * with a warning, rather than presenting it as a safe restriction.
 */
const DANGEROUS_SUDO_BASENAMES: ReadonlySet<string> = new Set([
  // shells / interpreters - arbitrary code execution
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'csh',
  'tcsh',
  'perl',
  'python',
  'python2',
  'python3',
  'ruby',
  'php',
  'node',
  'nodejs',
  'lua',
  'awk',
  'gawk',
  'tclsh',
  'expect',
  // arbitrary file write / ownership - trivial root via writing to system files
  'tee',
  'dd',
  'cp',
  'mv',
  'chmod',
  'chown',
  'chgrp',
  'install',
  'truncate',
  'ln',
  'rsync',
  'cpio',
  // exec wrappers that can run any command
  'env',
  'nohup',
  'setsid',
  'xargs',
  'find',
  'nice',
  'ionice',
  'timeout',
  'stdbuf',
  'unshare',
  'chroot',
  'nsenter',
  // editors / pagers - shell escape
  'vi',
  'vim',
  'nvim',
  'nano',
  'emacs',
  'less',
  'more',
  'man',
  'ed',
  'pico',
  'view',
  // package / build / service managers - run arbitrary code as root (hooks, scripts, units)
  'apt',
  'apt-get',
  'aptitude',
  'dpkg',
  'snap',
  'pip',
  'pip2',
  'pip3',
  'gem',
  'npm',
  'npx',
  'yarn',
  'make',
  'gcc',
  'cc',
  'systemctl',
  'service',
  'journalctl',
  'docker',
  'podman',
  'ctr',
  'nerdctl',
  // privilege / account management
  'su',
  'sudo',
  'visudo',
  'useradd',
  'usermod',
  'adduser',
  'passwd',
  'crontab',
  'at',
  'chpasswd'
]);

/**
 * Whether a sudo command path is escalation-prone (see DANGEROUS_SUDO_BASENAMES).
 */
export function isDangerousSudoCommand(command: string): boolean {
  const base = command.split('/').pop() || command;
  return DANGEROUS_SUDO_BASENAMES.has(base);
}

/**
 * Generate suggested sudoers rules from observed sudo usage.
 *
 * This is ADVISORY output (a starting point for the `sudo-config` input), not a
 * guarantee of safety. Design choices that make it least-privilege:
 * - run-as the exact target user observed (usually root), not `(ALL)`;
 * - pin the EXACT arguments observed. A bare command with no argument spec would
 *   allow ANY arguments in sudoers, so a no-argument invocation is emitted as
 *   `cmd ""` (require no args), never a bare `cmd`;
 * - escalation-prone binaries (shells, interpreters, file-writers, package/service
 *   managers, ...) are emitted COMMENTED OUT with a warning, because allowing them
 *   usually defeats the restriction.
 */
export function generateSudoersConfig(commands: SudoCommand[], username: string = 'runner'): string {
  if (commands.length === 0) {
    return '';
  }

  // De-duplicate on the exact (runAs, command, args) invocation
  const seen = new Set<string>();
  const lines: string[] = [];

  for (const cmd of commands) {
    const runAs = cmd.targetUser || 'root';
    const key = `${runAs}\u0000${cmd.command}\u0000${cmd.args}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    // Pin exact args; `""` means "no arguments allowed" (a bare command allows any args).
    const argSpec = cmd.args ? cmd.args : '""';
    const rule = `${username} ALL=(${runAs}) NOPASSWD: ${cmd.command} ${argSpec}`;

    if (isDangerousSudoCommand(cmd.command)) {
      lines.push(`# WARNING: '${cmd.command}' can usually be escalated to full root (shell escape,`);
      lines.push(`#   arbitrary file write, or running code as root). Uncomment only if you are sure`);
      lines.push(`#   this exact invocation is safe - otherwise allowing it defeats the restriction.`);
      lines.push(`# ${rule}`);
    } else {
      lines.push(rule);
    }
  }

  return lines.join('\n');
}
