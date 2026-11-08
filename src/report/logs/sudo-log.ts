/**
 * Parser for the sudo log (/var/log/safer-runner/sudo.log): classic sudo's logfile, or sudo-rs
 * syslog lines copied there by rsyslog in the same format (see sudo.ts)
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
 * Parse sudo logs from string content. Wrapped and multi-line entries are joined first, so every
 * entry is matched as one line.
 */
export function parseSudoLogsFromString(content: string): SudoCommand[] {
  const commands: SudoCommand[] = [];
  for (const line of joinContinuationLines(content)) {
    const cmd = parseSudoLogLine(line);
    if (cmd) {
      commands.push(cmd);
    }
  }

  // Deduplicate and limit to 1000 commands
  return deduplicateSudoCommands(commands).slice(0, 1000);
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
  /** commands the action ran itself (setup, validation) */
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
