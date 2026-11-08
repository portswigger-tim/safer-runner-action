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
  /** Set when the command was given environment variables (`sudo FOO=bar cmd`; values not kept) */
  env?: boolean;
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
  // classic sudo logs variables set on the command line as `ENV=A=1 B=2 ;` before COMMAND
  const match = line.match(
    /^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s*:\s*(\w+)\s*:.*USER=(\w+)\s*;\s*(ENV=[^;]*;\s*)?COMMAND=(.+)$/
  );

  if (!match) {
    return null;
  }

  const [, timestamp, user, targetUser, env, fullCommand] = match;

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
    ...(DENIED_PATTERN.test(line) && { denied: true }),
    ...(env && { env: true })
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

/** Every sudo log entry, in order (wrapped and multi-line entries joined first). */
export function parseSudoLogEntries(content: string): SudoCommand[] {
  const commands: SudoCommand[] = [];
  for (const line of joinContinuationLines(content)) {
    const cmd = parseSudoLogLine(line);
    if (cmd) {
      commands.push(cmd);
    }
  }
  return commands;
}

/** The sudo log's entries, deduplicated and limited to 1000. */
export function parseSudoLogsFromString(content: string): SudoCommand[] {
  return deduplicateSudoCommands(parseSudoLogEntries(content)).slice(0, 1000);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * A sudo log timestamp (`Nov  7 12:00:01`, no year, the runner's clock in UTC) as epoch seconds,
 * in the year that puts it at or before `now` (a log line is never from the future); null if it
 * does not parse.
 */
export function sudoLogSeconds(timestamp: string, now: Date): number | null {
  const m = timestamp.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$/);
  const month = m ? MONTHS.indexOf(m[1]) : -1;
  if (!m || month < 0) return null;
  const at = (year: number) => Date.UTC(year, month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])) / 1000;
  const year = now.getUTCFullYear();
  return at(year) > now.getTime() / 1000 + 86400 ? at(year - 1) : at(year);
}

/**
 * Where the action's own sudo is in the log, by entry position (the log is in order, and no step
 * runs while setup or the post step does): entries up to `setupEnd` (setup's last sudo command;
 * -1 when it was not found) and from `postStart` (the first entry the post step wrote).
 */
export interface ActionSudoBounds {
  setupEnd: number;
  postStart: number;
}

/**
 * Whether a (successful) command is one of the action's own. System binaries match by
 * basename ("cat /etc/resolv.conf"); anything else only by its exact absolute path, so a
 * same-named binary elsewhere (e.g. /home/runner/cat) is still reported.
 */
export function isInternal(cmd: SudoCommand, internal: Set<string>): boolean {
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

/**
 * Split parsed sudo log entries (in log order) by who ran them and whether they were allowed.
 * With `bounds`, a command is the action's own only if it matches one of its command lines AND
 * sits where the action ran sudo (setup, or the post step); the same line run by a job step is the
 * job's. Without them (an older setup), by the command line alone.
 */
export function classifySudoCommands(
  commands: SudoCommand[],
  internalCommands: string[],
  bounds?: ActionSudoBounds
): SudoUsage {
  const internal = new Set(internalCommands);
  const usage: SudoUsage = { ran: [], refused: [], internal: [] };
  const byAction = (i: number) => !bounds || i <= bounds.setupEnd || i >= bounds.postStart;
  commands.forEach((cmd, i) => {
    if (cmd.denied) usage.refused.push(cmd);
    else if (isInternal(cmd, internal) && byAction(i)) usage.internal.push(cmd);
    else usage.ran.push(cmd);
  });
  return usage;
}

/**
 * Setup's last sudo command in the log: the first allowed entry of `line` (setup runs before any
 * job step, so its own is the first), at most `slack` seconds after `notBefore` when both times
 * are known. -1 when it is not there (then nothing before the post step is the action's).
 */
export function setupEndIndex(
  commands: SudoCommand[],
  line: string,
  notBefore?: Date,
  slack = 300,
  now: Date = new Date()
): number {
  const set = new Set([line]);
  const latest = notBefore ? notBefore.getTime() / 1000 + slack : Infinity;
  return commands.findIndex(c => {
    if (c.denied || !isInternal(c, set)) return false;
    const at = sudoLogSeconds(c.timestamp, now);
    return at === null || at <= latest;
  });
}
