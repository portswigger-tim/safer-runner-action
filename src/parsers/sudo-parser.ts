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
}

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
    args
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
 * Parse sudo logs from string content
 */
export function parseSudoLogsFromString(content: string): SudoCommand[] {
  const lines = content.split('\n');
  const commands: SudoCommand[] = [];

  for (const line of lines) {
    const cmd = parseSudoLogLine(line);
    if (cmd) {
      commands.push(cmd);
    }
  }

  // Deduplicate and limit to 1000 commands
  const deduplicated = deduplicateSudoCommands(commands);
  return deduplicated.slice(0, 1000);
}

/**
 * Convert sudo commands to sudoers config format
 * Groups commands by executable and generates appropriate rules
 *
 * Note: No filtering needed - commands are captured after setup is complete
 */
export function generateSudoersConfig(commands: SudoCommand[], username: string = 'runner'): string {
  if (commands.length === 0) {
    return '';
  }

  // Group commands by executable
  const commandsByExecutable = new Map<string, Set<string>>();

  for (const cmd of commands) {
    if (!commandsByExecutable.has(cmd.command)) {
      commandsByExecutable.set(cmd.command, new Set());
    }
    commandsByExecutable.get(cmd.command)!.add(cmd.args);
  }

  // Generate sudoers rules
  const rules: string[] = [];

  for (const [executable, argsSet] of commandsByExecutable.entries()) {
    const args = Array.from(argsSet);

    if (args.length === 1 && args[0] === '') {
      // No arguments - allow bare command
      rules.push(`${username} ALL=(ALL) NOPASSWD: ${executable}`);
    } else if (args.length === 1) {
      // Single argument pattern - allow specific invocation
      rules.push(`${username} ALL=(ALL) NOPASSWD: ${executable} ${args[0]}`);
    } else {
      // Multiple argument patterns - allow executable with any args
      rules.push(`${username} ALL=(ALL) NOPASSWD: ${executable}`);
      rules.push(`# Used with: ${args.slice(0, 3).join(', ')}${args.length > 3 ? ', ...' : ''}`);
    }
  }

  return rules.join('\n');
}
