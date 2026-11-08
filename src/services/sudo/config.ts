/**
 * Sudo's pure config: the sudo-logging config for each sudo implementation, the restricted
 * sudoers file, and the list of the action's own sudo commands. No I/O.
 *
 * Sudoers text must be valid for BOTH implementations: no wildcards among command arguments
 * (sudo-rs accepts only a lone trailing `*`), no `Defaults!<alias>`, no `log_allowed`.
 */

import { isScalar, isSeq } from 'yaml';
import { strictYaml } from '../../config/yaml';
import type { SudoCommand } from '../../report/logs/sudo-log';
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
/**
 * One sudo-config rule as a sudoers command. A command with no arguments gets `""`: in sudoers
 * a bare command allows ANY arguments, `""` allows none. Every word is checked again here.
 */
export function sudoersCommand(r: SudoRule): string {
  for (const w of [r.path, ...r.args]) {
    if (!WORD.test(w)) throw new Error(`sudo-config: refusing to write '${w}' into sudoers`);
  }
  return r.args.length === 0 && !r.anyRest ? `${r.path} ""` : ruleText(r);
}

/**
 * The restricted sudoers file (disable-sudo): the action's own validation commands, plus the
 * job's sudo-config command lines, run as root only. Without sudo-config it is exactly the
 * validation-only file.
 */
export function buildRestrictedSudoers(rules: readonly SudoRule[] = []): string {
  const job = rules.length
    ? `
# The job's own command lines (sudo-config), as root only
Cmnd_Alias SAFER_RUNNER_JOB = ${rules.map(sudoersCommand).join(', \\\n    ')}

${RUNNER_USERNAME} ALL=(root) NOPASSWD: SAFER_RUNNER_JOB
`
    : '';
  return `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation.
# All other sudo commands will be denied.
${getRequiredSudoCommands(RUNNER_USERNAME)}${job}
`;
}

export interface SudoFacts {
  flavour: SudoFlavour;
  /** where sudo usage is logged (SUDO_LOG) */
  logFile: string;
  /** restrict sudo (disable-sudo in enforce) */
  restrict: boolean;
  /** sudo-config: kept in the restricted sudoers */
  rules: readonly SudoRule[];
}

/** What the sudo steps write. None of it is inert: each write is a named step in ./index.ts. */
export type SudoRendered = {
  flavour: SudoFlavour;
  logFile: string;
  /** the sudo-logging config: a sudoers drop-in (classic) or an rsyslog rule (sudo-rs) */
  logging: { path: string; content: string };
} & ({ restrict: { sudoers: string } } | { restrict: null });

/** A render that restricts sudo: the only kind restrictSudo() takes. */
export type RestrictingSudo = Extract<SudoRendered, { restrict: { sudoers: string } }>;

export function render(f: SudoFacts): SudoRendered {
  return {
    flavour: f.flavour,
    logFile: f.logFile,
    logging: {
      path: getSudoLoggingConfigFile(f.flavour),
      content: f.flavour === 'sudo-rs' ? buildSudoRsyslogConfig(f.logFile) : buildSudoLoggingDropIn(f.logFile)
    },
    restrict: f.restrict ? { sudoers: buildRestrictedSudoers(f.rules) } : null
  };
}

// ------------------------------------------------------------------ sudo-config

declare const sudoRule: unique symbol;
/**
 * One sudo-config entry: an exact command line the job may run as root, optionally ending in a
 * lone `*` (any further arguments). Minted only by parseSudoConfig(), so the sudoers text is
 * never built from a string that was not checked.
 */
export type SudoRule = {
  readonly path: string;
  readonly args: readonly string[];
  /** a trailing `*`: one or more further arguments (see ruleAllows) */
  readonly anyRest: boolean;
  readonly [sudoRule]: true;
};

/**
 * What an entry may contain: nothing sudoers would need escaped (`, : = \ # ! %` quotes,
 * whitespace inside an argument) and no glob other than the lone trailing `*`.
 */
const WORD = /^[A-Za-z0-9_./@+-]+$/;
const PATH = /^(\/[A-Za-z0-9_.@+-]+)+$/;
export const SUDO_CONFIG_MAX_RULES = 100;
const MAX_LINE = 512;

/** The sudoers text of one rule (also its identity): `path args...`, `*` last. */
export function ruleText(r: Pick<SudoRule, 'path' | 'args' | 'anyRest'>): string {
  return [r.path, ...r.args, ...(r.anyRest ? ['*'] : [])].join(' ');
}

/** One command line, or the reason it is not one. */
export function parseSudoLine(line: string): SudoRule {
  if (line.length > MAX_LINE) throw new Error(`is longer than ${MAX_LINE} characters`);
  const words = line.trim().split(/ +/).filter(Boolean);
  if (!words.length) throw new Error('is empty');
  const [path, ...rest] = words;
  if (/^(ALL|sudoedit|Defaults|Cmnd_Alias|Runas_Alias|User_Alias|Host_Alias)\b/.test(path) || /^[!%+]/.test(path)) {
    throw new Error(`is not a command line ('${path}' is sudoers syntax)`);
  }
  if (path.includes('*')) throw new Error('has a * in the command path (only a lone trailing * argument is allowed)');
  if (!path.startsWith('/')) throw new Error(`'${path}' is not an absolute path`);
  if (!PATH.test(path) || path.split('/').some(seg => seg === '.' || seg === '..')) {
    throw new Error(`'${path}' is not a plain absolute path (no //, ., .., trailing / or special characters)`);
  }
  if (/\/sudoedit$/.test(path)) throw new Error('sudoedit is not allowed');
  const anyRest = rest[rest.length - 1] === '*';
  const args = anyRest ? rest.slice(0, -1) : rest;
  for (const a of args) {
    if (a.includes('*')) throw new Error(`'${a}': only a lone trailing * is allowed (sudo-rs)`);
    if (!WORD.test(a)) {
      throw new Error(`'${a}' has an unsupported character (allowed: letters, digits and _ . / @ + -)`);
    }
  }
  if (anyRest && !args.length) {
    throw new Error(`'${path} *' would allow every argument: name at least the first argument before *`);
  }
  return Object.freeze({ path, args: Object.freeze([...args]), anyRest }) as SudoRule;
}

/**
 * sudo-config: a YAML list of command lines the job may run as root under disable-sudo in
 * enforce (on top of the action's own read-only checks). Read with the same strict YAML as
 * http-filter; anything invalid fails the step, never skipped or last-wins.
 */
export function parseSudoConfig(raw: string): SudoRule[] {
  if (!(raw || '').trim()) return [];
  const { doc, at } = strictYaml(raw, 'sudo-config', {
    fallback: 'write one command line per "- " list item',
    hints: { BAD_ALIAS: 'a command line must start with its absolute path, not *' }
  });
  if (doc.contents === null || (isScalar(doc.contents) && doc.contents.value === null)) return [];
  if (!isSeq(doc.contents)) {
    throw new Error(
      `${at(doc.contents)}: expected a list of command lines, e.g. "- /usr/bin/apt-get update" ` +
        '(the v1 sudo-config format is not accepted)'
    );
  }
  const items = doc.contents.items;
  if (items.length > SUDO_CONFIG_MAX_RULES) {
    throw new Error(`sudo-config: at most ${SUDO_CONFIG_MAX_RULES} command lines, got ${items.length}`);
  }
  const seen = new Set<string>();
  return items.map(item => {
    const where = at(item as Parameters<typeof at>[0]);
    if (!isScalar(item) || typeof item.value !== 'string') {
      throw new Error(`${where}: each entry must be one command line (a string)`);
    }
    let rule: SudoRule;
    try {
      rule = parseSudoLine(item.value);
    } catch (e) {
      throw new Error(`${where}: '${item.value}' ${(e as Error).message}`);
    }
    const text = ruleText(rule);
    if (seen.has(text)) throw new Error(`${where}: '${text}' is listed more than once`);
    seen.add(text);
    return rule;
  });
}

/**
 * Commands that give whoever can run them as root a way to run anything else, or to write any
 * file. Not exhaustive: a warning nudges towards tight entries, never a guarantee.
 */
const ROOT_EQUIVALENT =
  /^(sh|bash|dash|zsh|ksh|fish|python[0-9.]*|perl|ruby|node|nodejs|php|lua|env|su|sudo|visudo|tee|cp|mv|dd|install|chmod|chown|chgrp|ln|rm|systemctl|journalctl|docker|podman|iptables.*|ip6tables.*|nft|ip|mount|umount|kill|pkill|killall|apt|apt-get|aptitude|dpkg|snap|pip[0-9.]*|npm|npx|yarn|gem|cargo|vi|vim|nvim|nano|ed|emacs|less|more|man|find|xargs|awk|gawk|sed|tar|zip|unzip|rsync|scp|ssh|git|make|crontab|at|useradd|usermod|passwd|chroot|nsenter|unshare|setcap|insmod|modprobe|sysctl)$/;

/** Guardrail warnings for the job log and summary. Every sudo-config makes enforce ADVISORY. */
export function sudoConfigWarnings(rules: readonly SudoRule[]): string[] {
  const out: string[] = [];
  for (const r of rules) {
    const base = r.path.slice(r.path.lastIndexOf('/') + 1);
    if (ROOT_EQUIVALENT.test(base)) {
      out.push(
        `sudo-config: '${ruleText(r)}' gives the job root (${base} can run or write anything), so sudo can remove the egress controls`
      );
    } else if (r.anyRest) {
      out.push(`sudo-config: '${ruleText(r)}' allows any further arguments, including options`);
    }
  }
  return out;
}

/**
 * Does a rule allow this command (as the sudo log records it: absolute path, arguments joined
 * by single spaces, run as root)? Exact path and exact arguments; a trailing `*` takes one or
 * more further arguments. That is what BOTH sudo implementations allow: classic sudo's `*` needs
 * the space before it (so not zero further arguments), sudo-rs takes zero or more.
 */
export function ruleAllows(r: Pick<SudoRule, 'path' | 'args' | 'anyRest'>, command: string, args: string): boolean {
  if (command !== r.path) return false;
  const got = args.split(/ +/).filter(Boolean);
  if (!r.anyRest) return got.length === r.args.length && r.args.every((a, i) => got[i] === a);
  return got.length > r.args.length && r.args.every((a, i) => got[i] === a);
}

/**
 * Analyze: the workflow's own sudo commands the declared policy would block in enforce. With sudo
 * kept (disable-sudo: false) nothing would be; otherwise everything the sudo-config rules don't
 * allow (they run as root only).
 */
export function evaluateSudo(
  rules: readonly SudoRule[],
  kept: boolean,
  ran: readonly SudoCommand[]
): { allowed: SudoCommand[]; wouldBlock: SudoCommand[] } {
  const allowed: SudoCommand[] = [];
  const wouldBlock: SudoCommand[] = [];
  for (const c of ran) {
    const ok = kept || ((c.targetUser || 'root') === 'root' && rules.some(r => ruleAllows(r, c.command, c.args)));
    (ok ? allowed : wouldBlock).push(c);
  }
  return { allowed, wouldBlock };
}
