/**
 * Sudo's part of the job summary: what the workflow ran with sudo, what sudo blocked, and (analyze)
 * what the policy would block in enforce, with the suggested sudo-config that proxy/sudo_suggest.py
 * builds from the workflow's own sudo commands, as YAML written with the same library that reads
 * the input back.
 */

import { stringify } from 'yaml';
import type { SudoCommand, SudoUsage } from './log';
import { sudoCommandShown } from '../../report/redact';
import { code, plural, table } from '../../report/markdown';
import type { Advisory, BlockedRow, CheckRow, Details, ReportContext, Section, Suggestion } from '../../report/section';

export interface SudoConfigSuggestion {
  /** exact command lines, sorted; never a `*` */
  rules: string[];
  /** distinct command lines left out, by reason */
  omitted: { secret: number; unrepresentable: number; other_user: number; over_cap: number };
}

/**
 * The suggestion as the sudo-config input value: a YAML list, read back by parseSudoConfig.
 * A flagged line (line -> why) gets a `# ⚠️ why` comment, which the input ignores.
 */
export function sudoConfigYaml(rules: string[], flagged: Record<string, string> = {}): string {
  const items = stringify(rules, { lineWidth: 0 }).trimEnd().split('\n');
  return items.map((item, i) => (flagged[rules[i]] ? `${item} # ⚠️ ${flagged[rules[i]]}` : item)).join('\n') + '\n';
}

export interface SudoPolicyReport {
  /** sudo-config lines: kept in the restricted sudoers (enforce) or evaluated (analyze) */
  rules: string[];
  /** disable-sudo: false - sudo is kept as it is */
  kept: boolean;
  /** analyze: the workflow's sudo commands the policy would block in enforce */
  wouldBlock: SudoCommand[];
  /** analyze: the suggested sudo-config; undefined when it could not be built */
  suggestion?: SudoConfigSuggestion;
  /** suggested lines that give the job root, sit under a runner-writable path, ...: line -> why */
  flagged?: Record<string, string>;
}

export interface SudoObserved {
  /** sudo log split by who ran what (analyze: tells the user enforce will remove sudo) */
  usage?: SudoUsage;
  /** the sudo policy (disable-sudo, sudo-config) and, in analyze, what it would block */
  policy?: SudoPolicyReport;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  retained: boolean;
}

interface Facts {
  o: SudoObserved;
  enforce: boolean;
  ran: SudoCommand[];
  refused: SudoCommand[];
  /** analyze: workflow sudo commands the policy would block in enforce */
  wouldBlock: SudoCommand[];
  /** enforce kept sudo-config lines: ADVISORY */
  sudoAllowlist: number;
  /** the policy keeps sudo (disable-sudo: false) */
  kept: boolean;
}

const key = (c: SudoCommand) => `${c.targetUser} ${c.command} ${c.args}`;

function facts(o: SudoObserved, ctx: ReportContext): Facts {
  const { enforce } = ctx;
  const ran = o.usage?.ran ?? [];
  return {
    o,
    enforce,
    ran,
    refused: o.usage?.refused ?? [],
    // without a policy (an older setup marker), every workflow sudo command: enforce removes sudo
    wouldBlock: enforce ? [] : o.policy ? o.policy.wouldBlock : ran,
    sudoAllowlist: enforce && !o.retained ? (o.policy?.rules.length ?? 0) : 0,
    kept: o.retained || o.policy?.kept === true
  };
}

/** Each distinct command line once, with how many times it ran (`runs` from the log), in first-seen order. */
function counted(commands: SudoCommand[]): [SudoCommand, number][] {
  const by = new Map<string, [SudoCommand, number]>();
  for (const c of commands) {
    const row = by.get(key(c));
    if (row) row[1] += c.runs ?? 1;
    else by.set(key(c), [c, c.runs ?? 1]);
  }
  return [...by.values()];
}

/** A command as shown: arguments that could be credentials are redacted (redact.ts sudoCommandShown). */
const shown = (c: SudoCommand) => code(sudoCommandShown(c));

function blocked(f: Facts): BlockedRow[] {
  // the input that blocks it: sudo-config when the job has one, else disable-sudo
  const reason = code(f.o.policy?.rules.length ? 'sudo-config' : 'disable-sudo');
  return counted(f.enforce ? f.refused : f.wouldBlock).map(([c, n]) => ({
    reason,
    layer: 'sudo',
    tries: n,
    what: shown(c)
  }));
}

/** The cell in the row of numbers. */
function stat(f: Facts): string {
  if (f.enforce) {
    if (f.o.retained) return '⚠️ kept';
    if (f.sudoAllowlist) return `⚠️ ${plural(f.sudoAllowlist, 'sudo-config line')}`;
    return 'removed';
  }
  if (!f.o.usage) return 'not recorded';
  // the policy keeps sudo, or the job's sudo-config: enforce would be ADVISORY
  return f.kept || f.o.policy?.rules.length ? `⚠️ ${f.ran.length}` : String(f.ran.length);
}

function advisory(f: Facts): Advisory[] {
  if (!f.enforce) return [];
  if (f.o.retained) {
    return [
      {
        label: 'sudo kept',
        text: '`disable-sudo: false` kept sudo, so any step could have removed the egress controls.'
      }
    ];
  }
  if (f.sudoAllowlist) {
    return [
      {
        label: `${plural(f.sudoAllowlist, 'sudo-config line')}`,
        text:
          `\`sudo-config\` kept sudo for ${plural(f.sudoAllowlist, 'command line')}: a command that can run code or ` +
          'write files gives the job root, and root can remove the egress controls.'
      }
    ];
  }
  return [];
}

function suggestions(f: Facts): Suggestion[] {
  const s = f.o.policy?.suggestion;
  if (f.enforce || !s?.rules.length || !(f.wouldBlock.length || (f.kept && f.ran.length))) return [];
  return [
    {
      input: 'sudo-config',
      value: sudoConfigYaml(s.rules, f.o.policy?.flagged),
      advisory: 'ADVISORY'
    }
  ];
}

function notes(f: Facts): string[] {
  if (f.enforce) return [];
  const out: string[] = [];
  if (f.kept) out.push('remove `disable-sudo: false`: it keeps sudo, so enforce would be ADVISORY');
  else if (f.o.policy?.rules.length) out.push('the job sets `sudo-config`, so enforce would be ADVISORY');
  const s = f.o.policy?.suggestion;
  if (s && suggestions(f).length) {
    const left = [
      s.omitted.secret ? `${s.omitted.secret} with arguments that look like a secret` : '',
      s.omitted.unrepresentable ? `${s.omitted.unrepresentable} that a sudo-config line cannot express` : '',
      s.omitted.other_user ? `${s.omitted.other_user} run as another user` : '',
      s.omitted.over_cap ? `${s.omitted.over_cap} over the limit` : ''
    ].filter(Boolean);
    if (left.length) out.push(`sudo lines not suggested: ${left.join(', ')}`);
  }
  return out;
}

const MAX_SUDO_ROWS = 50;

function commandTable(rows: [SudoCommand, number][]): string {
  const listed = rows.slice(0, MAX_SUDO_ROWS);
  const extra = rows.length - listed.length;
  return (
    table(
      ['Command', 'Runs'],
      [':--', '--:'],
      listed.map(([c, n]) => [shown(c), String(n)])
    ) +
    (extra > 0 ? `\n\n+${extra} more (job log)` : '') +
    '\n\n'
  );
}

/** The job's sudo commands that were allowed (or that enforce would allow). */
function details(f: Facts): Details[] {
  const blockedKeys = new Set(f.wouldBlock.map(key));
  const allowed = counted(f.ran.filter(c => !blockedKeys.has(key(c))));
  if (!allowed.length) return [];
  const runs = allowed.reduce((a, [, n]) => a + n, 0);
  return [
    {
      summary: `Sudo, allowed: ${plural(allowed.length, 'command')} · ${plural(runs, 'run')}`,
      body: commandTable(allowed)
    }
  ];
}

/** Safer Runner's own sudo (setup, the post step's checks). */
function checks(f: Facts): CheckRow[] {
  return counted(f.o.usage?.internal ?? []).map(([c]) => ({ ok: true, check: 'own sudo', detail: shown(c) }));
}

/** Full lists in the job log (arguments redacted like the summary: the job log is just as public). */
export function jobLog(o: Pick<SudoObserved, 'usage' | 'policy'>): string[] {
  return [
    ...(o.usage?.ran ?? []).map(c => `sudo (workflow) ${sudoCommandShown(c)}`),
    ...(o.usage?.refused ?? []).map(c => `sudo REFUSED ${sudoCommandShown(c)}`),
    ...(o.policy?.wouldBlock ?? []).map(c => `sudo WOULD_BLOCK ${sudoCommandShown(c)}`)
  ];
}

export function report(o: SudoObserved, ctx: ReportContext): Section {
  const f = facts(o, ctx);
  return {
    blocked: blocked(f),
    alerts: [],
    suggestions: suggestions(f),
    notes: notes(f),
    advisory: advisory(f),
    details: details(f),
    checks: checks(f),
    stat: stat(f)
  };
}
