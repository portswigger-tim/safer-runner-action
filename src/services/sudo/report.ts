/**
 * Sudo's part of the job summary: what the workflow ran with sudo, what sudo refused, and (analyze)
 * what the policy would block in enforce, with the suggested sudo-config that proxy/sudo_suggest.py
 * builds from the workflow's own sudo commands, as YAML written with the same library that reads
 * the input back.
 */

import { stringify } from 'yaml';
import type { SudoCommand, SudoUsage } from './log';
import { sudoCommandShown } from '../../report/redact';
import { code, plural, table } from '../../report/markdown';
import {
  VERDICT_ICON,
  type Advisory,
  type ReportContext,
  type RunnerSystem,
  type ScoreRow,
  type Section,
  type Suggestion,
  type Verdict
} from '../../report/section';

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

/** Fixed caveat for every sudo-config: never shown as safe. */
export const SUDO_CONFIG_CAVEAT =
  'A sudo allowlist is not a boundary: a command that can run code or write files gives the job root, ' +
  'and root can remove the egress controls. Enforce with any `sudo-config` is ADVISORY.';

/** What analyze cannot see in the sudo log. */
export const SUDO_BEST_EFFORT =
  'Best effort: the sudo log does not show `sudo -E` or where one argument ends and the next begins, ' +
  'so a command shown as allowed can still be refused in enforce.';

interface Facts {
  o: SudoObserved;
  ctx: ReportContext;
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
    ctx,
    enforce,
    ran,
    refused: o.usage?.refused ?? [],
    // without a policy (an older setup marker), every workflow sudo command: enforce removes sudo
    wouldBlock: enforce ? [] : o.policy ? o.policy.wouldBlock : ran,
    sudoAllowlist: enforce && !o.retained ? (o.policy?.rules.length ?? 0) : 0,
    kept: o.retained || o.policy?.kept === true
  };
}

function score(f: Facts): ScoreRow[] {
  const { ran, refused, enforce } = f;
  const area = 'Sudo';
  if (enforce) {
    const rows: ScoreRow[] = [];
    if (f.o.retained) rows.push({ verdict: 'advisory', area, text: 'kept (`disable-sudo: false`)' });
    else if (f.sudoAllowlist) {
      rows.push({
        verdict: 'advisory',
        area,
        text: `\`sudo-config\` keeps ${plural(f.sudoAllowlist, 'command line')}${ran.length ? `; the job ran ${plural(ran.length, 'command')}` : ''}`
      });
    }
    if (refused.length)
      rows.push({ verdict: 'blocked', area, text: `${plural(refused.length, 'sudo attempt')} refused` });
    if (!rows.length) rows.push({ verdict: 'allowed', area, text: 'removed from the job' });
    return rows;
  }
  if (f.wouldBlock.length) {
    return [{ verdict: 'would-block', area, text: `${plural(f.wouldBlock.length, 'command')} would be blocked` }];
  }
  if (f.kept) {
    return [
      {
        verdict: 'advisory',
        area,
        text: `\`disable-sudo: false\` keeps sudo (ADVISORY)${ran.length ? `; the job ran ${plural(ran.length, 'command')}` : ''}`
      }
    ];
  }
  if (f.o.policy?.rules.length) {
    return [
      { verdict: 'advisory', area, text: `${plural(ran.length, 'command')}, all allowed by \`sudo-config\` (ADVISORY)` }
    ];
  }
  return [
    {
      verdict: 'allowed',
      area,
      text: ran.length ? `${plural(ran.length, 'command')}, none blocked` : 'the job ran no sudo'
    }
  ];
}

function advisory(f: Facts): Advisory[] {
  if (!f.enforce) return [];
  if (f.o.retained) {
    return [
      {
        chip: '⚠️ sudo retained',
        text:
          '`disable-sudo: false` kept sudo, so any step could have removed the egress controls. Remove it to make ' +
          'enforce a boundary.'
      }
    ];
  }
  if (f.sudoAllowlist) {
    return [
      {
        chip: `⚠️ sudo allowlist (${f.sudoAllowlist})`,
        text:
          `\`sudo-config\` kept sudo for ${plural(f.sudoAllowlist, 'command line')}. ` +
          SUDO_CONFIG_CAVEAT.replace(' Enforce with any `sudo-config` is ADVISORY.', '') +
          ' Remove `sudo-config` to make enforce a boundary.'
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
      advisory: 'any sudo-config makes enforce ADVISORY'
    }
  ];
}

function notes(f: Facts): string[] {
  if (f.enforce) return [];
  const out: string[] = [];
  if (f.kept) out.push('remove `disable-sudo: false`: it keeps sudo, so enforce would be ADVISORY');
  const s = f.o.policy?.suggestion;
  if (s && suggestions(f).length) {
    const left = [
      s.omitted.secret ? `${s.omitted.secret} with arguments that look like a secret` : '',
      s.omitted.unrepresentable ? `${s.omitted.unrepresentable} that a sudo-config line cannot express` : '',
      s.omitted.other_user ? `${s.omitted.other_user} run as another user` : '',
      s.omitted.over_cap ? `${s.omitted.over_cap} over the limit` : ''
    ].filter(Boolean);
    if (left.length) out.push(`sudo lines not suggested: ${left.join(', ')}`);
    out.push(SUDO_CONFIG_CAVEAT);
  }
  if (f.ran.length) out.push(SUDO_BEST_EFFORT);
  return out;
}

const MAX_SUDO_ROWS = 50;

/** One row per command; arguments that could be credentials are redacted (redact.ts sudoCommandShown). */
function commandTable(rows: [Verdict, SudoCommand, string][], more: string): string {
  const shown = rows.slice(0, MAX_SUDO_ROWS);
  const extra = rows.length - shown.length;
  return (
    table(
      ['', 'Command', 'Result'],
      [':-:', ':--', ':--'],
      shown.map(([v, c, result]) => [VERDICT_ICON[v], code(`sudo ${sudoCommandShown(c)}`), result])
    ) +
    (extra > 0 ? `\n\n+${extra} more ${more} (job log)` : '') +
    '\n\n'
  );
}

function body(f: Facts): string {
  if (!f.o.usage) return 'No sudo log was found.\n\n';
  const { ran, refused, enforce } = f;
  if (!ran.length && !refused.length) return 'The job ran no sudo.\n\n';
  const blocked = new Set(f.wouldBlock.map(key));
  const allowedAs: [Verdict, string] = f.kept
    ? ['advisory', 'allowed: sudo kept']
    : f.o.policy?.rules.length
      ? ['advisory', 'allowed by `sudo-config`']
      : ['allowed', 'allowed'];
  const rows: [Verdict, SudoCommand, string][] = [
    ...ran.map((c): [Verdict, SudoCommand, string] =>
      blocked.has(key(c)) ? ['would-block', c, 'enforce would block it'] : [allowedAs[0], c, allowedAs[1]]
    ),
    ...refused.map((c): [Verdict, SudoCommand, string] => ['blocked', c, 'refused by sudo'])
  ];
  let md = commandTable(rows, 'commands');
  if (!enforce && ran.length) md += `<sub>${SUDO_BEST_EFFORT}</sub>\n\n`;
  return md;
}

function runnerSystem(f: Facts): RunnerSystem[] {
  const internal = f.o.usage?.internal ?? [];
  if (!internal.length) return [];
  return [
    {
      summary: `Safer Runner ran ${plural(internal.length, 'sudo command')}`,
      body:
        "**Safer Runner's own sudo** (setup, integrity checks)\n\n" +
        commandTable(
          internal.map(c => ['allowed', c, 'the action'] as [Verdict, SudoCommand, string]),
          'commands'
        )
    }
  ];
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
    score: score(f),
    alerts: [],
    suggestions: suggestions(f),
    notes: notes(f),
    advisory: advisory(f),
    body: body(f),
    runnerSystem: runnerSystem(f)
  };
}
