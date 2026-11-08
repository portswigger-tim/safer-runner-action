/**
 * Sudo's part of the job summary: what the workflow ran with sudo, what sudo refused, and (analyze)
 * what the policy would block in enforce, with the suggested sudo-config that proxy/sudo_suggest.py
 * builds from the workflow's own sudo commands, as YAML written with the same library that reads
 * the input back.
 */

import { stringify } from 'yaml';
import type { SudoCommand, SudoUsage } from './log';
import { sudoCommandShown } from '../../report/redact';
import { codeBlock, plural } from '../../report/markdown';
import type { Alert, ReportContext, Section } from '../../report/section';

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
  enforce: boolean;
  sudoRan: number;
  /** analyze: workflow sudo commands the policy would block in enforce */
  sudoWouldBlock: number;
  /** enforce kept sudo-config lines: ADVISORY */
  sudoAllowlist: number;
}

function facts(o: SudoObserved, ctx: ReportContext): Facts {
  const { enforce } = ctx;
  return {
    o,
    enforce,
    sudoRan: o.usage?.ran.length ?? 0,
    // without a policy (an older setup marker), every workflow sudo command: enforce removes sudo
    sudoWouldBlock: o.policy ? o.policy.wouldBlock.length : (o.usage?.ran.length ?? 0),
    sudoAllowlist: enforce && !o.retained ? (o.policy?.rules.length ?? 0) : 0
  };
}

function chips(f: Facts): string[] {
  const out: string[] = [];
  if (f.enforce) {
    if (f.o.retained) out.push('⚠️ sudo retained');
    if (f.sudoAllowlist) out.push(`⚠️ sudo allowlist (${f.sudoAllowlist})`);
  } else if (f.o.policy && f.sudoWouldBlock) {
    out.push(`${plural(f.sudoWouldBlock, 'sudo command')} would be blocked`);
  }
  return out;
}

/** Analyze: the sudo commands enforce would block, and the suggested sudo-config (in an alert). */
function sudoAlert(f: Facts): string {
  const policy = f.o.policy;
  const quote = (text: string) =>
    text
      .split('\n')
      .map(l => `> ${l}`)
      .join('\n');
  let md: string;
  if (f.sudoWouldBlock) {
    md =
      `> **Enforce would block ${plural(f.sudoWouldBlock, 'sudo command')} this job ran** ` +
      `(enforce removes sudo${policy?.rules.length ? ', except your `sudo-config` lines' : ''}; listed under Diagnostics). ` +
      'Drop that usage, or allow the exact command lines with `sudo-config`';
  } else {
    md =
      `> **This job ran ${plural(f.sudoRan, 'sudo command')}, and \`disable-sudo: false\` keeps sudo**, so enforce ` +
      'would be ADVISORY (sudo can remove the controls). To make enforce a boundary, remove `disable-sudo: false`';
  }
  const s = policy?.suggestion;
  if (!s?.rules.length) return md + `.\n>\n> ${SUDO_BEST_EFFORT}\n`;
  md += ' (review each line):\n>\n';
  const yaml =
    'sudo-config: |\n' +
    sudoConfigYaml(s.rules, policy?.flagged)
      .replace(/^(?=.)/gm, '  ')
      .trimEnd();
  md += quote(codeBlock('yaml', yaml)) + '\n';
  const left = [
    s.omitted.secret ? `${s.omitted.secret} with arguments that look like a secret` : '',
    s.omitted.unrepresentable ? `${s.omitted.unrepresentable} that a sudo-config line cannot express` : '',
    s.omitted.other_user ? `${s.omitted.other_user} run as another user` : '',
    s.omitted.over_cap ? `${s.omitted.over_cap} over the limit` : ''
  ].filter(Boolean);
  if (left.length) md += `>\n> Not suggested: ${left.join(', ')}.\n`;
  return md + `>\n> ${SUDO_CONFIG_CAVEAT} ${SUDO_BEST_EFFORT}\n`;
}

function alerts(f: Facts): Alert[] {
  const { o, enforce } = f;
  const out: Alert[] = [];
  if (enforce) {
    if (f.sudoAllowlist) {
      out.push({
        kind: 'WARNING',
        text:
          `**ADVISORY: sudo was kept for ${plural(f.sudoAllowlist, 'command line')}** (\`sudo-config\`). ` +
          SUDO_CONFIG_CAVEAT.replace(' Enforce with any `sudo-config` is ADVISORY.', '') +
          ' Remove `sudo-config` to make enforce a boundary.'
      });
    }
    if (o.retained) {
      out.push({
        kind: 'WARNING',
        text:
          '**ADVISORY: sudo was retained** (`disable-sudo: false`), so any step could have used it to ' +
          'remove the egress controls. The policy below was applied, but this job did not run inside an enforced ' +
          'boundary. Remove `disable-sudo: false` to make enforce a boundary.'
      });
    }
    return out;
  }
  const sudoKeptRan = o.policy?.kept === true && f.sudoRan > 0;
  if (f.sudoWouldBlock || sudoKeptRan) out.push({ kind: 'IMPORTANT', text: sudoAlert(f) + '\n', quoted: true });
  return out;
}

function diagnostics(f: Facts): Section['diagnostics'] {
  const { o, enforce } = f;
  if (!o.usage) return [];
  const { ran, refused, internal } = o.usage;
  const summary =
    (ran.length === 0 ? 'no workflow sudo' : `workflow ran ${plural(ran.length, 'sudo command')}`) +
    (internal.length ? ` (${internal.length} by Safer Runner)` : '') +
    (refused.length ? ` · ${plural(refused.length, 'sudo attempt')} refused` : '') +
    (!enforce && f.sudoWouldBlock ? ` · enforce would block ${f.sudoWouldBlock}` : '');
  // arguments that could be credentials are redacted (redact.ts sudoCommandShown)
  const lines = (cmds: SudoCommand[]) =>
    cmds
      .slice(0, 50)
      .map(c => `$ sudo ${sudoCommandShown(c)}`)
      .join('\n') + (cmds.length > 50 ? `\n# ... +${cmds.length - 50} more (job log)` : '');
  let body = `**Sudo** — the workflow ran ${ran.length ? plural(ran.length, 'command') : 'none'}`;
  body += internal.length ? `; Safer Runner itself ran ${internal.length} (setup, integrity checks)` : '';
  body += ran.length ? ':\n\n' + codeBlock('console', lines(ran)) + '\n\n' : '.\n\n';
  if (refused.length) {
    body += `Refused by sudo (${refused.length}):\n\n` + codeBlock('console', lines(refused)) + '\n\n';
  }
  const wouldBlock = enforce ? [] : (o.policy?.wouldBlock ?? []);
  if (wouldBlock.length) {
    body += `Enforce would block (${wouldBlock.length}):\n\n` + codeBlock('console', lines(wouldBlock)) + '\n\n';
  }
  return [{ summary, body }];
}

/** Full lists in the job log (arguments redacted like the summary: the job log is just as public). */
function jobLog(o: SudoObserved): string[] {
  return [
    ...(o.usage?.ran ?? []).map(c => `sudo (workflow) ${sudoCommandShown(c)}`),
    ...(o.usage?.refused ?? []).map(c => `sudo REFUSED ${sudoCommandShown(c)}`),
    ...(o.policy?.wouldBlock ?? []).map(c => `sudo WOULD_BLOCK ${sudoCommandShown(c)}`)
  ];
}

export function report(o: SudoObserved, ctx: ReportContext): Section {
  const f = facts(o, ctx);
  return {
    chips: chips(f),
    alerts: alerts(f),
    score: [],
    blocking: f.sudoWouldBlock > 0,
    body: '',
    diagnostics: diagnostics(f),
    jobLog: jobLog(o),
    advisory: f.enforce ? (o.retained ? 'sudo' : f.sudoAllowlist ? 'sudo (sudo-config allowlist)' : '') : ''
  };
}
