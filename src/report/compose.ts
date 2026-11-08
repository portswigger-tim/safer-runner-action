/**
 * The job summary, put together from each service's part (services/<svc>/report.ts) and the setup
 * checks (checks.ts). This module only places the parts; every verdict, count and name comes from
 * the part that owns it.
 *
 *   banner
 *   # 📋 Summary                          the verdict, alerts and the scorecard
 *     ## 🔧 Suggested Enforce Configuration   analyze: one block to paste; enforce: one line
 *   # 🔎 Detail
 *     ## 🌐 Network  ## 🔑 Sudo  ## 🐳 Docker   what the job did; what the action did (and the
 *                                              GitHub baseline it trusts) under a collapsed
 *                                              🖥️ Runner System
 */

import { Document, Pair, Scalar, YAMLMap, YAMLSeq, stringify } from 'yaml';
import type { Mode } from '../policy';
import { report as proxyReport, type ProxySection } from '../services/mitmproxy/report';
import type { HostSummary } from '../services/mitmproxy/flows';
import type { HttpFilterReport } from '../services/mitmproxy/http-filter';
import { report as dnsReport } from '../services/coredns/report';
import { report as firewallReport } from '../services/iptables/report';
import type { FirewallEvent } from '../services/iptables/log';
import { report as sudoReport, type SudoPolicyReport } from '../services/sudo/report';
import type { SudoUsage } from '../services/sudo/log';
import { report as dockerReport, type DockerPolicyReport, type DockerReportObserved } from '../services/docker/report';
import type { ContainerSummary } from '../services/docker/containers';
import { setupChecks, type Checks, type IntegrityDetails, type SelfTest } from './checks';
import { code, codeBlock, table } from './markdown';
import { VERDICT_ICON, type ReportContext, type RunnerSystem, type Section, type Suggestion } from './section';

export interface ReportInput {
  mode: Mode;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  sudoRetained?: boolean;
  /** the runner user kept docker access (root-equivalent): as verified at setup, not the input */
  dockerRetained?: boolean;
  /** the docker input, the access verified after applying it (G4), and the dockerd CA restart (F1) */
  docker?: DockerReportObserved['docker'];
  /** analyze: the job's use of docker, what the docker policy would break, and the suggestion */
  dockerPolicy?: DockerPolicyReport;
  /** sudo log split by who ran what (analyze: tells the user enforce will remove sudo) */
  sudo?: SudoUsage;
  /** the sudo policy (disable-sudo, sudo-config) and, in analyze, what it would block */
  sudoPolicy?: SudoPolicyReport;
  job: string;
  hosts: HostSummary[];
  firewall: FirewallEvent[];
  /** names the resolver refused (enforce) / would refuse (analyze); the setup self-test excluded */
  dnsRefused: string[];
  /**
   * The job's own `allowed-domains` + `passthrough-domains` patterns. Allowed traffic to
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as the GitHub
   * baseline. Undefined: no split.
   */
  userDomains?: string[];
  /** the job's `allowed-domains` entries alone: the suggested value keeps them */
  allowedDomains?: string[];
  /** the job sets `http-filter` */
  httpFilterSet?: boolean;
  selfTests: SelfTest[];
  integrity?: IntegrityDetails;
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter); undefined: no http-filter section */
  httpFilter?: HttpFilterReport;
  /** GitHub platform endpoints the built-in list auto-allowed on filtered hosts (policy.json) */
  platformEndpoints?: number;
  /** per-container egress (P2); empty / undefined: no container traffic */
  containers?: ContainerSummary[];
  extraSections?: string[];
  /**
   * The action as the workflow named it in `uses:` (GITHUB_ACTION_REPOSITORY, GITHUB_ACTION_REF):
   * the banner and the suggested `uses:` line pin the same ref. v2 has no moving @v2 tag.
   */
  actionRepository?: string;
  actionRef?: string;
  now?: Date;
}

/** Each part of the summary, from its owner. */
export interface ReportSections {
  input: ReportInput;
  ctx: ReportContext;
  proxy: ProxySection;
  firewall: Section;
  dns: Section;
  sudo: Section;
  docker: Section;
  checks: Checks;
}

/** Where the action comes from, for the footer's attribution when the workflow's repository is unknown. */
export const ACTION_REPOSITORY = 'portswigger-tim/safer-runner-action';

/**
 * Emoji are functional only: one per heading (📋 🔎 🌐 🔑 🐳 🔧, 🖥️ for Runner System) and the
 * verdicts (VERDICT_ICON). Anything else in a summary is a bug (the tests check every one).
 */
export const SUMMARY_EMOJI = ['📋', '🔎', '🌐', '🔑', '🐳', '🔧', '🖥', '✅', '🟠', '⛔', '⚠'];

/** Pictographs in `md` that are not in SUMMARY_EMOJI. */
export function emojiOutsideAllowlist(md: string): string[] {
  return [...new Set(md.match(/\p{Extended_Pictographic}/gu) ?? [])].filter(e => !SUMMARY_EMOJI.includes(e));
}
/** a ref as `uses:` can name it: a tag, branch or SHA; never `..`, quotes, spaces or markup */
const REF = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/;

/** an `owner/name` as GitHub allows it; never `..`, quotes, spaces or markup */
const REPOSITORY = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;

/** The ref, when it is safe to print in a URL and in YAML; '' otherwise. */
export function safeRef(ref: string | undefined): string {
  const r = (ref ?? '').trim();
  return REF.test(r) && !r.includes('..') ? r : '';
}

/** The repository, when it is safe to print in a URL and in YAML; '' otherwise. */
export function safeRepository(repository: string | undefined): string {
  const r = (repository ?? '').trim();
  return REPOSITORY.test(r) && !r.includes('..') && !/\/\.+$/.test(r) ? r : '';
}

/**
 * The action as the workflow named it in `uses:` (GITHUB_ACTION_REPOSITORY @ GITHUB_ACTION_REF),
 * so a fork or an internal mirror is echoed as itself, never swapped for upstream. A placeholder
 * part for what is unknown or not safe to print (a local `uses: ./`, odd values).
 */
export function usesLine(repository: string | undefined, ref: string | undefined): string {
  const repo = safeRepository(repository);
  if (!repo) return '<owner>/<repo>@<pin an exact version or SHA>';
  return `${repo}@${safeRef(ref) || '<pin an exact version or SHA>'}`;
}

/**
 * The banner: docs/assets/banner.svg in the repository and at the ref the workflow used (inline
 * SVG is stripped from summaries), so a fork shows its own. None when either is unknown or not
 * safe to print (a local `uses: ./`, odd values).
 */
export function banner(repository: string | undefined, ref: string | undefined): string {
  const repo = safeRepository(repository);
  const r = safeRef(ref);
  if (!repo || !r) return '';
  return (
    `<p align="center"><img src="https://raw.githubusercontent.com/${repo}/${r}/docs/assets/banner.svg" ` +
    'width="480" alt="Safer Runner Action"></p>\n\n'
  );
}

/** Every part, each from its own observations. */
export function reportSections(input: ReportInput): ReportSections {
  const enforce = input.mode === 'enforce';
  const ctx: ReportContext = { mode: input.mode, enforce };
  const proxy = proxyReport(
    {
      hosts: input.hosts,
      userDomains: input.userDomains,
      allowedDomains: input.allowedDomains,
      httpFilter: input.httpFilter,
      httpFilterSet: input.httpFilterSet,
      platformEndpoints: input.platformEndpoints
    },
    ctx
  );
  return {
    input,
    ctx,
    proxy,
    firewall: firewallReport({ events: input.firewall }, ctx),
    dns: dnsReport({ refused: input.dnsRefused }, ctx, proxy.deniedNames),
    sudo: sudoReport({ usage: input.sudo, policy: input.sudoPolicy, retained: input.sudoRetained === true }, ctx),
    docker: dockerReport(
      {
        retained: input.dockerRetained === true,
        docker: input.docker,
        policy: input.dockerPolicy,
        containers: input.containers
      },
      ctx
    ),
    checks: setupChecks(input.selfTests, input.integrity)
  };
}

const services = (s: ReportSections): Section[] => [s.proxy, s.firewall, s.dns, s.sudo, s.docker];

// ---------------------------------------------------------------- summary

const SEVERITY: Record<string, number> = { blocked: 0, 'would-block': 0, advisory: 1, allowed: 2 };

/** Every scorecard row, worst first (stable: each part's own order within a verdict). */
function scoreRows(s: ReportSections) {
  return [...s.proxy.score, ...s.firewall.score, ...s.sudo.score, ...s.docker.score, s.checks.score].sort(
    (a, b) => SEVERITY[a.verdict] - SEVERITY[b.verdict]
  );
}

/** The services' rows: what enforce would block or make ADVISORY (the setup checks are not a policy). */
const policyRows = (s: ReportSections) => scoreRows(s).filter(r => r !== s.checks.score);

/** The verdict line: what was (or would be) blocked, by area. */
function headline(s: ReportSections): string {
  const rows = policyRows(s);
  const areas = (v: string) => [...new Set(rows.filter(r => r.verdict === v).map(r => r.area))];
  if (s.ctx.enforce) {
    const blocked = areas('blocked');
    const advisory = services(s).flatMap(x => x.advisory);
    // a weakened boundary is never skimmable as clean
    const weak = advisory.length
      ? `**ADVISORY: not an enforced boundary** (${advisory.map(a => a.chip.replace(/^⚠️ /, '')).join(', ')}). `
      : '';
    return weak + (blocked.length ? `**Blocked: ${blocked.join(', ')}** (see Detail).` : 'Nothing was blocked.');
  }
  const would = areas('would-block');
  if (would.length) {
    return (
      `Nothing was blocked: analyze only observes. **Under enforce, this job would be blocked in ${would.join(', ')}.** ` +
      'Use the configuration below, or change the job.'
    );
  }
  if (areas('advisory').length) {
    // ADVISORY, or not fully seen (a partial docker recording): never an all-clear
    return 'Nothing was blocked: analyze only observes. **Under enforce, check the ⚠️ rows below** (ADVISORY, or not fully seen).';
  }
  return 'Nothing was blocked: analyze only observes. **Nothing would be blocked under enforce:** this job should run unchanged with `mode: enforce`.';
}

function chips(s: ReportSections): string {
  const advisory = services(s).flatMap(x => x.advisory);
  const mode = s.ctx.enforce ? (advisory.length ? 'ENFORCE · ADVISORY' : 'ENFORCE') : 'ANALYZE';
  return [mode, ...advisory.map(a => a.chip)].map(c => `<kbd>${c}</kbd>`).join(' ');
}

/** Alerts at the top level only (they don't render inside <details>), one per kind. */
function alerts(s: ReportSections): string {
  const all = [...s.proxy.alerts, ...s.checks.alerts, ...s.sudo.alerts, ...s.docker.alerts];
  // enforce with a weakened boundary: one warning, with every reason
  if (s.ctx.enforce) {
    const advisory = services(s).flatMap(x => x.advisory);
    if (advisory.length) {
      all.push({ kind: 'WARNING', text: '**The boundary was weaker than it looks.**' });
      all.push(...advisory.map(a => ({ kind: 'WARNING' as const, text: a.text })));
    }
  }
  let md = '';
  for (const kind of ['CAUTION', 'WARNING', 'IMPORTANT'] as const) {
    const items = all.filter(a => a.kind === kind);
    if (items.length) md += `> [!${kind}]\n` + items.map(a => `> ${a.text}`).join('\n>\n') + '\n\n';
  }
  return md;
}

function scorecard(s: ReportSections): string {
  return (
    table(
      ['', 'Area', 'Result'],
      [':-:', ':--', ':--'],
      scoreRows(s).map(r => [VERDICT_ICON[r.verdict], r.area, r.text])
    ) + '\n\n'
  );
}

const INPUT_ORDER: Suggestion['input'][] = ['allowed-domains', 'http-filter', 'sudo-config', 'docker'];

/**
 * The suggested inputs as one `uses:` step, written by the `yaml` library that reads the inputs
 * back (so a pasted block reads as printed). An ADVISORY input carries a comment on its line.
 */
export function suggestedBlock(uses: string, suggestions: Suggestion[]): string {
  const scalar = (s: Suggestion) => {
    const x = new Scalar(s.value);
    if (s.value.includes('\n')) x.type = Scalar.BLOCK_LITERAL;
    const comment = [s.advisory ? `⚠️ ${s.advisory}` : '', s.comment ?? ''].filter(Boolean).join('; ');
    if (comment) x.comment = ` ${comment}`;
    return x;
  };
  const w = new YAMLMap();
  w.add(new Pair(new Scalar('mode'), new Scalar('enforce')));
  for (const input of INPUT_ORDER) {
    const s = suggestions.find(x => x.input === input);
    if (s) w.add(new Pair(new Scalar(s.input), scalar(s)));
  }
  const action = new Scalar(uses);
  action.comment = ' pin an exact version or commit SHA';
  const step = new YAMLMap();
  step.add(new Pair(new Scalar('uses'), action));
  step.add(new Pair(new Scalar('with'), w));
  const doc = new Document();
  doc.contents = new YAMLSeq();
  (doc.contents as YAMLSeq).items.push(step);
  return doc.toString({ lineWidth: 0 }).trimEnd();
}

/** A sentence for the notes paragraph: capitalised, with a full stop. */
const sentence = (n: string) => n[0].toUpperCase() + n.slice(1) + (/[.!?]$/.test(n) ? '' : '.');

function suggested(s: ReportSections): string {
  let md = '## 🔧 Suggested Enforce Configuration\n\n';
  const parts = services(s);
  if (s.ctx.enforce) {
    const advisory = parts.flatMap(x => x.advisory);
    return (
      md +
      (advisory.length
        ? 'Running under enforce. ⚠️ **ADVISORY:** not an enforced boundary (see the warning above).\n\n'
        : 'Running under enforce: the controls were applied at setup.\n\n')
    );
  }
  const all = parts.flatMap(x => x.suggestions);
  const inBlock = all.filter(x => !x.optional);
  const optional = all.filter(x => x.optional);
  const notes = parts.flatMap(x => x.notes);
  if (inBlock.length) {
    md +=
      'Review every line before you use it; inputs not listed stay as they are. A ⚠️ line makes enforce ADVISORY.\n\n';
    md += codeBlock('yaml', suggestedBlock(usesLine(s.input.actionRepository, s.input.actionRef), inBlock)) + '\n\n';
  } else {
    const advisory = policyRows(s).some(r => r.verdict === 'advisory');
    md += advisory
      ? 'No input to change, but enforce would be ADVISORY (⚠️ above).\n\n'
      : 'Nothing to change: this job should run under `mode: enforce` as it is configured.\n\n';
  }
  if (notes.length) md += `<sub>${notes.map(sentence).join(' ')}</sub>\n\n`;
  for (const o of optional) {
    md +=
      `<details>\n<summary>Optional: narrow the allowed hosts further with <code>${o.input}</code>${o.label ? ` (${o.label})` : ''}</summary>\n\n` +
      'Built from this job\'s allowed requests: reads collapse to one `"*"` line per host, write paths keep their ' +
      'structure. A filter only narrows: each host must still be allowed. Add it under `with:`.\n\n' +
      codeBlock('yaml', stringify({ [o.input]: o.value }, { blockQuote: 'literal', lineWidth: 0 }).trimEnd()) +
      '\n\n</details>\n\n';
  }
  return md;
}

// ---------------------------------------------------------------- detail

/** A collapsed Runner System part: what the action did, its result in the summary line. */
function runnerSystem(parts: RunnerSystem[]): string {
  if (!parts.length) return '';
  return (
    `<details>\n<summary>🖥️ <b>Runner System</b>: ${parts.map(p => p.summary).join(' · ')}</summary>\n\n` +
    parts.map(p => p.body).join('') +
    '</details>\n\n'
  );
}

function detail(s: ReportSections): string {
  let md = '# 🔎 Detail\n\n';
  md += '## 🌐 Network\n\n' + s.proxy.body;
  md += runnerSystem([...s.proxy.runnerSystem, ...s.dns.runnerSystem, ...s.firewall.runnerSystem]);
  md += '## 🔑 Sudo\n\n' + s.sudo.body + runnerSystem(s.sudo.runnerSystem);
  md += '## 🐳 Docker\n\n' + s.docker.body + runnerSystem(s.docker.runnerSystem);
  md += runnerSystem([s.checks.runnerSystem]);
  for (const x of s.input.extraSections ?? []) if (x) md += x + '\n\n';
  return md;
}

function footer(s: ReportSections): string {
  const now = (s.input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  const repo = safeRepository(s.input.actionRepository) || ACTION_REPOSITORY;
  return `<sub>${s.ctx.mode} · job ${code(s.input.job)} · ${now} UTC · [Safer Runner Action](https://github.com/${repo}) v2</sub>\n`;
}

/** The summary from its parts. */
export function compose(s: ReportSections): string {
  return [
    banner(s.input.actionRepository, s.input.actionRef),
    '# 📋 Summary\n\n',
    `${chips(s)}\n\n${headline(s)}\n\n`,
    alerts(s),
    scorecard(s),
    suggested(s),
    detail(s),
    footer(s)
  ].join('');
}

export function buildReport(input: ReportInput): string {
  return compose(reportSections(input));
}

/** The suggested block, for the job log (the same text the summary shows); '' when none. */
export function suggestedForLog(s: ReportSections): string {
  if (s.ctx.enforce) return '';
  const inBlock = services(s)
    .flatMap(x => x.suggestions)
    .filter(x => !x.optional);
  return inBlock.length ? suggestedBlock(usesLine(s.input.actionRepository, s.input.actionRef), inBlock) : '';
}
