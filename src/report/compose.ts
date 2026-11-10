/**
 * The job summary, put together from each service's part (services/<svc>/report.ts) and the setup
 * checks (checks.ts). This module only places the parts; every count, reason and name comes from
 * the part that owns it.
 *
 *   banner, linked to the repository
 *   ### Safer Runner · mode · job      the row of numbers, then any alert
 *   #### Blocked                       one row per reason, as the log writes it
 *   #### For enforce                   analyze only: the step to paste (enforce suggests nothing:
 *                                      what it blocked needs a look, not a paste)
 *   collapsed: what was allowed (the job's hosts, GitHub's, sudo, docker, containers), and
 *   Safer Runner's own checks
 *
 * One verb throughout: blocked (enforce) and would block (analyze). A clean run is the row of
 * numbers and nothing else.
 */

import { Document, Pair, Scalar, YAMLMap, YAMLSeq } from 'yaml';
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
import { capped, code, codeBlock, humanBytes, table } from './markdown';
import type { BlockedRow, CheckRow, Details, ReportContext, Section, Suggestion } from './section';

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

/** Where the action comes from, for the link when the workflow's repository is unknown. */
export const ACTION_REPOSITORY = 'portswigger-tim/safer-runner-action';

/**
 * Emoji are functional only: ✅ a check passed, ⚠️ a check failed or an input makes enforce
 * ADVISORY. Anything else in a summary is a bug (the tests check every one).
 */
export const SUMMARY_EMOJI = ['✅', '⚠'];

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
 * The comment on the `uses:` line: a reminder to pin, unless the ref already is an exact version
 * or a commit SHA. A SHA gets no version: it can be a fork's commit, or one between releases.
 */
function usesComment(ref: string | undefined): string {
  const r = safeRef(ref);
  return /^[0-9a-f]{40}$/.test(r) || /^v\d+\.\d+\.\d+$/.test(r) ? '' : ' pin an exact version or commit SHA';
}

/** The repository on GitHub: the workflow's own (a fork links to itself), else this one. */
export function repoUrl(repository: string | undefined): string {
  return `https://github.com/${safeRepository(repository) || ACTION_REPOSITORY}`;
}

/**
 * The banner: docs/assets/banner.svg in the repository and at the ref the workflow used (inline
 * SVG is stripped from summaries), so a fork shows its own, linked to the repository. None when
 * either is unknown or not safe to print (a local `uses: ./`, odd values).
 */
export function banner(repository: string | undefined, ref: string | undefined): string {
  const repo = safeRepository(repository);
  const r = safeRef(ref);
  if (!repo || !r) return '';
  return (
    `<a href="${repoUrl(repo)}"><img src="https://raw.githubusercontent.com/${repo}/${r}/docs/assets/banner.svg" ` +
    'width="480" alt="Safer Runner Action"></a>\n\n'
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

/** The parts in the order the Blocked table lists them. */
const services = (s: ReportSections): Section[] => [s.proxy, s.dns, s.firewall, s.sudo, s.docker];

const blockedRows = (s: ReportSections): BlockedRow[] => services(s).flatMap(x => x.blocked);

const advisories = (s: ReportSections) => services(s).flatMap(x => x.advisory);

// ---------------------------------------------------------------- numbers

/** The heading the Blocked count and table carry: what enforce blocked, or would block. */
const blockedWord = (s: ReportSections) => (s.ctx.enforce ? 'Blocked' : 'Enforce would block');

function title(s: ReportSections): string {
  const advisory = s.ctx.enforce && advisories(s).length ? ' · ADVISORY' : '';
  return `### Safer Runner · ${code(s.ctx.mode)}${advisory} · job ${code(s.input.job)}\n\n`;
}

function numbers(s: ReportSections): string {
  const n = blockedRows(s).length;
  const t = s.proxy.totals;
  return (
    table(
      [blockedWord(s), 'Hosts', 'Requests', '↑ Out', '↓ In', 'sudo', 'docker'],
      ['--:', '--:', '--:', '--:', '--:', '--:', '--:'],
      [
        [
          n ? `**${n}**` : '0',
          t.hosts,
          String(t.requests),
          humanBytes(t.out),
          humanBytes(t.in),
          s.sudo.stat ?? '',
          s.docker.stat ?? ''
        ]
      ]
    ) + '\n\n'
  );
}

/** Alerts at the top level only (they don't render inside <details>), one per kind. */
function alerts(s: ReportSections): string {
  const all = [...s.checks.alerts, ...services(s).flatMap(x => x.alerts)];
  const advisory = s.ctx.enforce ? advisories(s) : [];
  if (advisory.length) {
    all.push({
      kind: 'WARNING',
      text: `**ADVISORY: not an enforced boundary** (${advisory.map(a => a.label).join(', ')}).`
    });
    all.push(...advisory.map(a => ({ kind: 'WARNING' as const, text: a.text })));
  }
  let md = '';
  for (const kind of ['CAUTION', 'WARNING'] as const) {
    const items = all.filter(a => a.kind === kind);
    if (items.length) md += `> [!${kind}]\n` + items.map(a => `> ${a.text}`).join('\n>\n') + '\n\n';
  }
  return md;
}

// ---------------------------------------------------------------- blocked

function blocked(s: ReportSections): string {
  const rows = blockedRows(s);
  if (!rows.length) return '';
  const { shown, note } = capped(rows);
  return (
    `#### ${blockedWord(s)}\n\n` +
    table(
      ['Reason', 'Layer', 'Tries', 'Names'],
      [':--', ':--', '--:', ':--'],
      shown.map(r => [r.reason, r.layer, r.tries === undefined ? '—' : String(r.tries), r.what])
    ) +
    note +
    '\n\n'
  );
}

// ---------------------------------------------------------------- suggestion

const INPUT_ORDER: Suggestion['input'][] = ['allowed-domains', 'http-filter', 'sudo-config', 'docker'];

/** An input's value as a YAML scalar: a block literal when it has lines, its comment on its line. */
function scalar(s: Suggestion): Scalar {
  const x = new Scalar(s.value);
  if (s.value.includes('\n')) x.type = Scalar.BLOCK_LITERAL;
  const comment = [s.advisory ? `⚠️ ${s.advisory}` : '', s.comment ?? ''].filter(Boolean).join('; ');
  if (comment) x.comment = ` ${comment}`;
  return x;
}

/** The suggested inputs under `with:`, in their usual order. */
function inputsMap(suggestions: Suggestion[], mode: string): YAMLMap {
  const w = new YAMLMap();
  w.add(new Pair(new Scalar('mode'), new Scalar(mode)));
  for (const input of INPUT_ORDER) {
    const s = suggestions.find(x => x.input === input);
    if (s) w.add(new Pair(new Scalar(s.input), scalar(s)));
  }
  return w;
}

/**
 * The suggested inputs as one `uses:` step, written by the `yaml` library that reads the inputs
 * back (so a pasted block reads as printed). An ADVISORY input carries a comment on its line.
 */
export function suggestedBlock(uses: string, suggestions: Suggestion[], ref?: string): string {
  const action = new Scalar(uses);
  const comment = usesComment(ref);
  if (comment) action.comment = comment;
  const step = new YAMLMap();
  step.add(new Pair(new Scalar('uses'), action));
  step.add(new Pair(new Scalar('with'), inputsMap(suggestions, 'enforce')));
  const doc = new Document();
  doc.contents = new YAMLSeq();
  (doc.contents as YAMLSeq).items.push(step);
  return doc.toString({ lineWidth: 0 }).trimEnd();
}

/** A sentence for the notes line: capitalised, with a full stop. */
const sentence = (n: string) => n[0].toUpperCase() + n.slice(1) + (/[.!?]$/.test(n) ? '' : '.');

/** Analyze: the enforce step to paste. Enforce suggests nothing (see the proxy part's suggestions). */
function suggested(s: ReportSections): string {
  if (s.ctx.enforce) return '';
  const parts = services(s);
  const uses = usesLine(s.input.actionRepository, s.input.actionRef);
  const all = parts.flatMap(x => x.suggestions);
  let md = '#### For enforce\n\n' + codeBlock('yaml', suggestedBlock(uses, all, s.input.actionRef)) + '\n\n';
  const notes = parts.flatMap(x => x.notes);
  if (notes.length) md += `<sub>${notes.map(sentence).join(' ')}</sub>\n\n`;
  return md;
}

// ---------------------------------------------------------------- collapsed

function collapsed(d: Details): string {
  return `<details>\n<summary>${d.summary}</summary>\n\n${d.body}</details>\n\n`;
}

/** Safer Runner's own part: the setup checks, and what the action itself did. */
function saferRunner(s: ReportSections): string {
  const rows: CheckRow[] = [...s.checks.rows, ...s.sudo.checks, ...s.docker.checks];
  const body =
    table(
      ['', 'Check', 'Detail'],
      [':--', ':--', ':--'],
      rows.map(r => [r.ok ? '✅' : '⚠️', r.check, r.detail])
    ) +
    '\n\n' +
    (s.checks.body ? s.checks.body.trimEnd() + '\n\n' : '');
  return collapsed({ summary: `Safer Runner: ${s.checks.summary}`, body });
}

/** The action as the workflow named it, `owner/repo@ref`, linked to the repository. */
function footer(s: ReportSections): string {
  const now = (s.input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  const repo = safeRepository(s.input.actionRepository);
  const ref = safeRef(s.input.actionRef);
  const label = repo && ref ? `${repo}@${ref}` : 'Safer Runner';
  return `<sub>${now} UTC · [${label}](${repoUrl(s.input.actionRepository)})</sub>\n`;
}

/** The summary from its parts. */
export function compose(s: ReportSections): string {
  return [
    banner(s.input.actionRepository, s.input.actionRef),
    title(s),
    numbers(s),
    alerts(s),
    blocked(s),
    suggested(s),
    ...services(s).flatMap(x => x.details.map(collapsed)),
    saferRunner(s),
    ...(s.input.extraSections ?? []).filter(Boolean).map(x => x + '\n\n'),
    footer(s)
  ].join('');
}

export function buildReport(input: ReportInput): string {
  return compose(reportSections(input));
}

/** The suggested block, for the job log (the same text the summary shows); '' in enforce. */
export function suggestedForLog(s: ReportSections): string {
  if (s.ctx.enforce) return '';
  const uses = usesLine(s.input.actionRepository, s.input.actionRef);
  return suggestedBlock(
    uses,
    services(s).flatMap(x => x.suggestions),
    s.input.actionRef
  );
}
