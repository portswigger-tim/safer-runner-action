/**
 * The job summary, put together from each service's part (services/<svc>/report.ts) and the setup
 * checks (checks.ts). This module only places the parts; every verdict, count and name comes from
 * the part that owns it.
 */

import type { Mode } from '../policy';
import { report as proxyReport, type ProxySection } from '../services/mitmproxy/report';
import type { HostSummary } from '../services/mitmproxy/flows';
import type { HttpFilterReport } from '../services/mitmproxy/http-filter';
import { report as dnsReport } from '../services/coredns/report';
import { report as firewallReport } from '../services/iptables/report';
import type { FirewallEvent } from '../services/iptables/log';
import { report as sudoReport, type SudoPolicyReport } from '../services/sudo/report';
import type { SudoUsage } from '../services/sudo/log';
import { report as dockerReport, type DockerPolicyReport } from '../services/docker/report';
import type { ContainerSummary } from '../services/docker/containers';
import { integrityCheck, selfTestCheck, type Check, type IntegrityDetails, type SelfTest } from './checks';
import { code, table } from './markdown';
import type { Alert, ReportContext, Section } from './section';

export interface ReportInput {
  mode: Mode;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  sudoRetained?: boolean;
  /** the runner user kept docker access (root-equivalent): as verified at setup, not the input */
  dockerRetained?: boolean;
  /** the docker input and the access verified after applying it (G4) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running' };
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
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as GitHub
   * platform traffic. Undefined: no split.
   */
  userDomains?: string[];
  selfTests: SelfTest[];
  integrity?: IntegrityDetails;
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter); undefined: no http-filter section */
  httpFilter?: HttpFilterReport;
  /** GitHub platform endpoints the built-in list auto-allowed on filtered hosts (policy.json) */
  platformEndpoints?: number;
  /** per-container egress (P2); empty / undefined: no container traffic */
  containers?: ContainerSummary[];
  extraSections?: string[];
  /** the ref the workflow used in `uses:` (GITHUB_ACTION_REF); echoed in the enforce suggestion so the paste matches the user's pin. v2 has no moving @v2 tag. */
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
  selfTests: Check;
  integrity: Check;
}

/**
 * What made enforce advisory: 'sudo', 'sudo (sudo-config allowlist)', 'docker', joined with
 * 'and', or '' (a boundary).
 */
function retained(sudoRetained: boolean, dockerRetained: boolean, sudoAllowlist = false): string {
  const sudo = sudoRetained ? 'sudo' : sudoAllowlist ? 'sudo (sudo-config allowlist)' : '';
  return [sudo, dockerRetained ? 'docker' : ''].filter(Boolean).join(' and ');
}

/**
 * Mode as shown in the summary header. enforce with sudo or docker (root-equivalent) retained,
 * or a sudo-config allowlist, is never shown as plain enforce.
 */
export function modeLabel(mode: Mode, sudoRetained = false, dockerRetained = false, sudoAllowlist = false): string {
  if (mode === 'analyze') return '📊 ANALYZE';
  const what = retained(sudoRetained, dockerRetained, sudoAllowlist);
  return what ? `⚠️ ENFORCE (ADVISORY — ${what} retained, not an enforced boundary)` : '🔒 ENFORCE';
}

/** Every part, each from its own observations. */
export function reportSections(input: ReportInput): ReportSections {
  const enforce = input.mode === 'enforce';
  const ctx: ReportContext = { mode: input.mode, enforce, actionRef: input.actionRef };
  const proxy = proxyReport(
    {
      hosts: input.hosts,
      dnsRefused: input.dnsRefused,
      userDomains: input.userDomains,
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
    selfTests: selfTestCheck(input.selfTests),
    integrity: integrityCheck(input.integrity)
  };
}

function titleAndChips(s: ReportSections, advisoryWhat: string): string {
  const { enforce } = s.ctx;
  const advisory = advisoryWhat !== '';
  const md = `## 🛡️ Safer Runner — egress${advisory ? ` — enforce (ADVISORY — ${advisoryWhat} retained, not an enforced boundary)` : ''}\n\n`;
  const chips = [advisory ? '⚠️ ENFORCE · ADVISORY' : enforce ? '🔒 ENFORCE' : '📊 ANALYZE'];
  const parts = [...s.proxy.chips, ...s.sudo.chips, ...s.docker.chips];
  chips.push(...parts);
  if (enforce) {
    if (!advisory) chips.push('✅ controls applied at setup');
    chips.push(s.integrity.chip);
  } else if (!parts.length) {
    chips.push('nothing would be blocked');
  }
  if (s.selfTests.chip) chips.push(s.selfTests.chip);
  return md + chips.map(c => `<kbd>${c}</kbd>`).join(' ') + '\n\n';
}

/** Verdict alerts (top level only: alerts don't render inside <details>), one per kind. */
function alerts(s: ReportSections): string {
  const all: Alert[] = [
    ...s.proxy.alerts,
    ...s.selfTests.alerts,
    ...s.integrity.alerts,
    ...s.sudo.alerts,
    ...s.docker.alerts
  ];
  const quoted = (a: Alert) => (a.quoted ? a.text : `> ${a.text}\n`);
  let md = '';
  for (const kind of ['CAUTION', 'WARNING', 'IMPORTANT'] as const) {
    const items = all.filter(a => a.kind === kind).map(quoted);
    if (!items.length) continue;
    if (kind === 'WARNING') items.unshift('> **The boundary was weaker than it looks.**\n');
    md += `> [!${kind}]\n` + items.join('>\n') + '\n';
  }
  return md;
}

/** The scorecard, or the one-line clean verdict. */
function scorecard(s: ReportSections): string {
  const { proxy, firewall } = s;
  if (!proxy.blocking && !firewall.blocking) {
    if (s.ctx.enforce) return `**✅ Nothing blocked.** ${proxy.allowedLine} through the proxy.\n\n`;
    // sudo or docker would be blocked (or could not be checked): the all-clear is for egress only
    if (s.sudo.blocking || s.docker.blocking)
      return `**No host would be blocked.** ${proxy.allowedLine} through the proxy.\n\n`;
    return `**✅ Nothing would be blocked.** ${proxy.allowedLine} through the proxy. This job should run unchanged with \`mode: enforce\`.\n\n`;
  }
  return table(['', ''], [':--', ':--'], [...proxy.score, ...firewall.score]) + '\n\n';
}

/** Diagnostics: one collapsed section, every part states its result. */
function diagnostics(s: ReportSections): string {
  const parts = [
    s.selfTests.diagnostic,
    ...s.firewall.diagnostics,
    ...s.proxy.diagnostics,
    ...s.dns.diagnostics,
    ...s.sudo.diagnostics,
    ...s.docker.diagnostics,
    s.integrity.diagnostic
  ].filter(d => d !== undefined);
  let body = parts.map(d => d.body).join('');
  for (const x of s.input.extraSections ?? []) if (x) body += x + '\n\n';
  return `<details>\n<summary>🔧 <b>Diagnostics</b> — ${parts.map(d => d.summary).join(' · ')}</summary>\n\n${body}</details>\n\n`;
}

function footer(s: ReportSections): string {
  const now = (s.input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  return `<sub>${s.ctx.mode} · job ${code(s.input.job)} · ${now} UTC · [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2</sub>\n`;
}

/** The summary from its parts. */
export function compose(s: ReportSections): string {
  const advisoryWhat = [s.sudo.advisory, s.docker.advisory].filter(Boolean).join(' and ');
  return [
    titleAndChips(s, advisoryWhat),
    alerts(s),
    scorecard(s),
    s.proxy.body,
    s.docker.body,
    diagnostics(s),
    footer(s)
  ].join('');
}

export function buildReport(input: ReportInput): string {
  return compose(reportSections(input));
}

/** Every part's full lists, for the job log (redacted like the summary). */
export function jobLog(s: ReportSections): string[] {
  return [...s.proxy.jobLog, ...s.sudo.jobLog, ...s.docker.jobLog];
}
