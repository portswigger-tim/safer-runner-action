/**
 * v2 job-summary report built from the proxy flow log (+ firewall and DNS logs).
 * DENIED first and in full; anything that has to be cut is said so explicitly (review M6).
 */

import { compilePattern, expandPattern, matchesAny, type Mode } from '../../policy';
import { containerSection, type ContainerSummary } from '../aggregate/containers';
import {
  DENIED,
  DENYLISTED,
  MAX_LIST,
  NOT_LISTED,
  blockedName,
  categorize,
  suggestedAllowlist,
  type Category,
  type HostSummary
} from '../aggregate/flows';
import { httpFilterYaml, type HttpFilterReport, type HttpFilterSuggestion } from '../aggregate/http-filter';
import { CONTAINER_PREFIXES, firewallSummary, type FirewallEvent, type FirewallSummary } from '../logs/firewall-log';
import type { SudoCommand, SudoUsage } from '../logs/sudo-log';
import { sudoConfigYaml, type SudoConfigSuggestion } from '../aggregate/sudo-config';
import { PATH_HIDDEN } from '../redact';
import { capped, code, codeBlock, humanBytes, plural, table } from './markdown';

export interface ReportInput {
  mode: Mode;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  sudoRetained?: boolean;
  /** the runner user kept docker access (root-equivalent): as verified at setup, not the input */
  dockerRetained?: boolean;
  /** the docker input and the access verified after applying it (G4) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running' };
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
  selfTests: { name: string; ok: boolean; detail: string }[];
  integrity?: { status: 'verified' | 'tampered' | 'unavailable'; body: string };
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

/** Fixed caveat for every sudo-config: never shown as safe. */
export const SUDO_CONFIG_CAVEAT =
  'A sudo allowlist is not a boundary: a command that can run code or write files gives the job root, ' +
  'and root can remove the egress controls. Enforce with any `sudo-config` is ADVISORY.';

/** What analyze cannot see in the sudo log. */
export const SUDO_BEST_EFFORT =
  'Best effort: the sudo log does not show `sudo -E` or where one argument ends and the next begins, ' +
  'so a command shown as allowed can still be refused in enforce.';

/**
 * The post step (this report, the tamper check, fail-on-tampering) runs as the runner user from
 * the action's files on the runner, which the job's own steps can write to. Say so in the report.
 */
export const ADVISORY_REPORT_NOTE =
  '<sub>The tamper check and this summary come from the post step, which runs as the runner user from ' +
  "files the job's steps can modify: an advisory tripwire, not tamper-proof evidence. The egress controls " +
  "themselves are root-owned and don't depend on it.</sub>";

// ---------------------------------------------------------------- words

function inCidr4(ip: string, base: string, bits: number): boolean {
  const n = (s: string) => s.split('.').reduce((a, o) => a * 256 + Number(o), 0);
  const size = 2 ** (32 - bits);
  return Math.floor(n(ip) / size) === Math.floor(n(base) / size);
}

/** Plain-words class of an internal address (mirrors FORBIDDEN_UPSTREAM_NETS in policy_core.py). */
export function addressClass(ip: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    if (ip === '169.254.169.254') return 'cloud metadata service';
    if (ip === '168.63.129.16') return 'Azure wireserver';
    const nets: [string, number, string][] = [
      ['127.0.0.0', 8, 'loopback'],
      ['169.254.0.0', 16, 'link-local'],
      ['10.0.0.0', 8, 'private, RFC 1918'],
      ['172.16.0.0', 12, 'private, RFC 1918'],
      ['192.168.0.0', 16, 'private, RFC 1918'],
      ['100.64.0.0', 10, 'CGNAT'],
      ['0.0.0.0', 8, '"this network"'],
      ['224.0.0.0', 4, 'multicast'],
      ['240.0.0.0', 4, 'reserved']
    ];
    for (const [base, bits, label] of nets) if (inCidr4(ip, base, bits)) return label;
    return 'internal';
  }
  const v6 = ip.toLowerCase();
  if (v6 === '::1') return 'loopback';
  if (/^fe[89ab]/.test(v6)) return 'link-local';
  if (/^f[cd]/.test(v6)) return 'private, ULA';
  if (v6.startsWith('ff')) return 'multicast';
  return 'internal';
}

const PORT_NAMES: Record<string, string> = {
  '22': 'SSH',
  '25': 'SMTP',
  '53': 'DNS',
  '123': 'NTP',
  '443': 'HTTPS (not proxied)',
  '80': 'HTTP (not proxied)',
  '853': 'DNS-over-TLS',
  '3128': 'HTTP proxy',
  '8080': 'HTTP-alt',
  '9418': 'git'
};

const FILTER_REASON_TEXT: Record<string, string> = {
  'method-not-allowed': 'method not allowed on this path',
  'path-not-allowed': 'path not allowed'
};

const NO_NAME_TEXT: Record<string, string> = {
  'no-sni': 'TLS with no SNI',
  'ip-literal-sni': 'TLS with an IP address as SNI',
  'ip-literal-host': 'HTTP request with an IP literal as the Host',
  'no-host': 'HTTP request with no Host'
};

const DOCKER_ACCESS_TEXT: Record<string, string> = {
  retained: 'runner user can use docker',
  'group-removed': 'runner user removed from the docker group, socket root-only',
  'not-running': 'docker daemon not running'
};

/**
 * The post-run tamper check as a chip. It is advisory (ADVISORY_REPORT_NOTE), and a check that
 * could not run is unknown, never a pass.
 */
function integrityChip(status: 'verified' | 'tampered' | 'unavailable' | undefined): string {
  if (status === 'tampered') return '🚨 config tampered';
  if (status === 'verified') return '🔎 no config change seen (advisory)';
  return '❔ config unverified';
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

function compressionText(s: HttpFilterSuggestion): string {
  return (
    `collapsed ${plural(s.requests, 'request')} → ${plural(s.rules, 'rule')} (level B)` +
    (s.specific ? `; ${plural(s.specific, 'write endpoint')} kept specific` : '')
  );
}

// ---------------------------------------------------------------- cells

function displayName(h: HostSummary): string {
  return h.name.replace(/^\(no name\) /, '');
}

function nameList(hosts: HostSummary[]): string {
  const names = hosts.slice(0, MAX_LIST).map(h => code(blockedName(displayName(h))));
  return names.join(', ') + (hosts.length > MAX_LIST ? `, +${hosts.length - MAX_LIST} more` : '');
}

function isPassthroughOnly(h: HostSummary): boolean {
  return h.requests === 0 && h.kinds.includes('passthrough');
}

/** Passthrough is never decrypted: no request or byte counts exist, so never print 0. */
function requestsCell(h: HostSummary): string {
  return isPassthroughOnly(h) ? '—' : String(h.requests);
}

function dataCell(h: HostSummary): string {
  if (isPassthroughOnly(h)) return 'n/a';
  const parts = [];
  if (h.reqBytes > 0) parts.push(`↑ ${humanBytes(h.reqBytes)}`);
  if (h.respBytes > 0) parts.push(`↓ ${humanBytes(h.respBytes)}`);
  return parts.join(' ') || '—';
}

/** Grouped by class, one per line: "2xx (45)<br>3xx (4)<br>5xx (1)". */
export function statusSummary(h: HostSummary): string {
  if (isPassthroughOnly(h)) return 'n/a';
  const byClass = new Map<string, number>();
  let answered = 0;
  for (const [k, n] of Object.entries(h.statuses)) {
    answered += n;
    const cls = /^[1-5]\d\d$/.test(k) ? `${k[0]}xx` : k;
    byClass.set(cls, (byClass.get(cls) ?? 0) + n);
  }
  const parts = [...byClass.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([cls, n]) => `${cls} (${n})`);
  if (h.requests > answered) parts.push(`no response (${h.requests - answered})`);
  return parts.join('<br>') || '—';
}

function hostCell(h: HostSummary): string {
  let c = code(blockedName(h.name));
  if (h.kinds.includes('passthrough')) c += ' <sub>🔀 passthrough</sub>';
  else if (h.kinds.length === 1 && h.kinds[0] === 'http') c += ' <sub>plain HTTP</sub>';
  return c;
}

function frontingCell(h: HostSummary, verb: string): string {
  const what = h.reasons.includes('host-sni-mismatch')
    ? '🎭 **Host/SNI mismatch** (domain fronting)'
    : '🎭 **Conflicting Host / authority**';
  const notes: string[] = [];
  if (h.snis.length) notes.push(`sent inside TLS for ${h.snis.map(n => code(blockedName(n))).join(', ')}`);
  if (h.reasons.some(r => NOT_LISTED.has(r))) notes.push('also not on allowlist');
  if (h.dsts.length) notes.push(`dialled ${h.dsts.map(code).join(', ')}`);
  return what + (verb ? `, ${verb}` : '') + (notes.length ? `<br><sub>${notes.join(' · ')}</sub>` : '');
}

function internalCell(h: HostSummary, verb: string): string {
  if (h.upstreamIps.length) {
    const ips = h.upstreamIps.map(ip => `${code(ip)} (${addressClass(ip)})`).join(', ');
    return `🕳️ **Internal address** → ${ips}, ${verb}`;
  }
  return `🕳️ **Internal address**, ${verb}`;
}

function destinationText(e: FirewallEvent): string {
  const likely = PORT_NAMES[e.dport];
  return `${likely ? `${likely} to ` : ''}${code(`${e.dst}:${e.dport}`)}`;
}

// ---------------------------------------------------------------- allowed tables

function compileUserPatterns(patterns: string[]): RegExp[] {
  const out: RegExp[] = [];
  for (const p of patterns.flatMap(expandPattern)) {
    try {
      out.push(compilePattern(p));
    } catch {
      // invalid entries were dropped (and warned about) at setup
    }
  }
  return out;
}

function byData(a: HostSummary, b: HostSummary): number {
  return (
    b.reqBytes + b.respBytes - (a.reqBytes + a.respBytes) || b.requests - a.requests || a.name.localeCompare(b.name)
  );
}

function allowedTable(rows: HostSummary[]): string {
  const { shown, note } = capped([...rows].sort(byData));
  let md = table(
    ['Host', 'Requests', 'Data', 'Responses'],
    [':--', '--:', '--:', ':--'],
    shown.map(h => [hostCell(h), requestsCell(h), dataCell(h), statusSummary(h)])
  );
  md += note + '\n\n';
  if (shown.some(h => h.kinds.includes('passthrough'))) {
    md += '<sub>🔀 passthrough = checked by TLS name only — not decrypted, so no byte counts.</sub>\n\n';
  }
  return md;
}

function totals(rows: HostSummary[]): { requests: number; bytes: number } {
  return {
    requests: rows.reduce((a, h) => a + h.requests, 0),
    bytes: rows.reduce((a, h) => a + h.reqBytes + h.respBytes, 0)
  };
}

// ---------------------------------------------------------------- report

/** Everything the sections share, worked out once from the input. */
interface Facts {
  input: ReportInput;
  mode: Mode;
  enforce: boolean;
  /** what was retained in enforce ('' when nothing: a boundary) */
  advisoryWhat: string;
  advisory: boolean;
  dnsRefused: Set<string>;
  blockedWord: string;
  denied: HostSummary[];
  allowed: HostSummary[];
  groups: Record<Category, HostSummary[]>;
  /** fronting + internal: the attacks */
  bypass: HostSummary[];
  jobHosts: HostSummary[];
  platform: HostSummary[];
  all: { requests: number; bytes: number };
  plat: { requests: number; bytes: number };
  selfOk: number;
  selfFailed: ReportInput['selfTests'];
  tampered: boolean;
  /** host firewall events (container ones are in the container section) */
  fw: FirewallSummary;
  sudoRan: number;
  /** analyze: workflow sudo commands the policy would block in enforce */
  sudoWouldBlock: number;
  /** enforce kept sudo-config lines: ADVISORY */
  sudoAllowlist: number;
  /** names to suggest for `allowed-domains` */
  suggest: string[];
  filterBlocks: HttpFilterReport['blocks'];
  /** requests the http-filter refused */
  filtered: number;
  /** denied hosts, less the ones only the http-filter refused */
  hostsDenied: number;
}

function facts(input: ReportInput): Facts {
  const { mode } = input;
  const enforce = mode === 'enforce';
  const sudoAllowlist = enforce && !input.sudoRetained ? (input.sudoPolicy?.rules.length ?? 0) : 0;
  const advisoryWhat = enforce
    ? retained(input.sudoRetained === true, input.dockerRetained === true, sudoAllowlist > 0)
    : '';

  const denied = input.hosts.filter(h => DENIED.has(h.verdict));
  const allowed = input.hosts.filter(h => !DENIED.has(h.verdict));
  const groups: Record<Category, HostSummary[]> = {
    fronting: [],
    internal: [],
    'not-allowed': [],
    filtered: [],
    unresolved: [],
    'no-name': [],
    other: []
  };
  for (const h of denied) groups[categorize(h)].push(h);
  const byTries = (a: HostSummary, b: HostSummary) => b.tries - a.tries || a.name.localeCompare(b.name);
  for (const g of Object.values(groups)) g.sort(byTries);

  let jobHosts = allowed;
  let platform: HostSummary[] = [];
  if (input.userDomains) {
    const user = compileUserPatterns(input.userDomains);
    jobHosts = allowed.filter(h => matchesAny(h.name, user));
    platform = allowed.filter(h => !jobHosts.includes(h));
  }

  const filterBlocks = input.httpFilter?.blocks ?? [];
  return {
    input,
    mode,
    enforce,
    advisoryWhat,
    advisory: advisoryWhat !== '',
    dnsRefused: new Set(input.dnsRefused.map(n => n.toLowerCase())),
    blockedWord: enforce ? 'blocked' : 'would be blocked',
    denied,
    allowed,
    groups,
    bypass: [...groups.fronting, ...groups.internal],
    jobHosts,
    platform,
    all: totals(allowed),
    plat: totals(platform),
    selfOk: input.selfTests.filter(t => t.ok).length,
    selfFailed: input.selfTests.filter(t => !t.ok),
    tampered: input.integrity?.status === 'tampered',
    // container firewall events are reported in the container section, with their source
    fw: firewallSummary(input.firewall.filter(e => !CONTAINER_PREFIXES.has(e.prefix))),
    sudoRan: input.sudo?.ran.length ?? 0,
    // without a policy (an older setup marker), every workflow sudo command: enforce removes sudo
    sudoWouldBlock: input.sudoPolicy ? input.sudoPolicy.wouldBlock.length : (input.sudo?.ran.length ?? 0),
    sudoAllowlist,
    suggest: suggestedAllowlist(denied),
    filterBlocks,
    filtered: filterBlocks.reduce((a, b) => a + b.tries, 0),
    hostsDenied: denied.length - groups.filtered.length
  };
}

function titleAndChips(f: Facts): string {
  const { input, enforce } = f;
  let md = `## 🛡️ Safer Runner — egress${f.advisory ? ` — enforce (ADVISORY — ${f.advisoryWhat} retained, not an enforced boundary)` : ''}\n\n`;
  const chips = [f.advisory ? '⚠️ ENFORCE · ADVISORY' : enforce ? '🔒 ENFORCE' : '📊 ANALYZE'];
  if (enforce) {
    if (input.sudoRetained) chips.push('⚠️ sudo retained');
    if (f.sudoAllowlist) chips.push(`⚠️ sudo allowlist (${f.sudoAllowlist})`);
    if (input.dockerRetained) chips.push('⚠️ docker retained');
    if (!f.advisory) chips.push('✅ controls applied at setup');
    chips.push(integrityChip(input.integrity?.status));
  } else {
    if (f.hostsDenied) chips.push(`${plural(f.hostsDenied, 'host')} would be blocked`);
    if (f.filtered) chips.push(`${plural(f.filtered, 'request')} the http-filter would refuse`);
    if (input.sudoPolicy && f.sudoWouldBlock)
      chips.push(`${plural(f.sudoWouldBlock, 'sudo command')} would be blocked`);
    if (!f.hostsDenied && !f.filtered && !(input.sudoPolicy && f.sudoWouldBlock))
      chips.push('nothing would be blocked');
  }
  if (input.selfTests.length) {
    chips.push(`${f.selfFailed.length ? '❌' : '🧪'} self-tests ${f.selfOk}/${input.selfTests.length}`);
  }
  return md + chips.map(c => `<kbd>${c}</kbd>`).join(' ') + '\n\n';
}

/** Verdict alerts (top level only: alerts don't render inside <details>). */
function alerts(f: Facts): string {
  const { input, enforce, groups, bypass, filtered, suggest, sudoRan, sudoWouldBlock } = f;
  const sudoKeptRan = !enforce && input.sudoPolicy?.kept === true && sudoRan > 0;
  let md = '';
  const critical: string[] = [];
  if (bypass.length) {
    const kinds = [];
    if (groups.fronting.length) kinds.push(plural(groups.fronting.length, 'Host/SNI spoof'));
    if (groups.internal.length) {
      kinds.push(
        `${plural(groups.internal.length, 'name')} that point${groups.internal.length === 1 ? 's' : ''} at internal addresses`
      );
    }
    critical.push(
      enforce
        ? `**Bypass attempts to ${plural(bypass.length, 'host')} were blocked** — ${kinds.join(' and ')}.\n` +
            '> Nothing in a normal build does this. Check the steps that ran before the post step.'
        : `**Bypass attempts to ${plural(bypass.length, 'host')} were seen and NOT blocked** (analyze mode) — ${kinds.join(' and ')}.\n` +
            '> Enforce would block them. Nothing in a normal build does this: check the steps that ran.'
    );
  }
  if (f.selfFailed.length) {
    critical.push(
      `**Self-test failed:** ${f.selfFailed.map(t => `\`${t.name}\``).join(', ')} — the proxy may not be enforcing as designed on this runner.`
    );
  }
  if (f.tampered) {
    critical.push(
      '**Safer Runner configuration changed during the job** — see the config file check under Diagnostics.'
    );
  }
  if (critical.length) md += '> [!CAUTION]\n' + critical.map(c => `> ${c}`).join('\n>\n') + '\n\n';

  if (enforce && f.advisory) {
    const why: string[] = [];
    if (f.sudoAllowlist) {
      why.push(
        `**ADVISORY: sudo was kept for ${plural(f.sudoAllowlist, 'command line')}** (\`sudo-config\`). ` +
          SUDO_CONFIG_CAVEAT.replace(' Enforce with any `sudo-config` is ADVISORY.', '') +
          ' Remove `sudo-config` to make enforce a boundary.'
      );
    }
    if (input.sudoRetained) {
      why.push(
        '**ADVISORY: sudo was retained** (`disable-sudo: false`), so any step could have used it to ' +
          'remove the egress controls. The policy below was applied, but this job did not run inside an enforced ' +
          'boundary. Remove `disable-sudo: false` to make enforce a boundary.'
      );
    }
    if (input.dockerRetained) {
      why.push(
        '**ADVISORY: docker was retained** (`docker: keep`; verified on the runner). Docker access is ' +
          'root-equivalent, so any step could have used it to remove the egress controls. Use `docker: remove-group` ' +
          '(what enforce does) or `docker: stop` unless the job needs docker.'
      );
    }
    md +=
      '> [!WARNING]\n' +
      '> **The boundary was weaker than it looks.**\n>\n' +
      why.map(w => `> ${w}`).join('\n>\n') +
      '\n\n';
  }

  if (enforce && !bypass.length && (groups['not-allowed'].length || filtered)) {
    const n = groups['not-allowed'].length;
    const what: string[] = [];
    if (n) what.push(`${plural(n, 'host')} not on the allowlist ${n === 1 ? 'was' : 'were'} blocked`);
    if (filtered)
      what.push(`${plural(filtered, 'request')} ${filtered === 1 ? 'was' : 'were'} refused by \`http-filter\``);
    md += '> [!IMPORTANT]\n' + `> **${what.join('; ')}.** If this job failed, this is probably why — see below.\n\n`;
  }

  if (!enforce && (suggest.length || sudoWouldBlock || sudoKeptRan)) {
    md += '> [!IMPORTANT]\n';
    if (suggest.length) {
      md += `> **Enforce would block ${plural(suggest.length, 'host')} this job used.** Add ${suggest.length === 1 ? 'it' : 'them'} to run this job under \`mode: enforce\` (review each one first):\n>\n`;
      const ref = input.actionRef?.trim() || 'v2.0.0';
      const yaml =
        `- uses: portswigger-tim/safer-runner-action@${ref} # pin an exact version or commit SHA\n  with:\n    mode: enforce\n    allowed-domains: |\n` +
        suggest.map(s => `      ${s}`).join('\n');
      md +=
        codeBlock('yaml', yaml)
          .split('\n')
          .map(l => `> ${l}`)
          .join('\n') + '\n';
    }
    if (sudoWouldBlock || sudoKeptRan) {
      if (suggest.length) md += '>\n';
      md += sudoAlert(f) + '\n';
    }
    md += '\n';
  }
  return md;
}

/** Analyze: the sudo commands enforce would block, and the suggested sudo-config (in an alert). */
function sudoAlert(f: Facts): string {
  const policy = f.input.sudoPolicy;
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

/** The scorecard, or the one-line clean verdict. */
function scorecard(f: Facts): string {
  const { enforce, groups, bypass, blockedWord, fw, platform, plat, all } = f;
  const platNote = platform.length && plat.bytes ? ` <sub>(${humanBytes(plat.bytes)} of it GitHub platform)</sub>` : '';
  const allowedLine = `${plural(f.allowed.length, 'host')} · ${plural(all.requests, 'request')} · ${humanBytes(all.bytes)}`;
  if (f.denied.length === 0 && fw.rows.length === 0) {
    return enforce
      ? `**✅ Nothing blocked.** ${allowedLine} through the proxy.\n\n`
      : `**✅ Nothing would be blocked.** ${allowedLine} through the proxy.` +
          (f.sudoWouldBlock ? '\n\n' : ' This job should run unchanged with `mode: enforce`.\n\n');
  }
  const rows: string[][] = [];
  if (bypass.length) rows.push(['🚨 **Bypass attempts**', `**${plural(bypass.length, 'host')} ${blockedWord}**`]);
  if (groups['not-allowed'].length) {
    rows.push([
      '🚫 **Not on allowlist**',
      `**${groups['not-allowed'].length} ${blockedWord}** — ${nameList(groups['not-allowed'])}`
    ]);
  }
  if (f.filterBlocks.length) {
    rows.push(['🔒 **HTTP filter**', `${plural(f.filtered, 'request')} ${blockedWord} — ${nameList(groups.filtered)}`]);
  }
  if (groups.unresolved.length) {
    rows.push([
      '❔ **Did not resolve**',
      `${groups.unresolved.length} ${blockedWord} — ${nameList(groups.unresolved)}`
    ]);
  }
  if (groups['no-name'].length) {
    rows.push(['🔢 **No hostname**', `${groups['no-name'].length} ${blockedWord} (raw IP / no SNI)`]);
  }
  if (groups.other.length) rows.push(['⚙️ **Other**', `${groups.other.length} ${blockedWord}`]);
  rows.push(['✅ **Allowed**', allowedLine + platNote]);
  if (fw.rows.length) {
    const parts = [];
    if (fw.rejected) parts.push(`${fw.rejected} rejected`);
    if (fw.logged) parts.push(`${fw.logged} allowed, not proxied`);
    const one = fw.rows.length === 1 ? ` (${destinationText(fw.rows[0].e)})` : '';
    rows.push(['🧱 **Outside the proxy**', parts.join(' · ') + one]);
  }
  return table(['', ''], [':--', ':--'], rows) + '\n\n';
}

/** A `### title (n)` table of blocked hosts; the last column is right-aligned. */
function hostSection(
  f: Facts,
  title: string,
  rows: HostSummary[],
  header: string[],
  cells: (h: HostSummary) => string[]
): string {
  const { shown, note } = capped(rows);
  return (
    `### ${title} (${rows.length})${f.enforce ? '' : ' — would be blocked'}\n\n` +
    table(
      header,
      header.map((_, i) => (i === header.length - 1 ? '--:' : ':--')),
      shown.map(cells)
    ) +
    note +
    '\n\n'
  );
}

/** Blocked, grouped by cause, attacks first: bypass attempts, not on the allowlist, refused by http-filter. */
function blockedSections(f: Facts): string {
  const { enforce, groups, bypass, suggest, filterBlocks } = f;
  const verb = enforce ? 'refused' : 'would be refused';
  let md = '';
  if (bypass.length) {
    md += hostSection(f, '🚨 Bypass attempts', bypass, ['Host', 'What happened', 'Tries'], h => [
      code(blockedName(h.name)),
      categorize(h) === 'fronting' ? frontingCell(h, enforce ? '' : 'not blocked (analyze)') : internalCell(h, verb),
      String(h.tries)
    ]);
  }
  if (groups['not-allowed'].length) {
    md += hostSection(f, '🚫 Not on the allowlist', groups['not-allowed'], ['Host', 'Seen as', 'Tries'], h => {
      const seen: string[] = [];
      if (h.reasons.includes('sni-not-allowed')) seen.push('HTTPS (SNI)');
      if (h.reasons.includes('host-not-allowed')) seen.push('plain HTTP');
      if (h.reasons.some(r => DENYLISTED.has(r))) seen.push('on the risky-subdomain denylist');
      if (f.dnsRefused.has(h.name)) seen.push('DNS also refused');
      return [code(blockedName(h.name)), seen.join(' · '), String(h.tries)];
    });
    if (enforce && suggest.length) {
      md += 'If the job needs them, add them (review each one first):\n\n';
      md += codeBlock('yaml', 'allowed-domains: |\n' + suggest.map(s => `  ${s}`).join('\n')) + '\n\n';
    }
  }
  if (filterBlocks.length) {
    const { shown, note } = capped(filterBlocks);
    md += `### 🔒 Refused by \`http-filter\` (${filterBlocks.length})${enforce ? '' : ' — would be blocked'}\n\n`;
    md += table(
      ['Host', 'Request', 'Why', 'Tries'],
      [':--', ':--', ':--', '--:'],
      shown.map(b => [
        code(b.host),
        `${code(b.method)} ${PATH_HIDDEN}`,
        FILTER_REASON_TEXT[b.reason] ?? code(b.reason),
        String(b.tries)
      ])
    );
    md += note + '\n\n';
    md +=
      '<sub>The path of a refused request is never shown: whoever sent it chose it, and it can carry data. ' +
      "If the job needs one of these requests, run it in analyze mode without that host's `http-filter` entry: " +
      'the suggested `http-filter` then covers it. Review the rule before you add it: a write is how data ' +
      'leaves.</sub>\n\n';
  }
  return md;
}

function httpFilterSuggestion(f: Facts): string {
  const { enforce, filtered } = f;
  const sug = f.input.httpFilter?.suggestion;
  if (!sug?.hosts.length || (enforce && !filtered)) return '';
  let md = `<details${filtered && !enforce ? ' open' : ''}>\n<summary>🧰 <b>Suggested <code>http-filter</code></b> — ${compressionText(sug)}</summary>\n\n`;
  md +=
    "<sub>Advisory, built from this job's intercepted traffic — never applied for you. Reads collapse to one " +
    '`"*"` line per host; write paths keep their structure, with ids and hashes as `*`; git push and fetch stay ' +
    'pinned to the repos this job used. GitHub platform hosts are left out (the built-in platform allowlist covers ' +
    'them). Add each host to `allowed-domains` too: a filter never grants access.</sub>\n\n';
  if (sug.coarse) {
    md += '**⚠️ Coarse — review.** A write rule had to start with `*`, so it allows that write on any path.\n\n';
  }
  return md + codeBlock('yaml', httpFilterYaml(sug)) + '\n\n</details>\n\n';
}

/** The rest of the blocked hosts: did not resolve, no hostname, other. */
function otherBlockedSections(f: Facts): string {
  const { groups, blockedWord } = f;
  let md = '';
  if (groups.unresolved.length) {
    md += hostSection(f, '❔ Did not resolve', groups.unresolved, ['Host', 'What happened', 'Tries'], h => [
      code(blockedName(h.name)),
      'allowed name, but the proxy could not resolve it, so nothing was sent',
      String(h.tries)
    ]);
  }
  if (groups['no-name'].length) {
    const { shown, note } = capped(groups['no-name']);
    md += `<details>\n<summary>🔢 <b>No hostname</b> — ${groups['no-name'].length} ${blockedWord} (raw IP / no SNI)</summary>\n\n`;
    md += table(
      ['Destination', 'What happened', 'Tries'],
      [':--', ':--', '--:'],
      shown.map(h => [
        code(blockedName(displayName(h))),
        h.reasons.map(r => NO_NAME_TEXT[r] ?? r).join(' · '),
        String(h.tries)
      ])
    );
    md += note + '\n\n</details>\n\n';
  }
  if (groups.other.length) {
    // unknown reasons are never dropped: show the raw code
    md += hostSection(f, '⚙️ Other', groups.other, ['Host', 'Reason', 'Tries'], h => [
      code(blockedName(h.name)),
      h.reasons.map(code).join(', '),
      String(h.tries)
    ]);
  }
  return md;
}

/** Allowed: the job's own hosts open, GitHub platform collapsed. */
function allowedSections(f: Facts): string {
  const { jobHosts, platform, plat, allowed } = f;
  let md = '';
  if (f.input.userDomains) {
    if (jobHosts.length) md += `### Allowed — this job's hosts (${jobHosts.length})\n\n` + allowedTable(jobHosts);
    if (platform.length) {
      md += `<details>\n<summary>🐙 <b>GitHub platform</b> — ${plural(platform.length, 'host')} · ${plural(plat.requests, 'request')} · ${humanBytes(plat.bytes)} · expected for every job</summary>\n\n`;
      md += allowedTable(platform) + '</details>\n\n';
    }
  } else if (allowed.length) {
    md += `### Allowed (${allowed.length})\n\n` + allowedTable(allowed);
  }
  return md;
}

/** Diagnostics: one collapsed section, every part states its result. */
function diagnostics(f: Facts): string {
  const { input, enforce, fw } = f;
  const diag: string[] = [];
  let body = '';
  if (input.selfTests.length) {
    diag.push(`self-tests ${f.selfOk}/${input.selfTests.length} ${f.selfFailed.length ? '✗' : '✓'}`);
    body += '**Self-tests**\n\n';
    body +=
      input.selfTests
        .map(t => `- ${t.ok ? '✅' : '❌'} ${code(t.name)} — ${t.detail.replace(/[<>|`*_[\]]/g, '\\$&')}`)
        .join('\n') + '\n\n';
  } else {
    diag.push('self-tests not run');
  }
  if (fw.rows.length) {
    const p = [];
    if (fw.rejected) p.push(`${fw.rejected} non-proxy ${fw.rejected === 1 ? 'destination' : 'destinations'} rejected`);
    if (fw.logged) p.push(`${fw.logged} allowed outside the proxy`);
    diag.push(p.join(' · '));
    const { shown, note } = capped(fw.rows);
    body +=
      '**Outside the proxy** <sub>(only TCP 80/443 is proxied; new connections only; logging rate-limited to 60/min)</sub>\n\n';
    body += table(
      ['Destination', 'Proto', 'Likely', 'UID', 'Packets', 'Result'],
      [':--', ':--', ':--', '--:', '--:', ':--'],
      shown.map(({ e, n }) => [
        code(`${e.dst}:${e.dport}`),
        e.proto,
        PORT_NAMES[e.dport] ?? '',
        e.uid,
        String(n),
        e.prefix === 'SaferRunner-Drop' ? '❌ rejected' : '⚠️ allowed (not proxied)'
      ])
    );
    body += note + '\n\n';
  } else {
    diag.push('nothing bypassed the proxy');
  }
  if (input.platformEndpoints) {
    diag.push(`${plural(input.platformEndpoints, 'platform endpoint')} auto-allowed`);
    body +=
      `**http-filter** — ${plural(input.platformEndpoints, 'GitHub platform endpoint')} auto-allowed on filtered ` +
      'hosts by the built-in platform allowlist (`allow-github-platform: false` turns it off)\n\n';
  }
  if (input.dnsRefused.length) {
    diag.push(plural(input.dnsRefused.length, enforce ? 'DNS refusal' : 'DNS lookup enforce would refuse'));
    const shownAbove = new Set(f.denied.map(h => h.name));
    const rest = input.dnsRefused.filter(d => !shownAbove.has(d.toLowerCase()));
    const { shown, note } = capped(rest);
    body += `**DNS ${enforce ? 'refused' : 'would refuse'}** (${input.dnsRefused.length}): `;
    body += rest.length
      ? shown.map(n => code(blockedName(n))).join(', ') + note
      : 'all of them are listed with their blocked connection above';
    body += '\n\n';
  }
  if (input.sudo) {
    const { ran, refused, internal } = input.sudo;
    diag.push(
      (ran.length === 0 ? 'no workflow sudo' : `workflow ran ${plural(ran.length, 'sudo command')}`) +
        (internal.length ? ` (${internal.length} by Safer Runner)` : '') +
        (refused.length ? ` · ${plural(refused.length, 'sudo attempt')} refused` : '') +
        (!enforce && f.sudoWouldBlock ? ` · enforce would block ${f.sudoWouldBlock}` : '')
    );
    const lines = (cmds: SudoCommand[]) =>
      cmds
        .slice(0, 50)
        .map(
          c =>
            `$ sudo ${c.targetUser && c.targetUser !== 'root' ? `-u ${c.targetUser} ` : ''}${c.command}${c.args ? ` ${c.args}` : ''}`
        )
        .join('\n') + (cmds.length > 50 ? `\n# ... +${cmds.length - 50} more (job log)` : '');
    body += `**Sudo** — the workflow ran ${ran.length ? plural(ran.length, 'command') : 'none'}`;
    body += internal.length ? `; Safer Runner itself ran ${internal.length} (setup, integrity checks)` : '';
    body += ran.length ? ':\n\n' + codeBlock('console', lines(ran)) + '\n\n' : '.\n\n';
    if (refused.length) {
      body += `Refused by sudo (${refused.length}):\n\n` + codeBlock('console', lines(refused)) + '\n\n';
    }
    const wouldBlock = enforce ? [] : (input.sudoPolicy?.wouldBlock ?? []);
    if (wouldBlock.length) {
      body += `Enforce would block (${wouldBlock.length}):\n\n` + codeBlock('console', lines(wouldBlock)) + '\n\n';
    }
  }
  if (input.docker) {
    const { requested, access } = input.docker;
    diag.push(
      access === 'retained' ? 'docker retained' : access === 'group-removed' ? 'docker removed ✓' : 'docker stopped ✓'
    );
    body += `**Docker** — \`docker: ${requested}\`; verified at setup: ${DOCKER_ACCESS_TEXT[access] ?? access}\n\n`;
  }
  if (input.integrity) {
    const s = input.integrity.status;
    diag.push(s === 'verified' ? 'config unchanged ✓' : s === 'tampered' ? 'config CHANGED ⚠️' : 'config: no baseline');
    body += `**Config file tamper check** (advisory) — ${s === 'verified' ? 'all verified' : s === 'tampered' ? '⚠️ CHANGED' : 'no baseline'}\n\n`;
    body += input.integrity.body + '\n\n';
    body += `${ADVISORY_REPORT_NOTE}\n\n`;
  }
  for (const s of input.extraSections ?? []) if (s) body += s + '\n\n';
  return `<details>\n<summary>🔧 <b>Diagnostics</b> — ${diag.join(' · ')}</summary>\n\n${body}</details>\n\n`;
}

function footer(f: Facts): string {
  const now = (f.input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  return `<sub>${f.mode} · job ${code(f.input.job)} · ${now} UTC · [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2</sub>\n`;
}

export function buildReport(input: ReportInput): string {
  const f = facts(input);
  return [
    titleAndChips(f),
    alerts(f),
    scorecard(f),
    blockedSections(f),
    httpFilterSuggestion(f),
    otherBlockedSections(f),
    allowedSections(f),
    containerSection(input.containers ?? [], f.mode),
    diagnostics(f),
    footer(f)
  ].join('');
}
