/**
 * The proxy's part of the job summary, from the flow log: blocked hosts grouped by cause (attacks
 * first), the http-filter refusals and its suggestion, allowed traffic (the job's own hosts open,
 * GitHub platform collapsed). DENIED first and in full; anything that has to be cut is said so
 * explicitly (review M6).
 */

import { compilePattern, expandPattern, matchesAny } from '../../policy';
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
} from './flows';
import { httpFilterYaml, type HttpFilterReport, type HttpFilterSuggestion } from './http-filter';
import { PATH_HIDDEN } from '../../report/redact';
import { capped, code, codeBlock, humanBytes, plural, table } from '../../report/markdown';
import type { Alert, ReportContext, Section } from '../../report/section';

export interface ProxyObserved {
  hosts: HostSummary[];
  /** names the resolver refused: a blocked host's row says so (the setup self-test excluded) */
  dnsRefused: string[];
  /**
   * The job's own `allowed-domains` + `passthrough-domains` patterns. Allowed traffic to
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as GitHub
   * platform traffic. Undefined: no split.
   */
  userDomains?: string[];
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter); undefined: no http-filter section */
  httpFilter?: HttpFilterReport;
  /** GitHub platform endpoints the built-in list auto-allowed on filtered hosts (policy.json) */
  platformEndpoints?: number;
}

export interface ProxySection extends Section {
  /** `N hosts · N requests · N B` of allowed traffic */
  allowedLine: string;
  /** refused names shown here (the DNS diagnostics leave them out) */
  deniedNames: string[];
}

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

/** Everything the parts share, worked out once from the observations. */
interface Facts {
  o: ProxyObserved;
  ctx: ReportContext;
  enforce: boolean;
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
  /** names to suggest for `allowed-domains` */
  suggest: string[];
  filterBlocks: HttpFilterReport['blocks'];
  /** requests the http-filter refused */
  filtered: number;
  /** denied hosts, less the ones only the http-filter refused */
  hostsDenied: number;
}

function facts(o: ProxyObserved, ctx: ReportContext): Facts {
  const { enforce } = ctx;
  const denied = o.hosts.filter(h => DENIED.has(h.verdict));
  const allowed = o.hosts.filter(h => !DENIED.has(h.verdict));
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
  if (o.userDomains) {
    const user = compileUserPatterns(o.userDomains);
    jobHosts = allowed.filter(h => matchesAny(h.name, user));
    platform = allowed.filter(h => !jobHosts.includes(h));
  }

  const filterBlocks = o.httpFilter?.blocks ?? [];
  return {
    o,
    ctx,
    enforce,
    dnsRefused: new Set(o.dnsRefused.map(n => n.toLowerCase())),
    blockedWord: enforce ? 'blocked' : 'would be blocked',
    denied,
    allowed,
    groups,
    bypass: [...groups.fronting, ...groups.internal],
    jobHosts,
    platform,
    all: totals(allowed),
    plat: totals(platform),
    suggest: suggestedAllowlist(denied),
    filterBlocks,
    filtered: filterBlocks.reduce((a, b) => a + b.tries, 0),
    hostsDenied: denied.length - groups.filtered.length
  };
}

function chips(f: Facts): string[] {
  if (f.enforce) return [];
  const out: string[] = [];
  if (f.hostsDenied) out.push(`${plural(f.hostsDenied, 'host')} would be blocked`);
  if (f.filtered) out.push(`${plural(f.filtered, 'request')} the http-filter would refuse`);
  return out;
}

function alerts(f: Facts): Alert[] {
  const { enforce, groups, bypass, filtered, suggest } = f;
  const out: Alert[] = [];
  if (bypass.length) {
    const kinds = [];
    if (groups.fronting.length) kinds.push(plural(groups.fronting.length, 'Host/SNI spoof'));
    if (groups.internal.length) {
      kinds.push(
        `${plural(groups.internal.length, 'name')} that point${groups.internal.length === 1 ? 's' : ''} at internal addresses`
      );
    }
    out.push({
      kind: 'CAUTION',
      text: enforce
        ? `**Bypass attempts to ${plural(bypass.length, 'host')} were blocked** — ${kinds.join(' and ')}.\n` +
          '> Nothing in a normal build does this. Check the steps that ran before the post step.'
        : `**Bypass attempts to ${plural(bypass.length, 'host')} were seen and NOT blocked** (analyze mode) — ${kinds.join(' and ')}.\n` +
          '> Enforce would block them. Nothing in a normal build does this: check the steps that ran.'
    });
  }

  if (enforce && !bypass.length && (groups['not-allowed'].length || filtered)) {
    const n = groups['not-allowed'].length;
    const what: string[] = [];
    if (n) what.push(`${plural(n, 'host')} not on the allowlist ${n === 1 ? 'was' : 'were'} blocked`);
    if (filtered)
      what.push(`${plural(filtered, 'request')} ${filtered === 1 ? 'was' : 'were'} refused by \`http-filter\``);
    out.push({
      kind: 'IMPORTANT',
      text: `**${what.join('; ')}.** If this job failed, this is probably why — see below.`
    });
  }

  if (!enforce && suggest.length) {
    let md = `> **Enforce would block ${plural(suggest.length, 'host')} this job used.** Add ${suggest.length === 1 ? 'it' : 'them'} to run this job under \`mode: enforce\` (review each one first):\n>\n`;
    const ref = f.ctx.actionRef?.trim() || 'v2.0.0';
    const yaml =
      `- uses: portswigger-tim/safer-runner-action@${ref} # pin an exact version or commit SHA\n  with:\n    mode: enforce\n    allowed-domains: |\n` +
      suggest.map(s => `      ${s}`).join('\n');
    md +=
      codeBlock('yaml', yaml)
        .split('\n')
        .map(l => `> ${l}`)
        .join('\n') + '\n';
    out.push({ kind: 'IMPORTANT', text: md, quoted: true });
  }
  return out;
}

/** Scorecard rows: each cause, then allowed traffic. */
function score(f: Facts, allowedLine: string): string[][] {
  const { groups, bypass, blockedWord, platform, plat } = f;
  const platNote = platform.length && plat.bytes ? ` <sub>(${humanBytes(plat.bytes)} of it GitHub platform)</sub>` : '';
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
  return rows;
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
  const sug = f.o.httpFilter?.suggestion;
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
  if (f.o.userDomains) {
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

/** The http-filter platform allowlist, when it allowed anything. */
function diagnostics(o: ProxyObserved): Section['diagnostics'] {
  if (!o.platformEndpoints) return [];
  return [
    {
      summary: `${plural(o.platformEndpoints, 'platform endpoint')} auto-allowed`,
      body:
        `**http-filter** — ${plural(o.platformEndpoints, 'GitHub platform endpoint')} auto-allowed on filtered ` +
        'hosts by the built-in platform allowlist (`allow-github-platform: false` turns it off)\n\n'
    }
  ];
}

/** Full lists in the job log, so nothing is ever silently dropped from the summary (names redacted the same way). */
function jobLog(o: ProxyObserved): string[] {
  return [
    ...o.hosts.map(
      h =>
        `${h.verdict.padEnd(11)} ${blockedName(h.name)} conns=${h.connections} reqs=${h.requests} tries=${h.tries} ${h.reasons.join(',')}`
    ),
    ...(o.httpFilter?.blocks ?? []).map(
      b => `${b.verdict.padEnd(11)} http-filter ${b.host} ${b.method} ${PATH_HIDDEN} tries=${b.tries} ${b.reason}`
    )
  ];
}

export function report(o: ProxyObserved, ctx: ReportContext): ProxySection {
  const f = facts(o, ctx);
  const allowedLine = `${plural(f.allowed.length, 'host')} · ${plural(f.all.requests, 'request')} · ${humanBytes(f.all.bytes)}`;
  return {
    chips: chips(f),
    alerts: alerts(f),
    score: score(f, allowedLine),
    blocking: f.denied.length > 0,
    body: blockedSections(f) + httpFilterSuggestion(f) + otherBlockedSections(f) + allowedSections(f),
    diagnostics: diagnostics(o),
    jobLog: jobLog(o),
    advisory: '',
    allowedLine,
    deniedNames: f.denied.map(h => h.name)
  };
}
