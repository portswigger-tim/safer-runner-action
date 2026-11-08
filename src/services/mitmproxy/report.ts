/**
 * The proxy's part of the job summary, from the flow log: what it blocked (or would block), worst
 * first, the http-filter refusals, and the job's allowed hosts; the GitHub baseline it trusts goes
 * under Runner System. In analyze it suggests `allowed-domains` (and `http-filter`). DENIED first
 * and in full; anything that has to be cut is said so explicitly (review M6).
 */

import { compilePattern, expandPattern, matchesAny, validatePattern } from '../../policy';
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
import { httpFilterValue, httpFilterYaml, type HttpFilterReport } from './http-filter';
import { PATH_HIDDEN, needsRedaction } from '../../report/redact';
import { capped, code, codeBlock, humanBytes, plural, table } from '../../report/markdown';
import {
  VERDICT_ICON,
  refusedVerdict,
  type Alert,
  type ReportContext,
  type RunnerSystem,
  type ScoreRow,
  type Section,
  type Suggestion
} from '../../report/section';

export interface ProxyObserved {
  hosts: HostSummary[];
  /**
   * The job's own `allowed-domains` + `passthrough-domains` patterns. Allowed traffic to
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as the GitHub
   * baseline. Undefined: no split.
   */
  userDomains?: string[];
  /** the job's `allowed-domains` entries alone: the suggested value keeps them */
  allowedDomains?: string[];
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter); undefined: no http-filter section */
  httpFilter?: HttpFilterReport;
  /** the job sets `http-filter`: a suggested one goes in the block, as its update */
  httpFilterSet?: boolean;
  /** GitHub platform endpoints the built-in list auto-allowed on filtered hosts (policy.json) */
  platformEndpoints?: number;
}

export interface ProxySection extends Section {
  /** refused names shown here (the DNS part leaves them out) */
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
  blockedWord: string;
  denied: HostSummary[];
  allowed: HostSummary[];
  groups: Record<Category, HostSummary[]>;
  /** fronting + internal: the attacks */
  bypass: HostSummary[];
  jobHosts: HostSummary[];
  platform: HostSummary[];
  job: { requests: number; bytes: number };
  plat: { requests: number; bytes: number };
  /** names to suggest for `allowed-domains` */
  suggest: string[];
  filterBlocks: HttpFilterReport['blocks'];
  /** requests the http-filter refused */
  filtered: number;
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
    blockedWord: enforce ? 'blocked' : 'would be blocked',
    denied,
    allowed,
    groups,
    bypass: [...groups.fronting, ...groups.internal],
    jobHosts,
    platform,
    job: totals(jobHosts),
    plat: totals(platform),
    suggest: suggestedAllowlist(denied),
    filterBlocks,
    filtered: filterBlocks.reduce((a, b) => a + b.tries, 0)
  };
}

const OTHER_GROUPS: [Category, string][] = [
  ['unresolved', 'did not resolve'],
  ['no-name', 'no hostname'],
  ['other', 'other']
];

function score(f: Facts): ScoreRow[] {
  const { groups, bypass, blockedWord } = f;
  const refused = refusedVerdict(f.ctx);
  const rows: ScoreRow[] = [];
  if (bypass.length) {
    rows.push({
      verdict: refused,
      area: 'Network',
      text: `**${plural(bypass.length, 'bypass attempt')} ${blockedWord}**`
    });
  }
  if (groups['not-allowed'].length) {
    const n = groups['not-allowed'].length;
    rows.push({
      verdict: refused,
      area: 'Network',
      text: `${plural(n, 'host')} not on the allowlist ${blockedWord}: ${nameList(groups['not-allowed'])}`
    });
  }
  const others = OTHER_GROUPS.filter(([g]) => groups[g].length);
  if (others.length) {
    const n = others.reduce((a, [g]) => a + groups[g].length, 0);
    rows.push({
      verdict: refused,
      area: 'Network',
      text: `${plural(n, 'more host')} ${blockedWord} (${others.map(([, what]) => what).join(', ')})`
    });
  }
  if (f.filterBlocks.length) {
    rows.push({
      verdict: refused,
      area: 'HTTP filter',
      text: `${plural(f.filtered, 'request')} ${blockedWord}: ${nameList(groups.filtered)}`
    });
  }
  const hosts = f.o.userDomains
    ? `${plural(f.jobHosts.length, 'host')} beyond GitHub`
    : plural(f.allowed.length, 'host');
  rows.push({
    verdict: 'allowed',
    area: 'Network',
    text: `${hosts} · ${plural(f.job.requests, 'request')} · ${humanBytes(f.job.bytes)}`
  });
  return rows;
}

function alerts(f: Facts): Alert[] {
  const { enforce, groups, bypass, filtered } = f;
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
        ? `**Bypass attempts to ${plural(bypass.length, 'host')} were blocked** (${kinds.join(', ')}). ` +
          'A normal build does not do this: check the steps that ran.'
        : `**Bypass attempts to ${plural(bypass.length, 'host')} were seen** (${kinds.join(', ')}). Enforce blocks ` +
          'them. A normal build does not do this: check the steps that ran.'
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
      text: `**${what.join('; ')}.** If this job failed, this is probably why: see Network.`
    });
  }
  return out;
}

const KEEP_ENTRIES = 'keep your existing allowed-domains entries too';

/**
 * The job's own entries to repeat in the suggestion: only valid patterns, never one that looks
 * like data (an entry from an unmasked variable can be an internal name, and a masked secret
 * shows as ***). `held` is true when any was held back: the block then says to keep them.
 */
function keptEntries(entries: string[]): { kept: string[]; held: boolean } {
  const kept: string[] = [];
  let held = false;
  for (const e of entries) {
    try {
      if (e.includes('***') || expandPattern(e).some(p => needsRedaction(validatePattern(p)))) {
        throw new Error('not repeated');
      }
      if (!kept.includes(e)) kept.push(e);
    } catch {
      held = true;
    }
  }
  return { kept, held };
}

function suggestions(f: Facts): Suggestion[] {
  if (f.enforce) return [];
  const out: Suggestion[] = [];
  if (f.suggest.length) {
    // the job's entries as setup recorded them; when that record is missing, say to keep them
    const { kept, held } = f.o.allowedDomains ? keptEntries(f.o.allowedDomains) : { kept: [], held: true };
    const add = f.suggest.filter(n => !kept.includes(n));
    out.push({
      input: 'allowed-domains',
      value: [...kept, ...add].join('\n') + '\n',
      ...(held ? { comment: KEEP_ENTRIES } : {})
    });
  }
  const sug = f.o.httpFilter?.suggestion;
  if (sug?.hosts.length) {
    out.push({
      input: 'http-filter',
      value: httpFilterValue(sug),
      optional: !f.o.httpFilterSet,
      label:
        `${plural(sug.requests, 'request')} → ${plural(sug.rules, 'rule')}` +
        (sug.specific ? `; ${plural(sug.specific, 'write endpoint')} kept specific` : '')
    });
  }
  return out;
}

function notes(f: Facts): string[] {
  if (f.enforce) return [];
  const out: string[] = [];
  const left = f.groups['not-allowed'].length - f.suggest.length;
  if (left > 0) {
    out.push(
      `${plural(left, 'blocked name')} not suggested (on the risky-subdomain denylist, or a name that looks like data)`
    );
  }
  if (f.suggest.length) out.push("GitHub's own hosts are trusted automatically and are not listed");
  if (f.o.httpFilter?.suggestion?.coarse) {
    out.push(
      'the suggested `http-filter` has a write rule that starts with `*`, so it allows that write on any path: review it'
    );
  }
  return out;
}

// ---------------------------------------------------------------- detail

function hostCell(h: HostSummary): string {
  let c = code(blockedName(displayName(h)));
  if (h.kinds.includes('passthrough')) c += ' <sub>SNI only</sub>';
  else if (h.kinds.length === 1 && h.kinds[0] === 'http') c += ' <sub>plain HTTP</sub>';
  return c;
}

/** What happened to a refused host, in words; evidence in a <sub> line. */
function whatHappened(h: HostSummary): string {
  const cat = categorize(h);
  if (cat === 'fronting') {
    const what = h.reasons.includes('host-sni-mismatch')
      ? 'Host/SNI mismatch (domain fronting)'
      : 'Conflicting Host / authority';
    const notes: string[] = [];
    if (h.snis.length) notes.push(`inside TLS for ${h.snis.map(n => code(blockedName(n))).join(', ')}`);
    if (h.reasons.some(r => NOT_LISTED.has(r))) notes.push('also not on the allowlist');
    if (h.dsts.length) notes.push(`dialled ${h.dsts.map(code).join(', ')}`);
    return what + (notes.length ? `<br><sub>${notes.join(' · ')}</sub>` : '');
  }
  if (cat === 'internal') {
    const ips = h.upstreamIps.map(ip => `${code(ip)} (${addressClass(ip)})`).join(', ');
    return `Internal address${ips ? ` → ${ips}` : ''}`;
  }
  if (cat === 'not-allowed') {
    if (h.reasons.some(r => DENYLISTED.has(r))) return 'On the risky-subdomain denylist';
    const plain = h.reasons.includes('host-not-allowed') && !h.reasons.includes('sni-not-allowed');
    return `Not on the allowlist${plain ? ' (plain HTTP)' : ''}`;
  }
  if (cat === 'unresolved') return 'Did not resolve; nothing was sent';
  if (cat === 'no-name') return h.reasons.map(r => NO_NAME_TEXT[r] ?? r).join(' · ');
  // unknown reasons are never dropped: show the raw code
  return `Refused: ${h.reasons.map(code).join(', ')}`;
}

function blockedTable(f: Facts): string {
  const { groups } = f;
  const rows = [
    ...groups.fronting,
    ...groups.internal,
    ...groups['not-allowed'],
    ...groups.unresolved,
    ...groups['no-name'],
    ...groups.other
  ];
  if (!rows.length) return '';
  const icon = VERDICT_ICON[refusedVerdict(f.ctx)];
  const { shown, note } = capped(rows);
  return (
    `**${f.enforce ? 'Blocked' : 'Would be blocked'}**\n\n` +
    table(
      ['', 'Host', 'What happened', 'Tries'],
      [':-:', ':--', ':--', '--:'],
      shown.map(h => [icon, code(blockedName(displayName(h))), whatHappened(h), String(h.tries)])
    ) +
    note +
    '\n\n'
  );
}

function filterTable(f: Facts): string {
  if (!f.filterBlocks.length) return '';
  const icon = VERDICT_ICON[refusedVerdict(f.ctx)];
  const { shown, note } = capped(f.filterBlocks);
  return (
    `**${f.enforce ? 'Refused' : 'Would be refused'} by \`http-filter\`**\n\n` +
    table(
      ['', 'Host', 'Request', 'Why', 'Tries'],
      [':-:', ':--', ':--', ':--', '--:'],
      shown.map(b => [
        icon,
        code(b.host),
        `${code(b.method)} ${PATH_HIDDEN}`,
        FILTER_REASON_TEXT[b.reason] ?? code(b.reason),
        String(b.tries)
      ])
    ) +
    note +
    '\n\n<sub>The path of a refused request is never shown: whoever sent it chose it, and it can carry data. ' +
    "If the job needs one of these requests, run it in analyze mode without that host's `http-filter` entry: " +
    'the suggested `http-filter` then covers it. Review the rule before you add it: a write is how data ' +
    'leaves.</sub>\n\n'
  );
}

/** Enforce: what to add if the job needs it (the likely reason it failed). Review first. */
function enforceFixes(f: Facts): string {
  if (!f.enforce) return '';
  let md = '';
  if (f.suggest.length) {
    md += `If the job needs ${f.suggest.length === 1 ? 'it' : 'them'}, add ${f.suggest.length === 1 ? 'it' : 'them'} (review first):\n\n`;
    md += codeBlock('yaml', 'allowed-domains: |\n' + f.suggest.map(s => `  ${s}`).join('\n')) + '\n\n';
  }
  const sug = f.o.httpFilter?.suggestion;
  if (f.filtered && sug?.hosts.length) {
    md += `<details>\n<summary>A <code>http-filter</code> built from this job's allowed requests (${plural(sug.rules, 'rule')}; review first)</summary>\n\n`;
    md += codeBlock('yaml', httpFilterYaml(sug)) + '\n\n</details>\n\n';
  }
  return md;
}

function allowedTable(rows: HostSummary[], title: string): string {
  const { shown, note } = capped([...rows].sort(byData));
  let md =
    `${title}\n\n` +
    table(
      ['', 'Host', 'Requests', 'Data', 'Responses'],
      [':-:', ':--', '--:', '--:', ':--'],
      shown.map(h => [VERDICT_ICON.allowed, hostCell(h), requestsCell(h), dataCell(h), statusSummary(h)])
    ) +
    note +
    '\n\n';
  if (shown.some(h => h.kinds.includes('passthrough'))) {
    md += '<sub>SNI only = checked by TLS name, not decrypted: no request or byte counts.</sub>\n\n';
  }
  return md;
}

function body(f: Facts): string {
  let md = blockedTable(f) + filterTable(f) + enforceFixes(f);
  if (f.jobHosts.length)
    md += allowedTable(f.jobHosts, f.o.userDomains ? "**Allowed: this job's hosts**" : '**Allowed**');
  return md || 'No traffic went through the proxy.\n\n';
}

function runnerSystem(f: Facts): RunnerSystem[] {
  const out: RunnerSystem[] = [];
  if (f.platform.length) {
    out.push({
      summary: `GitHub baseline ${plural(f.platform.length, 'host')}`,
      body: allowedTable(
        f.platform,
        `**GitHub baseline** (trusted automatically) · ${plural(f.plat.requests, 'request')} · ${humanBytes(f.plat.bytes)}`
      )
    });
  }
  if (f.o.platformEndpoints) {
    out.push({
      summary: `${plural(f.o.platformEndpoints, 'platform endpoint')} auto-allowed`,
      body:
        `**http-filter**: ${plural(f.o.platformEndpoints, 'GitHub platform endpoint')} auto-allowed on filtered ` +
        'hosts by the built-in platform allowlist (`allow-github-platform: false` turns it off).\n\n'
    });
  }
  return out;
}

/** Full lists in the job log, so nothing is ever silently dropped from the summary (names redacted the same way). */
export function jobLog(o: Pick<ProxyObserved, 'hosts' | 'httpFilter'>): string[] {
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
  return {
    score: score(f),
    alerts: alerts(f),
    suggestions: suggestions(f),
    notes: notes(f),
    advisory: [],
    body: body(f),
    runnerSystem: runnerSystem(f),
    deniedNames: f.denied.map(h => h.name)
  };
}
