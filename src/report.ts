/**
 * v2 job-summary report built from the proxy flow log (+ firewall and DNS logs).
 * DENIED first and in full; anything that has to be cut is said so explicitly (review M6).
 */

import { ipOf, type FlowRecord } from './flowlog';
import { compilePattern, expandPattern, isIpLiteral, matchesAny, type Mode } from './policy';
import type { SudoCommand, SudoUsage } from './parsers/sudo-parser';

export interface HostSummary {
  name: string;
  /** worst verdict seen for this name: BLOCK > WOULD_BLOCK > PASSTHROUGH > INTERCEPT/ALLOW */
  verdict: string;
  reasons: string[];
  layers: string[];
  /** intercept | passthrough | http | tls */
  kinds: string[];
  /** distinct client connections that reached a TLS or upstream decision for this name */
  connections: number;
  requests: number;
  /** denied rows: distinct attempts (one refused connection counts once, however many records) */
  tries: number;
  reqBytes: number;
  respBytes: number;
  statuses: Record<string, number>;
  /** IPs the client dialled (repoint ignores them: evidence only) */
  dsts: string[];
  /** TLS names (SNI) that carried this Host: the domain-fronting evidence */
  snis: string[];
  /** internal addresses the upstream IP guard refused behind this name */
  upstreamIps: string[];
}

const RANK: Record<string, number> = { BLOCK: 4, WOULD_BLOCK: 3, PASSTHROUGH: 2, INTERCEPT: 1, ALLOW: 1 };
const MAX_ROWS = 300;
const MAX_LIST = 5;
const DECISIONS = new Set(['tls', 'http', 'https', 'upstream']);
const DENIED = new Set<string | undefined>(['BLOCK', 'WOULD_BLOCK']);

function nameOf(r: FlowRecord): string {
  return (r.ev === 'tls' ? r.sni : r.host || r.sni) || `(no name) ${r.dst ?? ''}`.trim();
}

/** The name the proxy connects upstream for (what the upstream IP guard checks). */
function targetOf(r: FlowRecord): string {
  const t = r.ev === 'tls' || r.ev === 'https' ? r.sni : r.host;
  return t && !isIpLiteral(t) ? t : '';
}

function addUnique(list: string[], v: string | undefined | null): void {
  if (v && !list.includes(v)) list.push(v);
}

interface Conn {
  name: string;
  /** set when the upstream IP guard refused this connection's target */
  refused?: FlowRecord;
}

/**
 * Tie records to client connections. The flow log has one record per decision: a TLS
 * ClientHello, each HTTP request, and an `upstream` record when the IP guard refuses the
 * upstream. A ClientHello for an allowlisted name is logged as INTERCEPT/PASSTHROUGH *before*
 * the guard runs, so without this a refused connection also showed up as allowed traffic.
 * Connections are keyed by client address; a new ClientHello or a different target name
 * starts a new one (client ports get reused over a long job).
 */
function assignConnections(records: FlowRecord[]): (Conn | undefined)[] {
  const open = new Map<string, Conn>();
  return records.map(r => {
    if (!DECISIONS.has(r.ev) || !r.verdict) return undefined;
    const name = targetOf(r);
    let c = r.client ? open.get(r.client) : undefined;
    if (!c || r.ev === 'tls' || c.name !== name) {
      c = { name };
      if (r.client) open.set(r.client, c);
    }
    if (r.ev === 'upstream' && DENIED.has(r.verdict)) c.refused = r;
    return c;
  });
}

function emptySummary(name: string, verdict: string): HostSummary {
  return {
    name,
    verdict,
    reasons: [],
    layers: [],
    kinds: [],
    connections: 0,
    requests: 0,
    tries: 0,
    reqBytes: 0,
    respBytes: 0,
    statuses: {},
    dsts: [],
    snis: [],
    upstreamIps: []
  };
}

/**
 * One row per (name, denied?): a host can have both refused attempts (e.g. a fronting try
 * with its name in the Host header) and allowed traffic; neither should hide the other.
 * Anything on a connection the upstream IP guard refused counts as denied, never allowed,
 * so allowed rows and totals only describe traffic that really left the runner.
 */
export function summarizeFlows(records: FlowRecord[]): HostSummary[] {
  const conns = assignConnections(records);
  const byKey = new Map<string, HostSummary>();
  // per row: connection -> [refused at connection level, denied requests]
  const attempts = new Map<HostSummary, Map<Conn, [boolean, number]>>();
  const seenConns = new Map<HostSummary, Set<Conn>>();

  records.forEach((rec, i) => {
    const conn = conns[i];
    if (!conn || !rec.verdict) return;
    let r = rec;
    if (conn.refused && r.ev !== 'upstream' && !DENIED.has(r.verdict)) {
      // allowed by name, then refused upstream: report it under the refusal
      r = { ...r, verdict: conn.refused.verdict, reason: conn.refused.reason, layer: conn.refused.layer };
    }
    const name = nameOf(r);
    const denied = DENIED.has(r.verdict as string);
    const key = `${denied ? 'D' : 'A'} ${name}`;
    let h = byKey.get(key);
    if (!h) {
      h = emptySummary(name, r.verdict as string);
      byKey.set(key, h);
      attempts.set(h, new Map());
      seenConns.set(h, new Set());
    }
    if ((RANK[r.verdict as string] ?? 0) > (RANK[h.verdict] ?? 0)) h.verdict = r.verdict as string;
    if (denied) {
      addUnique(h.reasons, r.reason);
      addUnique(h.layers, r.layer as string);
    }
    const isConnRecord = r.ev === 'tls' || r.ev === 'upstream';
    if (isConnRecord) seenConns.get(h)!.add(conn);
    if (r.ev === 'upstream') {
      // dst on an upstream record is the address the name resolved to, not what was dialled
      if (h.upstreamIps.length < MAX_LIST) addUnique(h.upstreamIps, ipOf(r.dst));
    } else if (r.ev === 'tls') {
      addUnique(h.kinds, r.passthrough ? 'passthrough' : denied ? 'tls' : 'intercept');
    } else {
      h.requests++;
      h.reqBytes += r.req_bytes ?? 0;
      h.respBytes += r.resp_bytes ?? 0;
      if (r.status !== undefined) h.statuses[String(r.status)] = (h.statuses[String(r.status)] ?? 0) + 1;
      if (r.ev === 'http') addUnique(h.kinds, 'http');
      if (r.ev === 'https' && r.sni && r.sni !== r.host && h.snis.length < MAX_LIST) addUnique(h.snis, r.sni);
    }
    if (r.ev !== 'upstream' && r.dst && h.dsts.length < MAX_LIST) addUnique(h.dsts, ipOf(r.dst));
    if (denied) {
      const a = attempts.get(h)!.get(conn) ?? [false, 0];
      if (isConnRecord) a[0] = true;
      else a[1]++;
      attempts.get(h)!.set(conn, a);
    }
  });

  for (const h of byKey.values()) {
    h.connections = seenConns.get(h)!.size;
    for (const [atConn, reqs] of attempts.get(h)!.values()) h.tries += Math.max(atConn ? 1 : 0, reqs);
  }
  return Array.from(byKey.values()).sort(
    (a, b) => (RANK[b.verdict] ?? 0) - (RANK[a.verdict] ?? 0) || a.name.localeCompare(b.name)
  );
}

export interface FirewallEvent {
  prefix: string;
  proto: string;
  /** source address: a container's address for the container prefixes */
  src: string;
  dst: string;
  dport: string;
  uid: string;
}

/** Container egress (FORWARD via DOCKER-USER) firewall prefixes. */
const CONTAINER_PREFIXES = new Set(['SaferRunner-CDrop', 'SaferRunner-CEgress']);
const REJECT_PREFIXES = new Set(['SaferRunner-Drop', 'SaferRunner-CDrop']);

/** Parse kernel LOG lines written by our filter chain (see firewall.ts). */
export function parseFirewallLog(text: string): FirewallEvent[] {
  const out: FirewallEvent[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/(SaferRunner-\w+):/);
    if (!m) continue;
    const field = (k: string) => line.match(new RegExp(`\\b${k}=(\\S*)`))?.[1] ?? '';
    out.push({
      prefix: m[1],
      proto: field('PROTO'),
      src: field('SRC'),
      dst: field('DST'),
      dport: field('DPT'),
      uid: field('UID')
    });
  }
  return out;
}

// ---------------------------------------------------------------- classification

/** Why a host was blocked, most severe first. A host goes in its most severe category only. */
export type Category = 'fronting' | 'internal' | 'not-allowed' | 'unresolved' | 'no-name' | 'other';

const FRONTING = new Set(['host-sni-mismatch', 'authority-host-mismatch']);
const NOT_LISTED = new Set(['sni-not-allowed', 'host-not-allowed']);
const DENYLISTED = new Set(['sni-denied', 'host-denied']);
const NO_NAME = new Set(['no-sni', 'ip-literal-sni', 'ip-literal-host', 'no-host']);

/**
 * `upstream-unresolved` is only called an attack when dnsmasq logged that it dropped the
 * name's answer as a DNS-rebind (a private address); otherwise it is just a name that did
 * not resolve - calling a typo an attack would cost the report its credibility.
 */
export function categorize(h: HostSummary, rebind: ReadonlySet<string> = new Set()): Category {
  const r = h.reasons;
  if (r.some(x => FRONTING.has(x))) return 'fronting';
  if (r.includes('upstream-ip-forbidden')) return 'internal';
  if (r.includes('upstream-unresolved') && rebind.has(h.name)) return 'internal';
  if (r.some(x => NOT_LISTED.has(x) || DENYLISTED.has(x))) return 'not-allowed';
  if (r.includes('upstream-unresolved')) return 'unresolved';
  if (r.length > 0 && r.every(x => NO_NAME.has(x))) return 'no-name';
  return 'other';
}

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

/** dnsmasq: "possible DNS-rebind attack detected: <name>" (stop-dns-rebind, enforce mode). */
export function parseDnsRebind(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/possible DNS-rebind attack detected: (\S+)/g)) out.add(m[1].toLowerCase());
  return Array.from(out);
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

// ---------------------------------------------------------------- formatting

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Untrusted text (hostnames come from the job's own Host headers) as a code span in a table. */
function code(s: string): string {
  return (
    '`' +
    s
      .slice(0, 253)
      .replace(/`/g, "'")
      .replace(/\|/g, '\\|')
      .replace(/[\r\n]/g, ' ') +
    '`'
  );
}

/** The same, inside raw HTML (<summary>). */
function codeHtml(s: string): string {
  const h = s.slice(0, 253).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<code>${h}</code>`;
}

function table(header: string[], align: string[], rows: string[][]): string {
  return [`| ${header.join(' | ')} |`, `|${align.join('|')}|`, ...rows.map(r => `| ${r.join(' | ')} |`)].join('\n');
}

function capped<T>(rows: T[]): { shown: T[]; note: string } {
  if (rows.length <= MAX_ROWS) return { shown: rows, note: '' };
  return {
    shown: rows.slice(0, MAX_ROWS),
    note: `\n\n**+${rows.length - MAX_ROWS} more not shown here** - the full list is in the post step's job log.`
  };
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function nameList(hosts: HostSummary[]): string {
  const names = hosts.slice(0, MAX_LIST).map(h => code(displayName(h)));
  return names.join(', ') + (hosts.length > MAX_LIST ? `, +${hosts.length - MAX_LIST} more` : '');
}

function displayName(h: HostSummary): string {
  return h.name.replace(/^\(no name\) /, '');
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

/** "2xx ×23 · 307 ×2 · 401": only codes that need a look stand out. */
export function statusSummary(h: HostSummary): string {
  if (isPassthroughOnly(h)) return 'n/a';
  const times = (k: string, n: number) => (n > 1 ? `${k} ×${n}` : k);
  let ok = 0;
  const other: [string, number][] = [];
  let answered = 0;
  for (const [k, n] of Object.entries(h.statuses)) {
    answered += n;
    if (/^2\d\d$/.test(k)) ok += n;
    else other.push([k, n]);
  }
  other.sort((a, b) => Number(a[0]) - Number(b[0]));
  const parts = ok ? [times('2xx', ok)] : [];
  parts.push(...other.map(([k, n]) => times(k, n)));
  if (h.requests > answered) parts.push(times('no response', h.requests - answered));
  return parts.join(' · ') || '—';
}

function hostCell(h: HostSummary): string {
  let c = code(h.name);
  if (h.kinds.includes('passthrough')) c += ' <sub>🔀 passthrough</sub>';
  else if (h.kinds.length === 1 && h.kinds[0] === 'http') c += ' <sub>plain HTTP</sub>';
  return c;
}

/** Longest backtick run + 1, so untrusted text can't close the fence early. */
function fenceFor(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map(m => m.length));
  return '`'.repeat(Math.max(3, longest + 1));
}

function codeBlock(lang: string, text: string): string {
  const f = fenceFor(text);
  return `${f}${lang}\n${text}\n${f}`;
}

// ---------------------------------------------------------------- containers (P2)

export interface ContainerSummary {
  /** container address (the proxy / firewall source) */
  ip: string;
  /** container name when docker could still be asked at post time */
  name?: string;
  allowed: string[];
  denied: string[];
  /** names checked by SNI only (container-tls: sni-only) */
  sniOnly: string[];
  /** names whose intercepted TLS the container refused (it does not trust the runtime CA) */
  untrusted: string[];
  /** firewall: off-host egress outside the proxy and DNS (rejected in enforce, logged in analyze) */
  firewall: { dst: string; proto: string; n: number; rejected: boolean }[];
}

/**
 * Per-container view of the flow log (records from the container listener) and of the
 * container firewall chain (CDrop / CEgress). `names` maps container IPs to names.
 */
export function summarizeContainers(
  records: FlowRecord[],
  firewall: FirewallEvent[],
  names: ReadonlyMap<string, string> = new Map()
): ContainerSummary[] {
  const by = new Map<string, ContainerSummary>();
  const get = (ip: string) => {
    let c = by.get(ip);
    if (!c) {
      c = { ip, name: names.get(ip), allowed: [], denied: [], sniOnly: [], untrusted: [], firewall: [] };
      by.set(ip, c);
    }
    return c;
  };
  for (const r of records) {
    if (r.source !== 'container' || !r.client) continue;
    const ip = ipOf(r.client);
    if (r.ev === 'tls-client-fail') {
      if (r.sni) addUnique(get(ip).untrusted, r.sni);
      continue;
    }
    if (!DECISIONS.has(r.ev) || !r.verdict) continue;
    const c = get(ip);
    const name = nameOf(r);
    if (DENIED.has(r.verdict)) addUnique(c.denied, name);
    else if (r.ev !== 'upstream') addUnique(c.allowed, name);
    if (r.reason === 'container-sni-only') addUnique(c.sniOnly, name);
  }
  for (const e of firewall) {
    if (!CONTAINER_PREFIXES.has(e.prefix) || !e.src) continue;
    const c = get(e.src);
    const dst = `${e.dst}:${e.dport}`;
    const row = c.firewall.find(f => f.dst === dst && f.proto === e.proto);
    if (row) row.n++;
    else c.firewall.push({ dst, proto: e.proto, n: 1, rejected: e.prefix === 'SaferRunner-CDrop' });
  }
  // a name both allowed and refused (e.g. an upstream refusal) is listed as refused only
  for (const c of by.values()) c.allowed = c.allowed.filter(n => !c.denied.includes(n));
  return Array.from(by.values()).sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

function listCell(names: string[]): string {
  if (!names.length) return '';
  const shown = names.slice(0, MAX_LIST).map(code).join(', ');
  return names.length > MAX_LIST ? `${shown} +${names.length - MAX_LIST} more` : shown;
}

export function containerSection(containers: ContainerSummary[], mode: Mode): string {
  if (!containers.length) return '';
  const enforce = mode === 'enforce';
  const untrusted = containers.filter(c => c.untrusted.length);
  const outside = containers.reduce((a, c) => a + c.firewall.length, 0);
  const summary = [plural(containers.length, 'container')];
  if (untrusted.length) summary.push(`⚠️ ${plural(untrusted.length, 'container')} did not trust the CA`);
  if (outside) summary.push(`${outside} outside the proxy ${enforce ? 'rejected' : 'allowed'}`);
  let md = `<details${untrusted.length ? ' open' : ''}>\n<summary>🐳 <b>Container egress</b> — ${summary.join(' · ')}</summary>\n\n`;
  md +=
    '<sub>Traffic from Docker containers (service containers, `docker run`, `docker build`) goes through the same ' +
    'proxy and DNS filter. 🔀 = checked by TLS name only (`container-tls: sni-only`), no CA needed in the container.</sub>\n\n';
  const { shown, note } = capped(containers);
  md += table(
    ['Container', 'Allowed', enforce ? 'Blocked' : 'Would be blocked', 'Outside the proxy'],
    [':--', ':--', ':--', ':--'],
    shown.map(c => [
      c.name ? `${code(c.name)}<br><sub>${c.ip}</sub>` : code(c.ip),
      c.allowed.map(n => (c.sniOnly.includes(n) ? `🔀 ${code(n)}` : code(n))).join(', ') || '—',
      listCell(c.denied) || '—',
      c.firewall
        .slice(0, MAX_LIST)
        .map(f => `${f.rejected ? '❌' : '⚠️'} ${code(f.dst)} ${f.proto}${f.n > 1 ? ` ×${f.n}` : ''}`)
        .join('<br>') || '—'
    ])
  );
  md += note + '\n\n';
  if (untrusted.length) {
    md +=
      '**TLS failed because the container did not trust the runtime CA:** ' +
      untrusted.map(c => `${code(c.name ?? c.ip)} → ${listCell(c.untrusted)}`).join('; ') +
      '. Under `container-tls: sni-only` containers need no CA, except for multi-tenant front doors (Azure ' +
      'Storage): those stay intercepted so the Host check still stops fronting to another tenant. Reach them ' +
      'from a step on the runner, or give the container the CA (`/etc/safer-runner/ca.pem`).\n\n';
  }
  return md + '</details>\n\n';
}

// ---------------------------------------------------------------- report

export interface ReportInput {
  mode: Mode;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  sudoRetained?: boolean;
  /** the runner user kept docker access (root-equivalent) */
  dockerRetained?: boolean;
  /** sudo log split by who ran what (analyze: tells the user enforce's default will remove sudo) */
  sudo?: SudoUsage;
  job: string;
  hosts: HostSummary[];
  firewall: FirewallEvent[];
  dnsRefused: string[];
  /** names dnsmasq dropped as a possible DNS-rebind (their answer was a private address) */
  dnsRebind?: string[];
  /**
   * The job's own `allowed-domains` + `passthrough-domains` patterns. Allowed traffic to
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as GitHub
   * platform traffic. Undefined: no split.
   */
  userDomains?: string[];
  selfTests: { name: string; ok: boolean; detail: string }[];
  integrity?: { status: 'verified' | 'tampered' | 'unavailable'; body: string };
  /** per-container egress (P2); empty / undefined: no container traffic */
  containers?: ContainerSummary[];
  extraSections?: string[];
  now?: Date;
}

const HOSTNAME = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

/**
 * Names refused only because they're not on the allowlist - never fronting, internal
 * addresses, IPs, the risky-subdomain denylist or the self-test - and only well-formed
 * hostnames (they are pasted into YAML).
 */
export function suggestedAllowlist(hosts: HostSummary[], rebind: ReadonlySet<string> = new Set()): string[] {
  return Array.from(
    new Set(
      hosts
        .filter(h => DENIED.has(h.verdict) && categorize(h, rebind) === 'not-allowed')
        .filter(h => h.reasons.some(r => NOT_LISTED.has(r)) && !h.reasons.some(r => DENYLISTED.has(r)))
        .filter(h => HOSTNAME.test(h.name) && !h.name.endsWith('.invalid'))
        .map(h => h.name)
    )
  );
}

/** Mode as shown in the summary header. enforce with sudo retained is never shown as plain enforce. */
export function modeLabel(mode: Mode, sudoRetained = false): string {
  if (mode === 'analyze') return '📊 ANALYZE';
  return sudoRetained ? '⚠️ ENFORCE (ADVISORY — sudo retained, not an enforced boundary)' : '🔒 ENFORCE';
}

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
    md += '<sub>🔀 passthrough = checked by TLS name only, not decrypted, so no request or byte counts.</sub>\n\n';
  }
  return md;
}

function totals(rows: HostSummary[]): { requests: number; bytes: number } {
  return {
    requests: rows.reduce((a, h) => a + h.requests, 0),
    bytes: rows.reduce((a, h) => a + h.reqBytes + h.respBytes, 0)
  };
}

function frontingCell(h: HostSummary, verb: string): string {
  const what = h.reasons.includes('host-sni-mismatch')
    ? '🎭 **Host/SNI mismatch** (domain fronting)'
    : '🎭 **Conflicting Host / authority**';
  const notes: string[] = [];
  if (h.snis.length) notes.push(`sent inside TLS for ${h.snis.map(code).join(', ')}`);
  if (h.reasons.some(r => NOT_LISTED.has(r))) notes.push('also not on allowlist');
  if (h.dsts.length) notes.push(`dialled ${h.dsts.map(code).join(', ')}`);
  return what + (verb ? `, ${verb}` : '') + (notes.length ? `<br><sub>${notes.join(' · ')}</sub>` : '');
}

function internalCell(h: HostSummary, verb: string): string {
  if (h.upstreamIps.length) {
    const ips = h.upstreamIps.map(ip => `${code(ip)} (${addressClass(ip)})`).join(', ');
    return `🕳️ **Internal address** → ${ips}, ${verb}`;
  }
  // the address itself is not logged by dnsmasq: say only what was measured
  return `🕳️ **Internal address** — DNS answer dropped by DNS-rebind protection`;
}

const NO_NAME_TEXT: Record<string, string> = {
  'no-sni': 'TLS with no SNI',
  'ip-literal-sni': 'TLS with an IP address as SNI',
  'ip-literal-host': 'HTTP request with an IP literal as the Host',
  'no-host': 'HTTP request with no Host'
};

function firewallSummary(events: FirewallEvent[]): {
  rows: { e: FirewallEvent; n: number }[];
  rejected: number;
  logged: number;
} {
  const seen = new Map<string, { e: FirewallEvent; n: number }>();
  for (const e of events) {
    const k = `${e.prefix} ${e.proto} ${e.dst}:${e.dport} uid ${e.uid}`;
    seen.set(k, { e, n: (seen.get(k)?.n ?? 0) + 1 });
  }
  const rows = Array.from(seen.values());
  const rejected = rows.filter(r => REJECT_PREFIXES.has(r.e.prefix)).length;
  return { rows, rejected, logged: rows.length - rejected };
}

function destinationText(e: FirewallEvent): string {
  const likely = PORT_NAMES[e.dport];
  return `${likely ? `${likely} to ` : ''}${code(`${e.dst}:${e.dport}`)}`;
}

export function buildReport(input: ReportInput): string {
  const { mode } = input;
  const enforce = mode === 'enforce';
  const advisory = enforce && input.sudoRetained === true;
  const rebind = new Set((input.dnsRebind ?? []).map(n => n.toLowerCase()));
  const dnsRefused = new Set(input.dnsRefused.map(n => n.toLowerCase()));
  const blockedWord = enforce ? 'blocked' : 'would be blocked';

  const denied = input.hosts.filter(h => DENIED.has(h.verdict));
  const allowed = input.hosts.filter(h => !DENIED.has(h.verdict));
  const groups: Record<Category, HostSummary[]> = {
    fronting: [],
    internal: [],
    'not-allowed': [],
    unresolved: [],
    'no-name': [],
    other: []
  };
  for (const h of denied) groups[categorize(h, rebind)].push(h);
  const byTries = (a: HostSummary, b: HostSummary) => b.tries - a.tries || a.name.localeCompare(b.name);
  for (const g of Object.values(groups)) g.sort(byTries);
  const bypass = [...groups.fronting, ...groups.internal];

  let jobHosts = allowed;
  let platform: HostSummary[] = [];
  if (input.userDomains) {
    const user = compileUserPatterns(input.userDomains);
    jobHosts = allowed.filter(h => matchesAny(h.name, user));
    platform = allowed.filter(h => !jobHosts.includes(h));
  }
  const all = totals(allowed);
  const plat = totals(platform);

  const selfOk = input.selfTests.filter(t => t.ok).length;
  const selfFailed = input.selfTests.filter(t => !t.ok);
  const tampered = input.integrity?.status === 'tampered';
  // container firewall events are reported in the container section, with their source
  const fw = firewallSummary(input.firewall.filter(e => !CONTAINER_PREFIXES.has(e.prefix)));
  const sudoRan = input.sudo?.ran.length ?? 0;
  const suggest = suggestedAllowlist(denied, rebind);

  // ---- title + chips
  let md = `## 🛡️ Safer Runner — egress${advisory ? ' — enforce (ADVISORY — sudo retained, not an enforced boundary)' : ''}\n\n`;
  const chips = [advisory ? '⚠️ ENFORCE · ADVISORY' : enforce ? '🔒 ENFORCE' : '📊 ANALYZE'];
  if (enforce) {
    const weak: string[] = [];
    if (input.sudoRetained) weak.push('⚠️ sudo retained');
    if (input.dockerRetained) weak.push('⚠️ docker retained');
    if (tampered) weak.push('🚨 config tampered');
    chips.push(...(weak.length ? weak : ['✅ boundary intact']));
  } else {
    chips.push(denied.length ? `${plural(denied.length, 'host')} would be blocked` : 'nothing would be blocked');
  }
  if (input.selfTests.length) {
    chips.push(`${selfFailed.length ? '❌' : '🧪'} self-tests ${selfOk}/${input.selfTests.length}`);
  }
  md += chips.map(c => `<kbd>${c}</kbd>`).join(' ') + '\n\n';

  // ---- verdict alerts (top level only: alerts don't render inside <details>)
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
  if (selfFailed.length) {
    critical.push(
      `**Self-test failed:** ${selfFailed.map(t => `\`${t.name}\``).join(', ')} — the proxy may not be enforcing as designed on this runner.`
    );
  }
  if (tampered) {
    critical.push(
      '**Safer Runner configuration changed during the job** — see the config file check under Diagnostics.'
    );
  }
  if (critical.length) md += '> [!CAUTION]\n' + critical.map(c => `> ${c}`).join('\n>\n') + '\n\n';

  if (enforce && (input.sudoRetained || input.dockerRetained)) {
    const why: string[] = [];
    if (input.sudoRetained) {
      why.push(
        '**ADVISORY: sudo was retained** (`disable-sudo: false` or `sudo-config`), so any step could have used it to ' +
          'remove the egress controls. The policy below was applied, but this job did not run inside an enforced ' +
          'boundary. Remove `disable-sudo: false` / `sudo-config` to make enforce a boundary.'
      );
    }
    if (input.dockerRetained) {
      why.push(
        'The runner user kept **docker** access, which is root-equivalent: a step could use it to remove the egress ' +
          'controls. Set `disable-docker: true` or `stop-docker: true` unless the job needs docker.'
      );
    }
    md +=
      '> [!WARNING]\n' +
      '> **The boundary was weaker than it looks.**\n>\n' +
      why.map(w => `> ${w}`).join('\n>\n') +
      '\n\n';
  }

  if (enforce && !bypass.length && groups['not-allowed'].length) {
    md +=
      '> [!IMPORTANT]\n' +
      `> **${plural(groups['not-allowed'].length, 'host')} not on the allowlist ${groups['not-allowed'].length === 1 ? 'was' : 'were'} blocked.** ` +
      'If this job failed, this is probably why — see below.\n\n';
  }

  if (!enforce && (suggest.length || sudoRan)) {
    md += '> [!IMPORTANT]\n';
    if (suggest.length) {
      md += `> **Enforce would block ${plural(suggest.length, 'host')} this job used.** Add ${suggest.length === 1 ? 'it' : 'them'} to run this job under \`mode: enforce\` (review each one first):\n>\n`;
      const yaml =
        '- uses: portswigger-tim/safer-runner-action@v2\n  with:\n    mode: enforce\n    allowed-domains: |\n' +
        suggest.map(s => `      ${s}`).join('\n');
      md +=
        codeBlock('yaml', yaml)
          .split('\n')
          .map(l => `> ${l}`)
          .join('\n') + '\n';
    }
    if (sudoRan) {
      if (suggest.length) md += '>\n';
      md +=
        `> **This job ran ${plural(sudoRan, 'sudo command')}.** Enforce removes sudo by default — drop that usage, ` +
        'or add `disable-sudo: false` (which makes enforce ADVISORY: sudo can remove the controls).\n';
    }
    md += '\n';
  }

  // ---- scorecard, or the one-line clean verdict
  const platNote = platform.length && plat.bytes ? ` <sub>(${humanBytes(plat.bytes)} of it GitHub platform)</sub>` : '';
  const allowedLine = `${plural(allowed.length, 'host')} · ${plural(all.requests, 'request')} · ${humanBytes(all.bytes)}`;
  if (denied.length === 0 && fw.rows.length === 0) {
    md += enforce
      ? `**✅ Nothing blocked.** ${allowedLine} through the proxy.\n\n`
      : `**✅ Nothing would be blocked.** ${allowedLine} through the proxy.` +
        (sudoRan ? '\n\n' : ' This job should run unchanged with `mode: enforce`.\n\n');
  } else {
    const rows: string[][] = [];
    if (bypass.length) rows.push(['🚨 **Bypass attempts**', `**${plural(bypass.length, 'host')} ${blockedWord}**`]);
    if (groups['not-allowed'].length) {
      rows.push([
        '🚫 **Not on allowlist**',
        `**${groups['not-allowed'].length} ${blockedWord}** — ${nameList(groups['not-allowed'])}`
      ]);
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
    md += table(['', ''], [':--', ':--'], rows) + '\n\n';
  }

  // ---- blocked, grouped by cause, attacks first
  const verb = enforce ? 'refused' : 'would be refused';
  const suffix = enforce ? '' : ' — would be blocked';
  const section = (title: string, rows: HostSummary[], header: string[], cells: (h: HostSummary) => string[]) => {
    const { shown, note } = capped(rows);
    return (
      `### ${title} (${rows.length})${suffix}\n\n` +
      table(
        header,
        header.map((_, i) => (i === header.length - 1 ? '--:' : ':--')),
        shown.map(cells)
      ) +
      note +
      '\n\n'
    );
  };
  if (bypass.length) {
    md += section('🚨 Bypass attempts', bypass, ['Host', 'What happened', 'Tries'], h => [
      code(h.name),
      categorize(h, rebind) === 'fronting'
        ? frontingCell(h, enforce ? '' : 'not blocked (analyze)')
        : internalCell(h, verb),
      String(h.tries)
    ]);
  }
  if (groups['not-allowed'].length) {
    md += section('🚫 Not on the allowlist', groups['not-allowed'], ['Host', 'Seen as', 'Tries'], h => {
      const seen: string[] = [];
      if (h.reasons.includes('sni-not-allowed')) seen.push('HTTPS (SNI)');
      if (h.reasons.includes('host-not-allowed')) seen.push('plain HTTP');
      if (h.reasons.some(r => DENYLISTED.has(r))) seen.push('on the risky-subdomain denylist');
      if (dnsRefused.has(h.name)) seen.push('DNS also refused');
      return [code(h.name), seen.join(' · '), String(h.tries)];
    });
    if (enforce && suggest.length) {
      md += 'If the job needs them, add them (review each one first):\n\n';
      md += codeBlock('yaml', 'allowed-domains: |\n' + suggest.map(s => `  ${s}`).join('\n')) + '\n\n';
    }
  }
  if (groups.unresolved.length) {
    md += section('❔ Did not resolve', groups.unresolved, ['Host', 'What happened', 'Tries'], h => [
      code(h.name),
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
      shown.map(h => [code(displayName(h)), h.reasons.map(r => NO_NAME_TEXT[r] ?? r).join(' · '), String(h.tries)])
    );
    md += note + '\n\n</details>\n\n';
  }
  if (groups.other.length) {
    // unknown reasons are never dropped: show the raw code
    md += section('⚙️ Other', groups.other, ['Host', 'Reason', 'Tries'], h => [
      code(h.name),
      h.reasons.map(code).join(', '),
      String(h.tries)
    ]);
  }

  // ---- allowed: the job's own hosts open, GitHub platform collapsed
  if (input.userDomains) {
    if (jobHosts.length) md += `### ✅ Allowed — this job's hosts (${jobHosts.length})\n\n` + allowedTable(jobHosts);
    if (platform.length) {
      md += `<details>\n<summary>🐙 <b>GitHub platform</b> — ${plural(platform.length, 'host')} · ${plural(plat.requests, 'request')} · ${humanBytes(plat.bytes)} · expected for every job</summary>\n\n`;
      md += allowedTable(platform) + '</details>\n\n';
    }
  } else if (allowed.length) {
    md += `### ✅ Allowed (${allowed.length})\n\n` + allowedTable(allowed);
  }

  md += containerSection(input.containers ?? [], mode);

  // ---- diagnostics: one collapsed section, every part states its result
  const diag: string[] = [];
  let body = '';
  if (input.selfTests.length) {
    diag.push(`self-tests ${selfOk}/${input.selfTests.length} ${selfFailed.length ? '✗' : '✓'}`);
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
    diag.push('nothing outside the proxy');
  }
  if (input.dnsRefused.length) {
    diag.push(plural(input.dnsRefused.length, 'DNS refusal'));
    const shownAbove = new Set(denied.map(h => h.name));
    const rest = input.dnsRefused.filter(d => !shownAbove.has(d.toLowerCase()));
    const { shown, note } = capped(rest);
    body += `**DNS refused** (${input.dnsRefused.length}): `;
    body += rest.length
      ? shown.map(code).join(', ') + note
      : 'all of them are listed with their blocked connection above';
    body += '\n\n';
  }
  if (input.sudo) {
    const { ran, refused, internal } = input.sudo;
    diag.push(
      `workflow sudo ${ran.length}` +
        (internal.length ? ` (${internal.length} by Safer Runner)` : '') +
        (refused.length ? ` · ${plural(refused.length, 'sudo attempt')} refused` : '')
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
    body += internal.length ? `; Safer Runner itself ran ${internal.length} (setup, integrity checks, teardown)` : '';
    body += ran.length ? ':\n\n' + codeBlock('console', lines(ran)) + '\n\n' : '.\n\n';
    if (refused.length) {
      body += `Refused by sudo (${refused.length}):\n\n` + codeBlock('console', lines(refused)) + '\n\n';
    }
  }
  if (input.integrity) {
    const s = input.integrity.status;
    diag.push(
      s === 'verified' ? 'config files ✓' : s === 'tampered' ? 'config files ⚠️ CHANGED' : 'config files: no baseline'
    );
    body += `**Config file tamper check** — ${s === 'verified' ? 'all verified' : s === 'tampered' ? '⚠️ CHANGED' : 'no baseline'}\n\n`;
    body += input.integrity.body + '\n\n';
  }
  for (const s of input.extraSections ?? []) if (s) body += s + '\n\n';
  md += `<details>\n<summary>🔧 <b>Diagnostics</b> — ${diag.join(' · ')}</summary>\n\n${body}</details>\n\n`;

  const now = (input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  md += `<sub>${mode} · job ${code(input.job)} · ${now} UTC · [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2</sub>\n`;
  return md;
}
