/**
 * v2 job-summary report built from the proxy flow log (+ firewall and DNS logs).
 * DENIED first and in full; anything that has to be cut is said so explicitly (review M6).
 */

import { ipOf, type FlowRecord } from './flowlog';
import {
  GIT_HOSTS,
  compilePattern,
  expandPattern,
  gitPatternKey,
  isIpLiteral,
  matchesAny,
  validatePathPattern,
  type Mode
} from './policy';
import type { SudoCommand, SudoUsage } from './parsers/sudo-parser';
import { STANDARD_METHODS, methodLabel, needsRedaction, pathSegmentShown, redactName, redactPath } from './redact';

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
export type Category = 'fronting' | 'internal' | 'not-allowed' | 'filtered' | 'unresolved' | 'no-name' | 'other';

const FRONTING = new Set(['host-sni-mismatch', 'authority-host-mismatch']);
const NOT_LISTED = new Set(['sni-not-allowed', 'host-not-allowed']);
const DENYLISTED = new Set(['sni-denied', 'host-denied']);
const NO_NAME = new Set(['no-sni', 'ip-literal-sni', 'ip-literal-host', 'no-host']);

/**
 * An internal-address attempt is one the proxy's upstream IP guard refused (it logs the
 * address). The resolver does no DNS-rebind filtering, so `upstream-unresolved` is just a name
 * that did not resolve - calling a typo an attack would cost the report its credibility.
 */
export function categorize(h: HostSummary): Category {
  const r = h.reasons;
  if (r.some(x => FRONTING.has(x))) return 'fronting';
  if (r.includes('upstream-ip-forbidden')) return 'internal';
  if (r.some(x => NOT_LISTED.has(x) || DENYLISTED.has(x))) return 'not-allowed';
  if (r.some(x => FILTER_REASONS.has(x))) return 'filtered';
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

/**
 * The post step (this report, the tamper check, fail-on-tampering) runs as the runner user from
 * the action's files on the runner, which the job's own steps can write to. Say so in the report.
 */
export const ADVISORY_REPORT_NOTE =
  '<sub>The tamper check and this summary come from the post step, which runs as the runner user from ' +
  "files the job's steps can modify: an advisory tripwire, not tamper-proof evidence. The egress controls " +
  "themselves are root-owned and don't depend on it.</sub>";

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function nameList(hosts: HostSummary[]): string {
  const names = hosts.slice(0, MAX_LIST).map(h => code(blockedName(displayName(h))));
  return names.join(', ') + (hosts.length > MAX_LIST ? `, +${hosts.length - MAX_LIST} more` : '');
}

/**
 * A refused name as printed: payload-looking labels redacted (src/redact.ts), because a blocked
 * name can be the data a step tried to send. IP literals are shown as they are.
 */
export function blockedName(name: string): string {
  return isIpLiteral(name) || name.startsWith('(') ? name : redactName(name);
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
  /** names checked by SNI only (container HTTPS to allowlisted names) */
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
  const shown = names
    .slice(0, MAX_LIST)
    .map(n => code(blockedName(n)))
    .join(', ');
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
    'proxy and DNS filter. 🔀 = checked by TLS name only, no CA needed in the container.</sub>\n\n';
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
      '. Containers need no CA, except for multi-tenant front doors (Azure ' +
      'Storage): those stay intercepted so the Host check still stops fronting to another tenant. Reach them ' +
      'from a step on the runner, or give the container the CA (`/etc/safer-runner/ca.pem`).\n\n';
  }
  return md + '</details>\n\n';
}

// ---------------------------------------------------------------- http-filter

/** Flow-log reasons for a request the http-filter refused (proxy/policy_core.py). */
const FILTER_REASONS = new Set(['method-not-allowed', 'path-not-allowed']);
const FILTER_REASON_TEXT: Record<string, string> = {
  'method-not-allowed': 'method not allowed on this path',
  'path-not-allowed': 'path not allowed'
};
/** Not the exfil surface: in a suggestion they collapse to one `"*"` line per host. */
const READ_METHODS = ['GET', 'HEAD', 'OPTIONS'];
const METHOD_ORDER = [...READ_METHODS, 'POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * Endpoints a suggestion keeps path-specific, matched on the end of the path, with the methods
 * they use. On these a read and a write share a method (git fetch and push are both POST), so
 * folding them into a host's method baseline would re-open the write everywhere. Seeded with
 * the git pack URLs; add more as they come up (registry blob uploads, PyPI `legacy`, ...). A
 * missing entry only makes a suggestion looser, never wrong at enforcement: the user reviews it.
 */
export const SENSITIVE_PATH_SUFFIXES: readonly { suffix: string; methods: readonly string[] }[] = [
  { suffix: 'git-receive-pack', methods: ['POST'] },
  { suffix: 'git-upload-pack', methods: ['POST'] }
];

/**
 * Hosts the built-in platform allowlist covers (step logs, artifacts, caches, OIDC). Left out of
 * the suggestion, which describes the job's own traffic.
 */
const PLATFORM_HOSTS = ['*.actions.githubusercontent.com', 'productionresultssa*.blob.core.windows.net'];
/** Distinct literals kept at one path position (same prefix); more than this become `*`. */
const MAX_PINNED = 3;
/** proxy/policy.py MAX_PATH_LOG: a logged path this long may have been cut short */
const PATH_LOG_MAX = 256;

export interface FilterBlock {
  /** redacted like any refused name */
  host: string;
  /** a standard method, or an opaque label for any other (src/redact.ts) */
  method: string;
  /** redacted path (src/redact.ts), no query string */
  path: string;
  reason: string;
  verdict: string;
  tries: number;
}

export interface HttpFilterRule {
  /** path pattern as written in `http-filter` (no leading `/`; `*` spans any depth) */
  path: string;
  /** allowed methods; empty = NONE */
  methods: string[];
}

export interface HttpFilterSuggestion {
  hosts: { host: string; rules: HttpFilterRule[] }[];
  /** requests the suggestion was built from */
  requests: number;
  rules: number;
  /** sensitive write endpoints kept path-specific */
  specific: number;
  /** a write rule had to start with `*`: generalised heavily, review it */
  coarse: boolean;
}

export interface HttpFilterReport {
  /** requests the filter refused (enforce) or would refuse (analyze) */
  blocks: FilterBlock[];
  /** rules that would let the refused requests through, if the job needs them */
  fixes: HttpFilterSuggestion;
  /** a whole `http-filter` from the job's observed traffic (level B: read/write split) */
  suggestion: HttpFilterSuggestion;
}

interface ObservedRequest {
  host: string;
  method: string;
  /** the path forms the engine matches (canonical_path: decoded, then relaxed), no leading `/` */
  forms: string[];
  /** each form as segments to template; `''` (an empty or cut-off segment) always becomes `*` */
  shapes: string[][];
}

function isFilterBlock(r: FlowRecord): boolean {
  return DENIED.has(r.verdict) && FILTER_REASONS.has(r.reason ?? '');
}

/**
 * The forms of a logged request path the engine matches (proxy/policy_core.py canonical_path):
 * decoded once without the leading `/`, and relaxed (no `;params` or trailing `/`). Undefined
 * when the engine refuses the path whatever the rules say. A path cut short in the log keeps
 * only its decoded form, its last segment unknown.
 */
function pathForms(path: string, git: boolean): { forms: string[]; shapes: string[][] } | undefined {
  const truncated = path.length >= PATH_LOG_MAX;
  let raw = path.split('?', 1)[0].split('#', 1)[0];
  if (raw.startsWith('/')) raw = raw.slice(1);
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    decoded = raw;
  }
  if (/[\\\x00-\x1f\x7f]/.test(decoded) || /%(?:2e|2f|5c)/i.test(decoded)) return undefined;
  if (decoded.split('/').some(s => s === '.' || s === '..')) return undefined;
  let relaxed = decoded
    .split('/')
    .map(s => s.split(';', 1)[0])
    .join('/')
    .replace(/\/+$/, '');
  if (git) [decoded, relaxed] = [decoded.toLowerCase(), relaxed.toLowerCase()];
  const forms = truncated || relaxed === decoded ? [decoded] : [decoded, relaxed];
  const shapes = forms.map(f => (f === '' ? [] : f.split('/').map(s => (git ? stripGit(s) : s))));
  if (truncated && shapes[0].length) shapes[0][shapes[0].length - 1] = '';
  return { forms, shapes };
}

/**
 * Numeric, empty, or not printable as a path segment (redact.ts pathSegmentShown: encoded-looking,
 * unusual characters, dot segments): becomes `*` in a suggestion.
 */
function isVariableSegment(segment: string): boolean {
  return /^\d+$/.test(segment) || !pathSegmentShown(segment);
}

/** `*`, or the segment itself; `name;params` keeps its name (`name*`), as the engine also matches it without them. */
function templateSegment(segment: string): string {
  if (!isVariableSegment(segment)) return segment;
  const name = segment.split(';', 1)[0];
  return segment.includes(';') && name && !isVariableSegment(name) ? `${name}*` : '*';
}

/** policy.ts stripGit: on a git host `repo` and `repo.git` are one segment. */
function stripGit(segment: string): string {
  return segment.endsWith('.git') && segment.length > 4 ? segment.slice(0, -4) : segment;
}

/** proxy/policy_core.py compile_path_pattern, for checking a suggestion before it is shown. */
function pathRegex(pattern: string, git: boolean): RegExp {
  const p = validatePathPattern(pattern);
  const parts = (git ? p.toLowerCase() : p).split('/').map(s => {
    if (s === '*') return '.*';
    const lit = (git ? stripGit(s) : s).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
    return git ? `${lit}(?:\\.git)?` : lit;
  });
  return new RegExp(`^${parts.join('/')}$`);
}

/** proxy/policy_core.py PathRule.specificity: literal characters, then segments, then fewer `*`. */
function pathSpecificity(pattern: string, git: boolean): number[] {
  const key = git ? gitPatternKey(pattern) : validatePathPattern(pattern);
  return [key.replace(/\*/g, '').length, key.split('/').length - 1, -(key.match(/\*/g) ?? []).length];
}

function compareSpecificity(a: number[], b: number[]): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/**
 * Make the rules allow every observed request in each of its forms, as the engine decides
 * (proxy/policy_core.py _decide_rules: the most specific matching rules win and every tied winner
 * must allow the method): a winner that lacks the method gets it, and a NONE guard that would
 * refuse an observed request is dropped. The round-trip test in report.test.ts runs the result
 * through the real parser and matcher.
 */
function settleRules(byPath: Map<string, Set<string>>, reqs: ObservedRequest[], git: boolean): void {
  for (let pass = 0; pass < 8; pass++) {
    const rules = [...byPath.keys()].map(p => ({ p, rx: pathRegex(p, git), spec: pathSpecificity(p, git) }));
    let changed = false;
    for (const r of reqs) {
      for (const form of r.forms) {
        const hits = rules.filter(x => byPath.has(x.p) && x.rx.test(form));
        if (!hits.length) continue;
        const best = hits.reduce((a, b) => (compareSpecificity(a.spec, b.spec) >= 0 ? a : b)).spec;
        for (const w of hits.filter(x => compareSpecificity(x.spec, best) === 0)) {
          const ms = byPath.get(w.p)!;
          if (ms.size === 0) byPath.delete(w.p);
          else if (ms.has(r.method)) continue;
          else ms.add(r.method);
          changed = true;
        }
      }
    }
    if (!changed) return;
  }
}

function sensitiveSuffixOf(segs: string[]): (typeof SENSITIVE_PATH_SUFFIXES)[number] | undefined {
  const p = segs.join('/');
  return SENSITIVE_PATH_SUFFIXES.find(s => p === s.suffix || p.endsWith(`/${s.suffix}`));
}

function methodRank(m: string): number {
  const i = METHOD_ORDER.indexOf(m);
  return i < 0 ? METHOD_ORDER.length : i;
}

function sortMethods(methods: Iterable<string>): string[] {
  return [...methods].sort((a, b) => methodRank(a) - methodRank(b) || a.localeCompare(b));
}

/**
 * Template paths: a payload-looking segment becomes `*`, and so does every literal at a position
 * where more than MAX_PINNED distinct ones follow the same prefix. The last `keep` segments of
 * a path (its sensitive suffix) stay literal. A run of `*` merges into one: a standalone `*`
 * spans any depth.
 */
function templatePaths(paths: { segs: string[]; keep: number }[]): string[] {
  const out = paths.map(p => p.segs.map((s, i) => (i < p.segs.length - p.keep ? templateSegment(s) : s)));
  const free = (i: number, d: number) => d < out[i].length - paths[i].keep && out[i][d] !== '*';
  const depth = Math.max(0, ...out.map(s => s.length));
  for (let d = 0; d < depth; d++) {
    const seen = new Map<string, Set<string>>();
    out.forEach((s, i) => {
      if (!free(i, d)) return;
      const k = s.slice(0, d).join('/');
      seen.set(k, (seen.get(k) ?? new Set()).add(s[d]));
    });
    out.forEach((s, i) => {
      if (free(i, d) && seen.get(s.slice(0, d).join('/'))!.size > MAX_PINNED) s[d] = '*';
    });
  }
  return out.map(s => s.filter((x, i) => x !== '*' || s[i - 1] !== '*').join('/') || '/');
}

/**
 * One host's rules. With `collapseReads`, reads become a single `"*"` line and only writes are
 * templated (level B); without it every request gets a templated rule (the fixes for refused
 * requests). Sensitive endpoints are templated on their own, so the repos actually written to
 * stay pinned; and when a broader write rule could also match one, a `NONE` rule under that
 * rule's prefix keeps the write closed elsewhere (the method-boundary trap).
 */
function hostRules(
  reqs: ObservedRequest[],
  collapseReads: boolean,
  git: boolean
): { rules: HttpFilterRule[]; specific: number; coarse: boolean } {
  const byPath = new Map<string, Set<string>>();
  const add = (path: string, methods: Iterable<string>) => {
    const set = byPath.get(path) ?? new Set<string>();
    for (const m of methods) set.add(m);
    byPath.set(path, set);
  };
  const reads = new Set<string>();
  const plain: { method: string; segs: string[] }[] = [];
  const sensitive: { method: string; segs: string[]; keep: number }[] = [];
  for (const r of reqs) {
    if (collapseReads && READ_METHODS.includes(r.method)) {
      reads.add(r.method);
      continue;
    }
    for (const segs of r.shapes) {
      const s = sensitiveSuffixOf(segs);
      if (s) sensitive.push({ method: r.method, segs, keep: s.suffix.split('/').length });
      else plain.push({ method: r.method, segs });
    }
  }
  if (reads.size) add('*', ['GET', 'HEAD', ...reads]);
  templatePaths(plain.map(r => ({ segs: r.segs, keep: 0 }))).forEach((p, i) => add(p, [plain[i].method]));
  const pinned = new Set<string>();
  templatePaths(sensitive).forEach((p, i) => {
    add(p, [sensitive[i].method]);
    pinned.add(p);
  });

  // A rule ending in `*` also matches `<its prefix>/.../<suffix>`. The guard sits under that same
  // prefix, so it always has more literal characters (the engine's "most specific") than the
  // rule it narrows, and fewer than a pinned repo.
  const guards: string[] = [];
  for (const [p, ms] of [...byPath]) {
    if (pinned.has(p) || !(p === '*' || p.endsWith('/*')) || !(sensitive.length > 0 || p.startsWith('*'))) continue;
    for (const s of SENSITIVE_PATH_SUFFIXES) {
      const guard = `${p}/${s.suffix}`;
      if (s.methods.some(m => ms.has(m)) && !byPath.has(guard) && !guards.includes(guard)) guards.push(guard);
    }
  }
  for (const g of guards) byPath.set(g, new Set());
  // reads are allowed anywhere on the host, so a more specific write rule must not refuse them
  // (the pack endpoints excepted: git only ever POSTs to them)
  if (reads.size) {
    for (const [p, ms] of byPath) if (ms.size && !pinned.has(p)) ['GET', 'HEAD', ...reads].forEach(m => ms.add(m));
  }
  settleRules(byPath, reqs, git);

  const rest = [...byPath.keys()].filter(p => p !== '*').sort();
  const rules: HttpFilterRule[] = [
    ...(byPath.has('*') ? [{ path: '*', methods: sortMethods(byPath.get('*')!) }] : []),
    ...rest.map(path => ({ path, methods: sortMethods(byPath.get(path)!) }))
  ];
  const coarse = rules.some(r => r.path.startsWith('*') && r.methods.some(m => !READ_METHODS.includes(m)));
  return { rules, specific: [...pinned].filter(p => byPath.has(p)).length, coarse };
}

function suggest(reqs: ObservedRequest[], collapseReads: boolean): HttpFilterSuggestion {
  const byHost = new Map<string, ObservedRequest[]>();
  for (const r of reqs) byHost.set(r.host, [...(byHost.get(r.host) ?? []), r]);
  const out: HttpFilterSuggestion = { hosts: [], requests: reqs.length, rules: 0, specific: 0, coarse: false };
  for (const host of [...byHost.keys()].sort()) {
    const h = hostRules(byHost.get(host)!, collapseReads, GIT_HOSTS.includes(host));
    out.hosts.push({ host, rules: h.rules });
    out.rules += h.rules.length;
    out.specific += h.specific;
    out.coarse ||= h.coarse;
  }
  return out;
}

/**
 * Intercepted requests (the only ones with a method and path) to well-formed names, never on a
 * connection the upstream IP guard refused. `refused`: only the http-filter's refusals; else only
 * what the policy allowed, less what the built-in platform list allowed (`filter: platform`). A refusal never goes into the suggestion (that would quietly undo the
 * user's own filter): it gets its own reviewed rule (`fixes`).
 */
function observedRequests(records: FlowRecord[], refused: boolean): ObservedRequest[] {
  const conns = assignConnections(records);
  const out: ObservedRequest[] = [];
  records.forEach((r, i) => {
    if ((r.ev !== 'https' && r.ev !== 'http') || !r.verdict || conns[i]?.refused) return;
    if (refused ? !isFilterBlock(r) : DENIED.has(r.verdict) || r.filter === 'platform') return;
    if (!r.host || typeof r.method !== 'string' || typeof r.path !== 'string') return;
    const host = r.host.toLowerCase();
    const method = r.method.toUpperCase();
    if (!STANDARD_METHODS.includes(method) || !HOSTNAME.test(host) || needsRedaction(host)) return;
    const p = pathForms(r.path, GIT_HOSTS.includes(host));
    if (p) out.push({ host, method, ...p });
  });
  return out;
}

/**
 * The http-filter part of the report: refused requests (method + redacted path), the rules that
 * would let them through, and a suggested `http-filter` built from observed traffic as
 * observe → split reads from writes → template writes → union methods (design: "Suggested
 * http-filter (report)"). Advisory: never applied.
 */
export function summarizeHttpFilter(records: FlowRecord[]): HttpFilterReport {
  const byKey = new Map<string, FilterBlock>();
  for (const r of records) {
    if ((r.ev !== 'https' && r.ev !== 'http') || !isFilterBlock(r)) continue;
    const b: FilterBlock = {
      host: blockedName(r.host || r.sni || '(no host)'),
      method: methodLabel(r.method),
      path: redactPath(String(r.path ?? '')),
      reason: r.reason as string,
      verdict: r.verdict as string,
      tries: 0
    };
    const key = [b.host, b.method, b.path, b.reason].join(' ');
    const row = byKey.get(key) ?? b;
    row.tries++;
    byKey.set(key, row);
  }
  const platform = compileUserPatterns(PLATFORM_HOSTS);
  return {
    blocks: [...byKey.values()].sort((a, b) => b.tries - a.tries || a.host.localeCompare(b.host)),
    fixes: suggest(observedRequests(records, true), false),
    suggestion: suggest(
      observedRequests(records, false).filter(r => !matchesAny(r.host, platform)),
      true
    )
  };
}

/** The suggestion as the `http-filter` input. Path segments are pre-checked (pathSegmentShown), methods standard. */
export function httpFilterYaml(s: HttpFilterSuggestion): string {
  const hosts = s.hosts.map(
    h =>
      `  ${h.host}:\n` +
      h.rules.map(r => `    "${r.path}": ${r.methods.length ? r.methods.join(', ') : 'NONE'}`).join('\n')
  );
  return 'http-filter: |\n' + hosts.join('\n');
}

function compressionText(s: HttpFilterSuggestion): string {
  return (
    `collapsed ${plural(s.requests, 'request')} → ${plural(s.rules, 'rule')} (level B)` +
    (s.specific ? `; ${plural(s.specific, 'write endpoint')} kept specific` : '')
  );
}

// ---------------------------------------------------------------- report

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
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter) */
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

const HOSTNAME = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

/**
 * Names refused only because they're not on the allowlist - never fronting, internal
 * addresses, IPs, the risky-subdomain denylist or the self-test - and only well-formed
 * hostnames (they are pasted into YAML).
 */
export function suggestedAllowlist(hosts: HostSummary[]): string[] {
  return Array.from(
    new Set(
      hosts
        .filter(h => DENIED.has(h.verdict) && categorize(h) === 'not-allowed')
        .filter(h => h.reasons.some(r => NOT_LISTED.has(r)) && !h.reasons.some(r => DENYLISTED.has(r)))
        .filter(h => HOSTNAME.test(h.name) && !h.name.endsWith('.invalid') && !needsRedaction(h.name))
        .map(h => h.name)
    )
  );
}

/**
 * The post-run tamper check as a chip. It is advisory (ADVISORY_REPORT_NOTE), and a check that
 * could not run is unknown, never a pass.
 */
function integrityChip(status: 'verified' | 'tampered' | 'unavailable' | undefined): string {
  if (status === 'tampered') return '🚨 config tampered';
  if (status === 'verified') return '🔎 no config change seen (advisory)';
  return '❔ config unverified';
}

/** What made enforce advisory: 'sudo', 'docker', 'sudo and docker', or '' (a boundary). */
function retained(sudoRetained: boolean, dockerRetained: boolean): string {
  return [sudoRetained ? 'sudo' : '', dockerRetained ? 'docker' : ''].filter(Boolean).join(' and ');
}

/**
 * Mode as shown in the summary header. enforce with sudo or docker (root-equivalent) retained
 * is never shown as plain enforce.
 */
export function modeLabel(mode: Mode, sudoRetained = false, dockerRetained = false): string {
  if (mode === 'analyze') return '📊 ANALYZE';
  const what = retained(sudoRetained, dockerRetained);
  return what ? `⚠️ ENFORCE (ADVISORY — ${what} retained, not an enforced boundary)` : '🔒 ENFORCE';
}

const DOCKER_ACCESS_TEXT: Record<string, string> = {
  retained: 'runner user can use docker',
  'group-removed': 'runner user removed from the docker group, socket root-only',
  'not-running': 'docker daemon not running'
};

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
  const advisoryWhat = enforce ? retained(input.sudoRetained === true, input.dockerRetained === true) : '';
  const advisory = advisoryWhat !== '';
  const dnsRefused = new Set(input.dnsRefused.map(n => n.toLowerCase()));
  const blockedWord = enforce ? 'blocked' : 'would be blocked';

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
  const suggest = suggestedAllowlist(denied);
  const filterBlocks = input.httpFilter?.blocks ?? [];
  const filtered = filterBlocks.length
    ? filterBlocks.reduce((a, b) => a + b.tries, 0)
    : groups.filtered.reduce((a, h) => a + h.requests, 0);
  const hostsDenied = denied.length - groups.filtered.length;

  // ---- title + chips
  let md = `## 🛡️ Safer Runner — egress${advisory ? ` — enforce (ADVISORY — ${advisoryWhat} retained, not an enforced boundary)` : ''}\n\n`;
  const chips = [advisory ? '⚠️ ENFORCE · ADVISORY' : enforce ? '🔒 ENFORCE' : '📊 ANALYZE'];
  if (enforce) {
    if (input.sudoRetained) chips.push('⚠️ sudo retained');
    if (input.dockerRetained) chips.push('⚠️ docker retained');
    if (!input.sudoRetained && !input.dockerRetained) chips.push('✅ controls applied at setup');
    chips.push(integrityChip(input.integrity?.status));
  } else {
    if (hostsDenied) chips.push(`${plural(hostsDenied, 'host')} would be blocked`);
    if (filtered) chips.push(`${plural(filtered, 'request')} the http-filter would refuse`);
    if (!hostsDenied && !filtered) chips.push('nothing would be blocked');
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

  if (!enforce && (suggest.length || sudoRan)) {
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
    if (sudoRan) {
      if (suggest.length) md += '>\n';
      md +=
        `> **This job ran ${plural(sudoRan, 'sudo command')}.** Enforce removes sudo — drop that usage, ` +
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
    if (groups.filtered.length || filterBlocks.length) {
      rows.push(['🔒 **HTTP filter**', `${plural(filtered, 'request')} ${blockedWord} — ${nameList(groups.filtered)}`]);
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
      code(blockedName(h.name)),
      categorize(h) === 'fronting' ? frontingCell(h, enforce ? '' : 'not blocked (analyze)') : internalCell(h, verb),
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
      return [code(blockedName(h.name)), seen.join(' · '), String(h.tries)];
    });
    if (enforce && suggest.length) {
      md += 'If the job needs them, add them (review each one first):\n\n';
      md += codeBlock('yaml', 'allowed-domains: |\n' + suggest.map(s => `  ${s}`).join('\n')) + '\n\n';
    }
  }
  if (filterBlocks.length) {
    const { shown, note } = capped(filterBlocks);
    md += `### 🔒 Refused by \`http-filter\` (${filterBlocks.length})${suffix}\n\n`;
    md += table(
      ['Host', 'Request', 'Why', 'Tries'],
      [':--', ':--', ':--', '--:'],
      shown.map(b => [
        code(b.host),
        `${code(b.method)} ${code(b.path)}`,
        FILTER_REASON_TEXT[b.reason] ?? code(b.reason),
        String(b.tries)
      ])
    );
    md += note + '\n\n';
  } else if (groups.filtered.length) {
    md += section('🔒 Refused by `http-filter`', groups.filtered, ['Host', 'Reason', 'Tries'], h => [
      code(blockedName(h.name)),
      h.reasons.map(r => FILTER_REASON_TEXT[r] ?? code(r)).join(' · '),
      String(h.tries)
    ]);
  }
  const fixes = input.httpFilter?.fixes;
  if (fixes?.hosts.length) {
    md +=
      `If the job needs ${filterBlocks.length === 1 ? 'it' : 'them'}, add ${fixes.rules === 1 ? 'this rule' : 'these rules'} to \`http-filter\` ` +
      '(review each one first: a write is how data leaves):\n\n';
    md += codeBlock('yaml', httpFilterYaml(fixes)) + '\n\n';
  }
  const sug = input.httpFilter?.suggestion;
  if (sug?.hosts.length && (!enforce || filtered)) {
    md += `<details${filtered && !enforce ? ' open' : ''}>\n<summary>🧰 <b>Suggested <code>http-filter</code></b> — ${compressionText(sug)}</summary>\n\n`;
    md +=
      "<sub>Advisory, built from this job's intercepted traffic — never applied for you. Reads collapse to one " +
      '`"*"` line per host; write paths keep their structure, with ids and hashes as `*`; git push and fetch stay ' +
      'pinned to the repos this job used. GitHub platform hosts are left out (the built-in platform allowlist covers ' +
      'them). Add each host to `allowed-domains` too: a filter never grants access.</sub>\n\n';
    if (sug.coarse) {
      md += '**⚠️ Coarse — review.** A write rule had to start with `*`, so it allows that write on any path.\n\n';
    }
    md += codeBlock('yaml', httpFilterYaml(sug)) + '\n\n</details>\n\n';
  }
  if (groups.unresolved.length) {
    md += section('❔ Did not resolve', groups.unresolved, ['Host', 'What happened', 'Tries'], h => [
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
    md += section('⚙️ Other', groups.other, ['Host', 'Reason', 'Tries'], h => [
      code(blockedName(h.name)),
      h.reasons.map(code).join(', '),
      String(h.tries)
    ]);
  }

  // ---- allowed: the job's own hosts open, GitHub platform collapsed
  if (input.userDomains) {
    if (jobHosts.length) md += `### Allowed — this job's hosts (${jobHosts.length})\n\n` + allowedTable(jobHosts);
    if (platform.length) {
      md += `<details>\n<summary>🐙 <b>GitHub platform</b> — ${plural(platform.length, 'host')} · ${plural(plat.requests, 'request')} · ${humanBytes(plat.bytes)} · expected for every job</summary>\n\n`;
      md += allowedTable(platform) + '</details>\n\n';
    }
  } else if (allowed.length) {
    md += `### Allowed (${allowed.length})\n\n` + allowedTable(allowed);
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
    const shownAbove = new Set(denied.map(h => h.name));
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
  md += `<details>\n<summary>🔧 <b>Diagnostics</b> — ${diag.join(' · ')}</summary>\n\n${body}</details>\n\n`;

  const now = (input.now ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  md += `<sub>${mode} · job ${code(input.job)} · ${now} UTC · [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2</sub>\n`;
  return md;
}
