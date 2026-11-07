/**
 * Flow log -> per-host summaries: records tied to client connections, one row per (name,
 * denied?), and why each refused host was blocked.
 */

import { ipOf, type FlowRecord } from '../../flowlog';
import { isIpLiteral } from '../../policy';
import { needsRedaction, redactName } from '../redact';

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
export const MAX_LIST = 5;
export const DECISIONS = new Set(['tls', 'http', 'https', 'upstream']);
export const DENIED = new Set<string | undefined>(['BLOCK', 'WOULD_BLOCK']);

export function nameOf(r: FlowRecord): string {
  return (r.ev === 'tls' ? r.sni : r.host || r.sni) || `(no name) ${r.dst ?? ''}`.trim();
}

/** The name the proxy connects upstream for (what the upstream IP guard checks). */
function targetOf(r: FlowRecord): string {
  const t = r.ev === 'tls' || r.ev === 'https' ? r.sni : r.host;
  return t && !isIpLiteral(t) ? t : '';
}

export function addUnique(list: string[], v: string | undefined | null): void {
  if (v && !list.includes(v)) list.push(v);
}

/**
 * A refused name as printed: payload-looking labels redacted (src/report/redact.ts), because a
 * blocked name can be the data a step tried to send. IP literals are shown as they are.
 */
export function blockedName(name: string): string {
  return isIpLiteral(name) || name.startsWith('(') ? name : redactName(name);
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
      addUnique(h.layers, r.layer);
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

/** An allowed request as logged, for the suggester (proxy/suggest.py checks and templates it). */
export interface AllowedRequest {
  host: string;
  method: string;
  path: string;
}

/**
 * Allowed intercepted requests (the only ones with a method and path), never on a connection the
 * upstream IP guard refused, less what the built-in platform list allowed (`filter: platform`).
 * A refused request never goes into a suggestion: that would quietly undo the user's own filter,
 * and its path was chosen by whoever sent it. Names, methods and paths are checked by the
 * suggester itself.
 */
export function allowedRequests(records: FlowRecord[]): AllowedRequest[] {
  const conns = assignConnections(records);
  const out: AllowedRequest[] = [];
  records.forEach((r, i) => {
    if ((r.ev !== 'https' && r.ev !== 'http') || !r.verdict || conns[i]?.refused) return;
    if (DENIED.has(r.verdict) || r.filter === 'platform') return;
    if (typeof r.host !== 'string' || !r.host || typeof r.method !== 'string' || typeof r.path !== 'string') return;
    out.push({ host: r.host, method: r.method, path: r.path });
  });
  return out;
}

// ---------------------------------------------------------------- classification

/** Why a host was blocked, most severe first. A host goes in its most severe category only. */
export type Category = 'fronting' | 'internal' | 'not-allowed' | 'filtered' | 'unresolved' | 'no-name' | 'other';

const FRONTING = new Set(['host-sni-mismatch', 'authority-host-mismatch']);
export const NOT_LISTED = new Set(['sni-not-allowed', 'host-not-allowed']);
export const DENYLISTED = new Set(['sni-denied', 'host-denied']);
const NO_NAME = new Set(['no-sni', 'ip-literal-sni', 'ip-literal-host', 'no-host']);
/** Flow-log reasons for a request the http-filter refused (proxy/policy_core.py). */
export const FILTER_REASONS = new Set(['method-not-allowed', 'path-not-allowed']);

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
