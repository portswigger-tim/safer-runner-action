/**
 * The proxy's part of the job summary, from the flow log: the hosts and requests it blocked (or
 * would block), each with the reason code the flow log wrote, and the allowed hosts with their
 * numbers. It suggests `allowed-domains` and `http-filter`: in analyze the job's whole value, in
 * enforce only what would allow what was blocked. Nothing is cut silently (review M6).
 */

import { compilePattern, expandPattern, matchesAny, validatePattern } from '../../policy';
import { DENIED, blockedName, categorize, suggestedAllowlist, type HostSummary } from './flows';
import { httpFilterValue, type HttpFilterReport } from './http-filter';
import { PATH_HIDDEN, needsRedaction } from '../../report/redact';
import { capped, code, humanBytes, plural, table } from '../../report/markdown';
import type { BlockedRow, Details, ReportContext, Section, Suggestion } from '../../report/section';

export interface ProxyObserved {
  hosts: HostSummary[];
  /**
   * The job's own `allowed-domains` + `passthrough-domains` patterns. Allowed traffic to
   * anything else matched the GitHub list (allow = GitHub ∪ user), so it is shown as GitHub's.
   * Undefined: no split.
   */
  userDomains?: string[];
  /** the job's `allowed-domains` entries alone: the suggested value keeps them */
  allowedDomains?: string[];
  /** requests refused by `http-filter` and the suggested filter (summarizeHttpFilter) */
  httpFilter?: HttpFilterReport;
  /** GitHub platform endpoints the built-in list allowed on filtered hosts (policy.json) */
  platformEndpoints?: number;
}

/** The allowed traffic, for the row of numbers. */
export interface ProxyTotals {
  /** `3 + 3 GitHub`, or `6` with no split */
  hosts: string;
  requests: number;
  out: number;
  in: number;
}

export interface ProxySection extends Section {
  /** blocked names shown here (the DNS part leaves them out) */
  deniedNames: string[];
  totals: ProxyTotals;
}

/**
 * The flow log's refusal reasons, in the order the Blocked table lists them: the attempts to get
 * round the proxy first (fronting, an internal address), so a cut table never drops them; then by
 * layer (the TLS name, the HTTP request, the upstream). A reason not here comes last, as logged.
 */
const REASON_ORDER = [
  'host-sni-mismatch',
  'authority-host-mismatch',
  'upstream-ip-forbidden',
  'sni-not-allowed',
  'sni-denied',
  'no-sni',
  'ip-literal-sni',
  'invalid-clienthello',
  'host-not-allowed',
  'host-denied',
  'no-host',
  'ip-literal-host',
  'connect-method',
  'upstream-unresolved'
];

const rank = (reason: string) => {
  const i = REASON_ORDER.indexOf(reason);
  return i < 0 ? REASON_ORDER.length : i;
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

function displayName(h: HostSummary): string {
  return h.name.replace(/^\(no name\) /, '');
}

function isPassthroughOnly(h: HostSummary): boolean {
  return h.requests === 0 && h.kinds.includes('passthrough');
}

const plainHttp = (h: HostSummary) => (h.kinds.length === 1 && h.kinds[0] === 'http' ? ' <sub>plain HTTP</sub>' : '');

// ---------------------------------------------------------------- blocked

/** A blocked host and its data: the TLS name that carried it, the address dialled or resolved. */
function blockedWhat(h: HostSummary): string {
  let c = code(blockedName(displayName(h))) + plainHttp(h);
  const cat = categorize(h);
  if (cat === 'fronting') {
    if (h.snis.length) c += ` inside TLS for ${h.snis.map(n => code(blockedName(n))).join(', ')}`;
    if (h.dsts.length) c += `, dialled ${h.dsts.map(code).join(', ')}`;
  } else if (cat === 'internal' && h.upstreamIps.length) {
    c += ` → ${h.upstreamIps.map(code).join(', ')}`;
  }
  return c;
}

function blockedRows(denied: HostSummary[], filter: HttpFilterReport | undefined): BlockedRow[] {
  const hosts = denied
    // a request the http-filter blocked is listed with its method, below
    .filter(h => categorize(h) !== 'filtered')
    .map(h => ({ h, reasons: [...h.reasons].sort((a, b) => rank(a) - rank(b)) }))
    .sort(
      (a, b) =>
        rank(a.reasons[0] ?? '') - rank(b.reasons[0] ?? '') || b.h.tries - a.h.tries || a.h.name.localeCompare(b.h.name)
    )
    .map(({ h, reasons }) => ({
      reason: reasons.map(code).join(', '),
      layer: h.layers.join(', '),
      tries: h.tries,
      what: blockedWhat(h)
    }));
  const requests = (filter?.blocks ?? []).map(b => ({
    reason: code(b.reason),
    layer: 'http-filter',
    tries: b.tries,
    what: `${code(b.host)} ${code(b.method)} ${PATH_HIDDEN}`
  }));
  return [...hosts, ...requests];
}

// ---------------------------------------------------------------- suggestions

const KEEP_ENTRIES = 'keep your existing allowed-domains entries too';

/**
 * The job's own entries to repeat in the suggestion: only valid patterns, never one that looks
 * like data (an entry from an unmasked variable can be an internal name). `held` is true when any
 * was held back: the block then says to keep them.
 */
function keptEntries(entries: string[]): { kept: string[]; held: boolean } {
  const kept: string[] = [];
  let held = false;
  for (const e of entries) {
    try {
      if (expandPattern(e).some(p => needsRedaction(validatePattern(p)))) {
        throw new Error('not repeated');
      }
      if (!kept.includes(e)) kept.push(e);
    } catch {
      held = true;
    }
  }
  return { kept, held };
}

function suggestions(o: ProxyObserved, ctx: ReportContext, suggest: string[]): Suggestion[] {
  const out: Suggestion[] = [];
  if (suggest.length) {
    if (ctx.enforce) {
      out.push({ input: 'allowed-domains', value: suggest.join('\n') + '\n' });
    } else {
      // the job's entries as setup recorded them; when that record is missing, say to keep them
      const { kept, held } = o.allowedDomains ? keptEntries(o.allowedDomains) : { kept: [], held: true };
      const add = suggest.filter(n => !kept.includes(n));
      out.push({
        input: 'allowed-domains',
        value: [...kept, ...add].join('\n') + '\n',
        ...(held ? { comment: KEEP_ENTRIES } : {})
      });
    }
  }
  const sug = o.httpFilter?.suggestion;
  // enforce: only when the filter blocked something, so the job may need it
  if (sug?.hosts.length && (!ctx.enforce || o.httpFilter?.blocks.length)) {
    out.push({ input: 'http-filter', value: httpFilterValue(sug) });
  }
  return out;
}

function notes(o: ProxyObserved, ctx: ReportContext, denied: HostSummary[], suggest: string[]): string[] {
  if (ctx.enforce) return [];
  const out: string[] = [];
  const left = denied.filter(h => categorize(h) === 'not-allowed').length - suggest.length;
  if (left > 0) {
    out.push(`${plural(left, 'blocked name')} not suggested (on the risky-subdomain denylist, or it looks like data)`);
  }
  if (o.httpFilter?.suggestion?.coarse) {
    out.push('the suggested `http-filter` has a write rule that starts with `*`, so it allows that write on any path');
  }
  return out;
}

// ---------------------------------------------------------------- allowed

/** Each status code with its count: `200 ×45 · 304 ×4`, and requests with no response. */
export function statusSummary(h: HostSummary): string {
  if (isPassthroughOnly(h)) return '`passthrough`';
  let answered = 0;
  const parts = Object.entries(h.statuses)
    .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
    .map(([status, n]) => {
      answered += n;
      return `${status.replace(/[^0-9A-Za-z-]/g, '')} ×${n}`;
    });
  if (h.requests > answered) parts.push(`no response ×${h.requests - answered}`);
  return parts.join(' · ');
}

const bytes = (n: number) => (n > 0 ? humanBytes(n) : '');

function byData(a: HostSummary, b: HostSummary): number {
  return (
    b.reqBytes + b.respBytes - (a.reqBytes + a.respBytes) || b.requests - a.requests || a.name.localeCompare(b.name)
  );
}

function sum(rows: HostSummary[]): { requests: number; out: number; in: number } {
  return {
    requests: rows.reduce((a, h) => a + h.requests, 0),
    out: rows.reduce((a, h) => a + h.reqBytes, 0),
    in: rows.reduce((a, h) => a + h.respBytes, 0)
  };
}

function allowedDetails(rows: HostSummary[], title: string, extra = ''): Details {
  const t = sum(rows);
  const { shown, note } = capped([...rows].sort(byData));
  return {
    summary:
      `${title}: ${plural(rows.length, 'host')} · ${plural(t.requests, 'request')} · ↑ ${humanBytes(t.out)} · ` +
      `↓ ${humanBytes(t.in)}${extra}`,
    body:
      table(
        ['Host', 'Requests', '↑ Out', '↓ In', 'Status'],
        [':--', '--:', '--:', '--:', ':--'],
        shown.map(h => [
          code(blockedName(displayName(h))) + plainHttp(h),
          isPassthroughOnly(h) ? '—' : String(h.requests),
          bytes(h.reqBytes),
          bytes(h.respBytes),
          statusSummary(h)
        ])
      ) +
      note +
      '\n\n'
  };
}

// ---------------------------------------------------------------- report

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
  const denied = o.hosts.filter(h => DENIED.has(h.verdict));
  const allowed = o.hosts.filter(h => !DENIED.has(h.verdict));
  let jobHosts = allowed;
  let platform: HostSummary[] = [];
  if (o.userDomains) {
    const user = compileUserPatterns(o.userDomains);
    jobHosts = allowed.filter(h => matchesAny(h.name, user));
    platform = allowed.filter(h => !jobHosts.includes(h));
  }
  const suggest = suggestedAllowlist(denied);

  const details: Details[] = [];
  if (jobHosts.length) details.push(allowedDetails(jobHosts, 'Allowed'));
  if (platform.length || o.platformEndpoints) {
    const endpoints = o.platformEndpoints ? ` · ${plural(o.platformEndpoints, 'platform endpoint')}` : '';
    details.push(allowedDetails(platform, 'GitHub, always allowed', endpoints));
  }

  const all = sum(allowed);
  return {
    blocked: blockedRows(denied, o.httpFilter),
    alerts: [],
    suggestions: suggestions(o, ctx, suggest),
    notes: notes(o, ctx, denied, suggest),
    advisory: [],
    details,
    checks: [],
    deniedNames: denied.map(h => h.name),
    totals: {
      hosts: o.userDomains ? `${jobHosts.length} + ${platform.length} GitHub` : String(allowed.length),
      requests: all.requests,
      out: all.out,
      in: all.in
    }
  };
}
