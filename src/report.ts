/**
 * v2 job-summary report built from the proxy flow log (+ firewall and DNS logs).
 * DENIED first and in full; anything that has to be cut is said so explicitly (review M6).
 */

import { ipOf, type FlowRecord } from './flowlog';
import { isIpLiteral } from './policy';
import type { Mode } from './policy';

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
  dst: string;
  dport: string;
  uid: string;
}

/** Parse kernel LOG lines written by our filter chain (see firewall.ts). */
export function parseFirewallLog(text: string): FirewallEvent[] {
  const out: FirewallEvent[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/(SaferRunner-\w+):/);
    if (!m) continue;
    const field = (k: string) => line.match(new RegExp(`\\b${k}=(\\S*)`))?.[1] ?? '';
    out.push({ prefix: m[1], proto: field('PROTO'), dst: field('DST'), dport: field('DPT'), uid: field('UID') });
  }
  return out;
}

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

function esc(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/</g, '&lt;');
}

function table(header: string[], rows: string[][]): string {
  return [
    `| ${header.join(' | ')} |`,
    `|${header.map(() => '---').join('|')}|`,
    ...rows.map(r => `| ${r.map(esc).join(' | ')} |`)
  ].join('\n');
}

function capped<T>(rows: T[]): { shown: T[]; note: string } {
  if (rows.length <= MAX_ROWS) return { shown: rows, note: '' };
  return {
    shown: rows.slice(0, MAX_ROWS),
    note: `\n\n**+${rows.length - MAX_ROWS} more not shown here** - the full list is in the post step's job log.\n`
  };
}

function statusText(s: Record<string, number>): string {
  return Object.entries(s)
    .sort()
    .map(([k, v]) => (v > 1 ? `${k}×${v}` : k))
    .join(' ');
}

export interface ReportInput {
  mode: Mode;
  /** enforce ran with sudo left in place: the controls were advisory (review H2) */
  sudoRetained?: boolean;
  /** the runner user kept docker access (root-equivalent) */
  dockerRetained?: boolean;
  /** sudo commands the job ran (analyze: tells the user enforce's default will remove sudo) */
  sudoCommandCount?: number;
  job: string;
  hosts: HostSummary[];
  firewall: FirewallEvent[];
  dnsRefused: string[];
  selfTests: { name: string; ok: boolean; detail: string }[];
  extraSections: string[];
}

/** Names that were refused only because they're not on the allowlist (not fronting, IPs, ...). */
export function suggestedAllowlist(hosts: HostSummary[]): string[] {
  const notListed = new Set(['sni-not-allowed', 'host-not-allowed']);
  return Array.from(
    new Set(
      hosts
        .filter(h => h.verdict === 'WOULD_BLOCK' && h.reasons.some(r => notListed.has(r)))
        .filter(h => !h.name.startsWith('(no name)') && !h.name.endsWith('.invalid'))
        .map(h => h.name)
    )
  );
}

/** Mode as shown in the summary header. enforce with sudo retained is never shown as plain enforce. */
export function modeLabel(mode: Mode, sudoRetained = false): string {
  if (mode === 'analyze') return '📊 ANALYZE';
  return sudoRetained ? '⚠️ ENFORCE (ADVISORY — sudo retained, not an enforced boundary)' : '🔒 ENFORCE';
}

export function buildReport(input: ReportInput): string {
  const { mode, hosts } = input;
  const denied = hosts.filter(h => DENIED.has(h.verdict));
  const allowed = hosts.filter(h => !denied.includes(h));
  const deniedWord = mode === 'enforce' ? 'Blocked' : 'Would be blocked';
  const advisory = mode === 'enforce' && input.sudoRetained === true;

  let md = `# Safer Runner v2 egress report${advisory ? ' — enforce (ADVISORY — sudo retained, not an enforced boundary)' : ''}\n\n`;
  if (advisory) {
    md +=
      '> [!WARNING]\n' +
      '> **ADVISORY: sudo was retained** (`disable-sudo: false` or `sudo-config`), so any step could have used it to ' +
      'remove the egress controls. The policy below was applied, but this job did not run inside an enforced boundary. ' +
      'Remove `disable-sudo: false` / `sudo-config` to make enforce a boundary.\n\n';
  }
  if (mode === 'enforce' && input.dockerRetained) {
    md +=
      '> [!CAUTION]\n' +
      '> The runner user kept **docker** access, which is root-equivalent: a step could use it to remove the egress ' +
      'controls. Set `disable-docker: true` or `stop-docker: true` unless the job needs docker.\n\n';
  }
  md += `**Job:** ${input.job} · **Mode:** ${modeLabel(mode, input.sudoRetained)} · **Generated:** ${new Date().toISOString()}\n\n`;
  const totalReq = hosts.reduce((a, h) => a + h.requests, 0);
  const totalBytes = hosts.reduce((a, h) => a + h.reqBytes + h.respBytes, 0);
  md += `${allowed.length} host(s) allowed · **${denied.length} host(s) ${deniedWord.toLowerCase()}** · `;
  md += `${totalReq} HTTP request(s) · ${humanBytes(totalBytes)} through the proxy\n\n`;

  if (input.selfTests.length) {
    md +=
      input.selfTests.map(t => `${t.ok ? '✅' : '❌'} self-test **${t.name}**: ${esc(t.detail)}`).join('  \n') + '\n\n';
  }

  md += `## ${mode === 'enforce' ? '❌' : '⚠️'} ${deniedWord} (${denied.length})\n\n`;
  if (denied.length === 0) {
    md += `None.\n\n`;
  } else {
    const { shown, note } = capped(denied);
    md += table(
      ['Host (SNI / Host)', 'Reason', 'Layer', 'Connections', 'Requests', 'Dialled IP(s)'],
      shown.map(h => [
        h.name,
        h.reasons.join(', '),
        h.layers.join(', '),
        String(h.connections),
        String(h.requests),
        h.dsts.join(', ')
      ])
    );
    md += note + '\n\n';
  }

  md += `## ✅ Allowed (${allowed.length})\n\n`;
  if (allowed.length === 0) {
    md += `None.\n\n`;
  } else {
    const { shown, note } = capped(allowed);
    md += table(
      ['Host', 'How', 'Connections', 'Requests', 'Sent', 'Received', 'Status codes'],
      shown.map(h => [
        h.name,
        h.kinds.join(', '),
        String(h.connections),
        String(h.requests),
        humanBytes(h.reqBytes),
        humanBytes(h.respBytes),
        statusText(h.statuses)
      ])
    );
    md += note + '\n\n';
    md += `<sub>intercept = TLS terminated and every request's Host checked · passthrough = SNI-only, not decrypted (byte counts not available) · http = plain HTTP</sub>\n\n`;
  }

  const nonHttp = input.firewall;
  md += `## Other egress - not through the proxy (${nonHttp.length})\n\n`;
  if (nonHttp.length === 0) {
    md += `None logged.\n\n`;
  } else {
    const seen = new Map<string, { e: FirewallEvent; n: number }>();
    for (const e of nonHttp) {
      const k = `${e.proto} ${e.dst}:${e.dport} uid ${e.uid}`;
      seen.set(k, { e, n: (seen.get(k)?.n ?? 0) + 1 });
    }
    const rows = Array.from(seen.values()).map(({ e, n }) => [
      e.prefix === 'SaferRunner-Drop' ? '❌ rejected' : '⚠️ allowed (not proxied)',
      e.proto,
      `${e.dst}:${e.dport}`,
      e.uid,
      String(n)
    ]);
    const { shown, note } = capped(rows);
    md += table(['Result', 'Proto', 'Destination', 'UID', 'Packets logged'], shown) + note + '\n\n';
    md += `<sub>New connections only; only TCP 80/443 is proxied. Logging is rate-limited (60/min).</sub>\n\n`;
  }

  if (input.dnsRefused.length) {
    const { shown, note } = capped(input.dnsRefused);
    md += `## DNS queries refused (${input.dnsRefused.length})\n\n`;
    md += shown.map(d => `\`${d}\``).join(', ') + note + '\n\n';
  }

  if (mode === 'analyze') {
    const suggest = suggestedAllowlist(hosts);
    md += `## Suggested configuration\n\n`;
    const sudoUsed = (input.sudoCommandCount ?? 0) > 0;
    if (suggest.length === 0) {
      md += sudoUsed
        ? `Every host seen is already allowed, but see the sudo note below.\n\n`
        : `Everything seen is already allowed - this job should run unchanged with \`mode: enforce\`.\n\n`;
    } else {
      md += 'To run this job in enforce mode, allow these hosts (review each one first):\n\n';
      md +=
        '```yaml\n- uses: portswigger-tim/safer-runner-action@v2\n  with:\n    mode: enforce\n    allowed-domains: |\n';
      md += suggest.map(s => `      ${s}`).join('\n') + '\n```\n\n';
    }
    if (sudoUsed) {
      md +=
        `**This job ran ${input.sudoCommandCount} sudo command(s)** (see "Sudo usage"). enforce removes sudo by default, ` +
        'so either remove that sudo usage from the job, or add `disable-sudo: false` - which makes enforce ' +
        'ADVISORY (sudo can remove the controls).\n\n';
    }
  }

  for (const s of input.extraSections) md += s + '\n\n';
  md += `*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2*\n`;
  return md;
}
