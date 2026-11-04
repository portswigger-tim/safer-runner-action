/**
 * v2 job-summary report built from the proxy flow log (+ firewall and DNS logs).
 * DENIED first and in full; anything that has to be cut is said so explicitly (review M6).
 */

import type { FlowRecord } from './flowlog';
import type { Mode } from './policy';

export interface HostSummary {
  name: string;
  /** worst verdict seen for this name: BLOCK > WOULD_BLOCK > PASSTHROUGH > INTERCEPT/ALLOW */
  verdict: string;
  reasons: string[];
  layers: string[];
  kinds: string[];
  connections: number;
  requests: number;
  reqBytes: number;
  respBytes: number;
  statuses: Record<string, number>;
  dsts: string[];
}

const RANK: Record<string, number> = { BLOCK: 4, WOULD_BLOCK: 3, PASSTHROUGH: 2, INTERCEPT: 1, ALLOW: 1 };
const MAX_ROWS = 300;
const MAX_LIST = 5;

function nameOf(r: FlowRecord): string {
  return (r.ev === 'tls' ? r.sni : r.host || r.sni) || `(no name) ${r.dst ?? ''}`.trim();
}

function addUnique(list: string[], v: string | undefined | null): void {
  if (v && !list.includes(v)) list.push(v);
}

const DENIED = new Set(['BLOCK', 'WOULD_BLOCK']);

/**
 * One row per (name, denied?): a host can have both refused attempts (e.g. a fronting try
 * with its name in the Host header) and allowed traffic; neither should hide the other.
 */
export function summarizeFlows(records: FlowRecord[]): HostSummary[] {
  const byKey = new Map<string, HostSummary>();
  for (const r of records) {
    if (!['tls', 'http', 'https'].includes(r.ev) || !r.verdict) continue;
    const name = nameOf(r);
    const denied = DENIED.has(r.verdict);
    const key = `${denied ? 'D' : 'A'} ${name}`;
    let h = byKey.get(key);
    if (!h) {
      h = {
        name,
        verdict: r.verdict,
        reasons: [],
        layers: [],
        kinds: [],
        connections: 0,
        requests: 0,
        reqBytes: 0,
        respBytes: 0,
        statuses: {},
        dsts: []
      };
      byKey.set(key, h);
    }
    if ((RANK[r.verdict] ?? 0) > (RANK[h.verdict] ?? 0)) h.verdict = r.verdict;
    if (denied) {
      addUnique(h.reasons, r.reason);
      addUnique(h.layers, r.layer);
    }
    if (r.ev === 'tls') {
      h.connections++;
      addUnique(h.kinds, r.passthrough ? 'passthrough' : denied ? 'tls' : 'intercept');
    } else {
      h.requests++;
      h.reqBytes += r.req_bytes ?? 0;
      h.respBytes += r.resp_bytes ?? 0;
      if (r.status !== undefined) h.statuses[String(r.status)] = (h.statuses[String(r.status)] ?? 0) + 1;
      if (r.ev === 'http') addUnique(h.kinds, 'http');
    }
    if (h.dsts.length < MAX_LIST && r.dst) addUnique(h.dsts, r.dst.replace(/:\d+$/, ''));
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

export function buildReport(input: ReportInput): string {
  const { mode, hosts } = input;
  const denied = hosts.filter(h => DENIED.has(h.verdict));
  const allowed = hosts.filter(h => !denied.includes(h));
  const deniedWord = mode === 'enforce' ? 'Blocked' : 'Would be blocked';
  const icon = mode === 'enforce' ? '🔒' : '📊';

  let md = `# Safer Runner v2 egress report\n\n`;
  md += `**Job:** ${input.job} · **Mode:** ${icon} ${mode.toUpperCase()} · **Generated:** ${new Date().toISOString()}\n\n`;
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
    if (suggest.length === 0) {
      md += `Everything seen is already allowed - this job should run unchanged with \`mode: enforce\`.\n\n`;
    } else {
      md += 'To run this job in enforce mode, allow these hosts (review each one first):\n\n';
      md +=
        '```yaml\n- uses: portswigger-tim/safer-runner-action@v2\n  with:\n    mode: enforce\n    allowed-domains: |\n';
      md += suggest.map(s => `      ${s}`).join('\n') + '\n```\n\n';
    }
  }

  for (const s of input.extraSections) md += s + '\n\n';
  md += `*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2*\n`;
  return md;
}
