/** Per-container egress (P2): the container listener's flow records and the container firewall chain. */

import { ipOf, type FlowRecord } from '../../flowlog';
import { CONTAINER_PREFIXES, attempts, type FirewallEvent } from '../iptables/log';
import { capped, code, plural, table } from '../../report/markdown';
import type { BlockedRow, Details } from '../../report/section';
import { DECISIONS, DENIED, MAX_LIST, addUnique, blockedName, nameOf } from '../mitmproxy/flows';
import { destination, prefixWord } from '../iptables/report';

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
  firewall: { dst: string; dport: string; proto: string; n: number; rejected: boolean }[];
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
  const lines = new Map<ContainerSummary['firewall'][number], FirewallEvent[]>();
  for (const e of firewall) {
    if (!CONTAINER_PREFIXES.has(e.prefix) || !e.src) continue;
    const c = get(e.src);
    const dst = `${e.dst}:${e.dport}`;
    let row = c.firewall.find(f => f.dst === dst && f.proto === e.proto);
    if (!row)
      c.firewall.push(
        (row = { dst, dport: e.dport, proto: e.proto, n: 0, rejected: e.prefix === 'SaferRunner-CDrop' })
      );
    lines.set(row, [...(lines.get(row) ?? []), e]);
    row.n = attempts(lines.get(row)!);
  }
  // a name both allowed and refused (e.g. an upstream refusal) is listed as refused only
  for (const c of by.values()) c.allowed = c.allowed.filter(n => !c.denied.includes(n));
  return Array.from(by.values()).sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

function listCell(names: string[]): string {
  const shown = names
    .slice(0, MAX_LIST)
    .map(n => code(blockedName(n)))
    .join(', ');
  return names.length > MAX_LIST ? `${shown} +${names.length - MAX_LIST} more` : shown;
}

const containerName = (c: ContainerSummary) => code(c.name ?? c.ip);

/**
 * What the container firewall chain blocked, with the container that sent it. Names the proxy
 * blocked for a container are already in the proxy's rows (one flow log), so they are not repeated.
 */
export function containerBlocked(containers: ContainerSummary[]): BlockedRow[] {
  return containers.flatMap(c =>
    c.firewall.map(f => ({
      reason: code(prefixWord(f.rejected ? 'SaferRunner-CDrop' : 'SaferRunner-CEgress')),
      layer: 'firewall',
      tries: f.n,
      what: destination(f.dst, f.dport, f.proto, `from ${containerName(c)}`)
    }))
  );
}

/** The containers and what each one reached. Undefined when no container sent anything. */
export function containerDetails(containers: ContainerSummary[]): Details | undefined {
  if (!containers.length) return undefined;
  const untrusted = containers.filter(c => c.untrusted.length);
  const { shown, note } = capped(containers);
  let body = table(
    ['Container', 'Allowed', 'Blocked'],
    [':--', ':--', ':--'],
    shown.map(c => [
      c.name ? `${code(c.name)} <sub>${c.ip}</sub>` : code(c.ip),
      c.allowed
        .map(n => `${code(blockedName(n))}${c.sniOnly.includes(n) ? ' <sub>`container-sni-only`</sub>' : ''}`)
        .join(', ') || '—',
      listCell(c.denied) || '—'
    ])
  );
  body += note + '\n\n';
  if (untrusted.length) {
    body +=
      '⚠️ **TLS failed: the container does not trust the proxy CA:** ' +
      untrusted.map(c => `${containerName(c)} → ${listCell(c.untrusted)}`).join('; ') +
      '. Azure Storage front doors stay intercepted for containers: reach them from a step on the runner, or give ' +
      'the container the CA (`/etc/safer-runner/ca.pem`).\n\n';
  }
  return { summary: `Containers: ${plural(containers.length, 'container')}`, body };
}
