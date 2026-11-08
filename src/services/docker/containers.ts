/** Per-container egress (P2): the container listener's flow records and the container firewall chain. */

import { ipOf, type FlowRecord } from '../../flowlog';
import type { Mode } from '../../policy';
import { CONTAINER_PREFIXES, type FirewallEvent } from '../iptables/log';
import { capped, code, plural, table } from '../../report/markdown';
import { DECISIONS, DENIED, MAX_LIST, addUnique, blockedName, nameOf } from '../mitmproxy/flows';

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
      c.allowed.map(n => `${c.sniOnly.includes(n) ? '🔀 ' : ''}${code(blockedName(n))}`).join(', ') || '—',
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
