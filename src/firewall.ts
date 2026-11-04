/**
 * v2 iptables: force 80/443 through the proxy, force all DNS through dnsmasq, and (enforce)
 * deny everything else. Rulesets are generated as iptables-restore text (pure functions,
 * unit-tested) and applied atomically with `iptables-restore --noflush` into chains we own,
 * jumped to from position 1 of OUTPUT, so the image's own rules are left alone.
 *
 * Rules are interface-agnostic ("allow lo + the proxy path, deny the rest") rather than
 * `-o eth0`-scoped, so a renamed or extra NIC fails closed instead of open (review M3).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import {
  AZURE_IMDS,
  AZURE_WIRESERVER,
  FILTER_CHAIN,
  LOG_PREFIX_ANALYZE,
  LOG_PREFIX_DROP,
  NAT_CHAIN
} from './constants';
import type { Mode } from './policy';

export interface FirewallOptions {
  mode: Mode;
  proxyUid: number;
  dnsUid: number;
  proxyPort: number;
  /** Upstream DNS servers dnsmasq forwards to (the only :53 egress allowed). */
  dnsServers: string[];
}

/** Local bridges (docker0, user-defined networks). Container egress itself (FORWARD) is P2. */
const LOCAL_BRIDGES = ['docker0', 'br-+'];

/**
 * nat OUTPUT: send DNS to dnsmasq and 80/443 to the proxy. Exempt: the proxy and dnsmasq
 * uids (their own upstream connections), loopback, local bridges and the Azure platform IPs.
 */
export function buildNatRules(o: FirewallOptions): string {
  const c = NAT_CHAIN;
  const lines = [
    '*nat',
    `:${c} - [0:0]`,
    `-A ${c} -m owner --uid-owner ${o.proxyUid} -j RETURN`,
    `-A ${c} -m owner --uid-owner ${o.dnsUid} -j RETURN`,
    // Every resolver, whatever address it is aimed at (8.8.8.8, 168.63.129.16, GitHub's
    // 127.0.0.100 egress resolver...), is answered by our dnsmasq (fixes C1/M4).
    `-A ${c} -p udp --dport 53 -j REDIRECT --to-ports 53`,
    `-A ${c} -p tcp --dport 53 -j REDIRECT --to-ports 53`,
    `-A ${c} -d 127.0.0.0/8 -j RETURN`,
    `-A ${c} -d ${AZURE_IMDS}/32 -j RETURN`,
    `-A ${c} -d ${AZURE_WIRESERVER}/32 -j RETURN`,
    ...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`),
    `-A ${c} -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports ${o.proxyPort}`,
    `-I OUTPUT 1 -j ${c}`,
    'COMMIT',
    ''
  ];
  return lines.join('\n');
}

function commonFilterAllows(c: string): string[] {
  return [
    `-A ${c} -o lo -j RETURN`,
    ...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`),
    // Azure platform: IMDS and wireserver (WALinuxAgent, health) only on the ports they use.
    // 168.63.129.16:53 is NOT allowed - it is an open recursive resolver (C1).
    `-A ${c} -d ${AZURE_IMDS}/32 -p tcp --dport 80 -j RETURN`,
    `-A ${c} -d ${AZURE_WIRESERVER}/32 -p tcp -m multiport --dports 80,32526 -j RETURN`
  ];
}

/**
 * filter OUTPUT.
 * - enforce: allow lo, the proxy uid on 80/443, dnsmasq's uid to its upstream servers on 53,
 *   the Azure platform; reject everything else. A hole in the REDIRECT therefore still
 *   fails closed, and so does any non-80/443 egress.
 * - analyze: allow everything, but reject QUIC (UDP/443) so HTTP/3 clients fall back to TCP
 *   through the proxy, and log new non-proxied connections for the report.
 */
export function buildFilterRules(o: FirewallOptions): string {
  const c = FILTER_CHAIN;
  const lines = ['*filter', `:${c} - [0:0]`, ...commonFilterAllows(c)];
  if (o.mode === 'enforce') {
    lines.push(`-A ${c} -m owner --uid-owner ${o.proxyUid} -p tcp -m multiport --dports 80,443 -j RETURN`);
    for (const server of o.dnsServers) {
      for (const proto of ['udp', 'tcp']) {
        lines.push(`-A ${c} -m owner --uid-owner ${o.dnsUid} -d ${server}/32 -p ${proto} --dport 53 -j RETURN`);
      }
    }
    lines.push(
      `-A ${c} -p icmp -m conntrack --ctstate RELATED -j RETURN`,
      `-A ${c} -m limit --limit 60/min --limit-burst 60 -j LOG --log-prefix "${LOG_PREFIX_DROP}" --log-uid`,
      `-A ${c} -p tcp -j REJECT --reject-with tcp-reset`,
      `-A ${c} -j REJECT --reject-with icmp-port-unreachable`
    );
  } else {
    lines.push(
      `-A ${c} -m owner --uid-owner ${o.proxyUid} -j RETURN`,
      `-A ${c} -m owner --uid-owner ${o.dnsUid} -j RETURN`,
      `-A ${c} -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable`,
      `-A ${c} -m conntrack --ctstate NEW -m limit --limit 60/min --limit-burst 60 -j LOG --log-prefix "${LOG_PREFIX_ANALYZE}" --log-uid`
    );
  }
  lines.push(`-I OUTPUT 1 -j ${c}`, 'COMMIT', '');
  return lines.join('\n');
}

/**
 * ip6tables: there is no IPv6 path through the proxy. enforce rejects all non-loopback IPv6
 * egress (except neighbour discovery); analyze rejects 80/443 (+QUIC) so clients fall back
 * to IPv4 and through the proxy.
 */
export function buildIp6FilterRules(o: FirewallOptions): string {
  const c = FILTER_CHAIN;
  const lines = ['*filter', `:${c} - [0:0]`, `-A ${c} -o lo -j RETURN`];
  if (o.mode === 'enforce') {
    lines.push(...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`));
    for (const t of ['router-solicitation', 'neighbour-solicitation', 'neighbour-advertisement']) {
      lines.push(`-A ${c} -p ipv6-icmp --icmpv6-type ${t} -j RETURN`);
    }
    lines.push(
      `-A ${c} -p tcp -j REJECT --reject-with tcp-reset`,
      `-A ${c} -j REJECT --reject-with icmp6-port-unreachable`
    );
  } else {
    lines.push(
      `-A ${c} -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset`,
      `-A ${c} -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable`
    );
  }
  lines.push(`-I OUTPUT 1 -j ${c}`, 'COMMIT', '');
  return lines.join('\n');
}

/** Parse `ip -4 route show default` output into the interface names carrying the default route. */
export function parseDefaultRouteInterfaces(output: string): string[] {
  const out: string[] = [];
  for (const line of output.split('\n')) {
    const m = line.match(/^default\b.*\bdev\s+(\S+)/);
    if (m) out.push(m[1]);
  }
  return Array.from(new Set(out));
}

/**
 * Report where egress actually goes. Our rules are interface-agnostic so they fail closed
 * whatever the NIC is called; this is a loud diagnostic for the unexpected cases.
 */
export async function detectEgressInterface(): Promise<string[]> {
  const { stdout } = await exec.getExecOutput('ip', ['-4', 'route', 'show', 'default'], {
    silent: true,
    ignoreReturnCode: true
  });
  const ifaces = parseDefaultRouteInterfaces(stdout);
  if (ifaces.length === 0) {
    core.warning('No IPv4 default route found - egress rules are interface-agnostic and still apply.');
  } else if (ifaces.length > 1 || ifaces[0] !== 'eth0') {
    core.warning(
      `Default route via ${ifaces.join(', ')} (expected eth0). Egress rules are interface-agnostic ` +
        '(allow loopback + proxy path, reject the rest), so they still fail closed.'
    );
  } else {
    core.info('Default route via eth0');
  }
  return ifaces;
}

async function restore(binary: 'iptables-restore' | 'ip6tables-restore', rules: string): Promise<void> {
  await exec.exec('sudo', [binary, '--noflush'], { input: Buffer.from(rules) });
}

/** Remove our chains and jumps if present (idempotency for a re-run in the main step). */
export async function removeFirewall(): Promise<void> {
  const opts = { ignoreReturnCode: true, silent: true };
  for (const [bin, table, chain] of [
    ['iptables', 'nat', NAT_CHAIN],
    ['iptables', 'filter', FILTER_CHAIN],
    ['ip6tables', 'filter', FILTER_CHAIN]
  ]) {
    // -D removes one jump per call; loop until none remain.
    for (let i = 0; i < 5; i++) {
      if ((await exec.exec('sudo', [bin, '-t', table, '-D', 'OUTPUT', '-j', chain], opts)) !== 0) break;
    }
    await exec.exec('sudo', [bin, '-t', table, '-F', chain], opts);
    await exec.exec('sudo', [bin, '-t', table, '-X', chain], opts);
  }
}

/**
 * Apply the full ruleset. Order matters: nat (redirect) and filter go in together per
 * table; IPv6 last. The proxy must already be listening.
 */
export async function applyFirewall(o: FirewallOptions): Promise<void> {
  await removeFirewall();
  // REDIRECT to 127.0.0.1 of packets that were routed to another interface
  await exec.exec('sudo', ['sysctl', '-q', '-w', 'net.ipv4.conf.all.route_localnet=1']);
  await restore('iptables-restore', buildNatRules(o) + buildFilterRules(o));
  const v6 = await exec.exec('sudo', ['ip6tables-restore', '--noflush'], {
    input: Buffer.from(buildIp6FilterRules(o)),
    ignoreReturnCode: true
  });
  if (v6 !== 0) {
    const msg = 'ip6tables rules could not be applied';
    if (o.mode === 'enforce') throw new Error(msg);
    core.warning(msg);
  }
}

/**
 * Kill established :80/:443 connections that predate the REDIRECT (runner long-polls etc.),
 * so the cutover is immediate: they reconnect through the proxy instead of being rejected
 * mid-stream later.
 */
export async function killPreexistingConnections(): Promise<void> {
  const rc = await exec.exec('sudo', ['ss', '-K', 'state', 'established', '( dport = :443 or dport = :80 )'], {
    ignoreReturnCode: true,
    silent: true
  });
  if (rc !== 0) core.warning('ss -K failed: pre-existing connections will be cut off by the firewall instead');
}

/** Human-readable dump of what we installed (job log). */
export async function logFirewall(): Promise<void> {
  const opts = { ignoreReturnCode: true };
  await exec.exec('sudo', ['iptables', '-t', 'nat', '-S', NAT_CHAIN], opts);
  await exec.exec('sudo', ['iptables', '-S', FILTER_CHAIN], opts);
  await exec.exec('sudo', ['ip6tables', '-S', FILTER_CHAIN], opts);
}
