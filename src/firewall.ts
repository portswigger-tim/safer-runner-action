/**
 * v2 iptables: force 80/443 through the proxy, force all DNS through the resolver (CoreDNS), and (enforce)
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
  CONTAINER_FWD_CHAIN,
  CONTAINER_NAT_CHAIN,
  DOCKER_USER_CHAIN,
  FILTER_CHAIN,
  LOG_PREFIX_ANALYZE,
  LOG_PREFIX_CDROP,
  LOG_PREFIX_CEGRESS,
  LOG_PREFIX_DROP,
  NAT_CHAIN
} from './constants';
import type { Mode } from './policy';

export interface FirewallOptions {
  mode: Mode;
  proxyUid: number;
  dnsUid: number;
  proxyPort: number;
  /** Upstream DNS servers the resolver forwards to (the only :53 egress allowed). */
  dnsServers: string[];
  /** Proxy listener for container traffic (DNATed from the bridges); the addon classifies by it. */
  containerProxyPort: number;
  /** Docker is running: add the container rules (nat PREROUTING + DOCKER-USER). */
  containers: boolean;
}

/** Local bridges (docker0, user-defined networks). */
const LOCAL_BRIDGES = ['docker0', 'br-+'];

/** Private destinations a container may reach on its own bridge (container <-> container). */
const RFC1918 = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

/**
 * nat OUTPUT: send DNS to the resolver and 80/443 to the proxy. Exempt: the proxy and the resolver
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
    // 127.0.0.100 egress resolver...), is answered by our resolver (fixes C1/M4).
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
    // REDIRECTed packets (to the proxy / the resolver): after nat OUTPUT the destination is
    // 127.0.0.1, but `-o` still reports the ORIGINAL route (e.g. eth0), so `-o lo` alone
    // never matches them. A 127/8 destination cannot leave the host.
    `-A ${c} -d 127.0.0.0/8 -j RETURN`,
    ...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`),
    // Azure platform: IMDS and wireserver (WALinuxAgent, health) only on the ports they use.
    // 168.63.129.16:53 is NOT allowed - it is an open recursive resolver (C1).
    `-A ${c} -d ${AZURE_IMDS}/32 -p tcp --dport 80 -j RETURN`,
    `-A ${c} -d ${AZURE_WIRESERVER}/32 -p tcp -m multiport --dports 80,32526 -j RETURN`
  ];
}

/**
 * filter OUTPUT.
 * - enforce: allow lo, the proxy uid on 80/443, the resolver's uid to its upstream servers on 53,
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
      // log new connections only: packets of flows that predate the cutover (and ownerless
      // RST/FIN of sockets ss -K closed) are rejected too, but are just noise in the report
      `-A ${c} -m conntrack --ctstate NEW -m limit --limit 60/min --limit-burst 60 -j LOG --log-prefix "${LOG_PREFIX_DROP}" --log-uid`,
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
  const lines = ['*filter', `:${c} - [0:0]`, `-A ${c} -o lo -j RETURN`, `-A ${c} -d ::1/128 -j RETURN`];
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

/**
 * nat PREROUTING for traffic containers send off their bridge (docker0, user networks): DNS
 * to the resolver and 80/443 to the proxy's container listener (DNAT to 127.0.0.1 - needs
 * route_localnet). Container -> host services and container <-> container (bridged traffic
 * traverses PREROUTING once Docker loads br_netfilter) are left alone; anything they don't
 * cover falls through to the DOCKER-USER chain below.
 */
export function buildContainerNatRules(o: FirewallOptions): string {
  const c = CONTAINER_NAT_CHAIN;
  return [
    '*nat',
    `:${c} - [0:0]`,
    `-A ${c} -m addrtype --dst-type LOCAL -j RETURN`,
    `-A ${c} -d ${RFC1918} -j RETURN`,
    `-A ${c} -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53`,
    `-A ${c} -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:53`,
    `-A ${c} -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 127.0.0.1:${o.containerProxyPort}`,
    ...LOCAL_BRIDGES.map(b => `-I PREROUTING 1 -i ${b} -j ${c}`),
    'COMMIT',
    ''
  ].join('\n');
}

function containerForwardTail(c: string, o: FirewallOptions, icmpReject: string): string[] {
  if (o.mode === 'enforce') {
    return [
      `-A ${c} -m conntrack --ctstate NEW -m limit --limit 60/min --limit-burst 60 -j LOG --log-prefix "${LOG_PREFIX_CDROP}"`,
      `-A ${c} -p tcp -j REJECT --reject-with tcp-reset`,
      `-A ${c} -j REJECT --reject-with ${icmpReject}`
    ];
  }
  return [
    // QUIC: make HTTP/3 clients fall back to TCP, through the proxy (as on the host)
    `-A ${c} -p udp --dport 443 -j REJECT --reject-with ${icmpReject}`,
    `-A ${c} -m conntrack --ctstate NEW -m limit --limit 60/min --limit-burst 60 -j LOG --log-prefix "${LOG_PREFIX_CEGRESS}"`
  ];
}

/**
 * filter DOCKER-USER: everything a container forwards off-host that the DNAT did not send to
 * the proxy or the resolver. enforce rejects it (so a hole in the DNAT still fails closed), analyze
 * logs it. DOCKER-USER, not FORWARD: Docker re-inserts its FORWARD jumps ahead of ours on
 * every restart, but never touches DOCKER-USER.
 */
export function buildContainerForwardRules(o: FirewallOptions): string {
  const c = CONTAINER_FWD_CHAIN;
  return [
    '*filter',
    `:${c} - [0:0]`,
    ...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`),
    `-A ${c} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN`,
    ...containerForwardTail(c, o, 'icmp-port-unreachable'),
    ...LOCAL_BRIDGES.map(b => `-I ${DOCKER_USER_CHAIN} 1 -i ${b} -j ${c}`),
    'COMMIT',
    ''
  ].join('\n');
}

/**
 * ip6tables counterpart: there is no IPv6 path through the proxy, so an IPv6-enabled container
 * network fails closed (enforce) or is pushed back to IPv4 for 80/443 (analyze). `hook` is
 * DOCKER-USER when Docker manages ip6tables, otherwise FORWARD.
 */
export function buildIp6ContainerForwardRules(o: FirewallOptions, hook: string = DOCKER_USER_CHAIN): string {
  const c = CONTAINER_FWD_CHAIN;
  const tail =
    o.mode === 'enforce'
      ? containerForwardTail(c, o, 'icmp6-port-unreachable')
      : [
          `-A ${c} -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset`,
          ...containerForwardTail(c, o, 'icmp6-port-unreachable')
        ];
  return [
    '*filter',
    `:${c} - [0:0]`,
    ...LOCAL_BRIDGES.map(b => `-A ${c} -o ${b} -j RETURN`),
    `-A ${c} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN`,
    ...tail,
    ...LOCAL_BRIDGES.map(b => `-I ${hook} 1 -i ${b} -j ${c}`),
    'COMMIT',
    ''
  ].join('\n');
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
  const jumps: [string, string, string, string][] = [
    ['iptables', 'nat', 'PREROUTING', CONTAINER_NAT_CHAIN],
    ['iptables', 'filter', DOCKER_USER_CHAIN, CONTAINER_FWD_CHAIN],
    ['ip6tables', 'filter', DOCKER_USER_CHAIN, CONTAINER_FWD_CHAIN],
    ['ip6tables', 'filter', 'FORWARD', CONTAINER_FWD_CHAIN]
  ];
  for (const [bin, table, from, chain] of jumps) {
    for (const b of LOCAL_BRIDGES) {
      for (let i = 0; i < 5; i++) {
        if ((await exec.exec('sudo', [bin, '-t', table, '-D', from, '-i', b, '-j', chain], opts)) !== 0) break;
      }
    }
  }
  for (const [bin, table, chain] of [
    ['iptables', 'nat', CONTAINER_NAT_CHAIN],
    ['iptables', 'filter', CONTAINER_FWD_CHAIN],
    ['ip6tables', 'filter', CONTAINER_FWD_CHAIN]
  ]) {
    await exec.exec('sudo', [bin, '-t', table, '-F', chain], opts);
    await exec.exec('sudo', [bin, '-t', table, '-X', chain], opts);
  }
}

/** True if `chain` exists in the filter table of `bin`. */
async function chainExists(bin: 'iptables' | 'ip6tables', chain: string): Promise<boolean> {
  const rc = await exec.exec('sudo', [bin, '-t', 'filter', '-n', '-L', chain], {
    ignoreReturnCode: true,
    silent: true
  });
  return rc === 0;
}

/**
 * Apply the full ruleset. Order matters: nat (redirect) and filter go in together per
 * table; IPv6 last. The proxy must already be listening.
 */
export async function applyFirewall(o: FirewallOptions): Promise<void> {
  await removeFirewall();
  // REDIRECT to 127.0.0.1 of packets that were routed to another interface
  await exec.exec('sudo', ['sysctl', '-q', '-w', 'net.ipv4.conf.all.route_localnet=1']);
  let v4 = buildNatRules(o) + buildFilterRules(o);
  let v6 = buildIp6FilterRules(o);
  if (o.containers) {
    if (!(await chainExists('iptables', DOCKER_USER_CHAIN))) {
      // Docker is running but has not set up its chains (iptables: false?): nothing forwards
      // through DOCKER-USER, so there is nothing to hook. Say so rather than fail open silently.
      core.warning('Docker is running but the DOCKER-USER chain is missing: container egress rules not applied');
    } else {
      v4 += buildContainerNatRules(o) + buildContainerForwardRules(o);
      const hook = (await chainExists('ip6tables', DOCKER_USER_CHAIN)) ? DOCKER_USER_CHAIN : 'FORWARD';
      v6 += buildIp6ContainerForwardRules(o, hook);
    }
  }
  await restore('iptables-restore', v4);
  const rc6 = await exec.exec('sudo', ['ip6tables-restore', '--noflush'], {
    input: Buffer.from(v6),
    ignoreReturnCode: true
  });
  if (rc6 !== 0) {
    const msg = 'ip6tables rules could not be applied';
    if (o.mode === 'enforce') throw new Error(msg);
    core.warning(msg);
  }
}

/** Parse `docker network inspect` JSON into the IPv4/IPv6 subnets of the local bridges. */
export function parseDockerSubnets(json: string): string[] {
  const out: string[] = [];
  try {
    const nets = JSON.parse(json) as { Driver?: string; IPAM?: { Config?: { Subnet?: string }[] } }[];
    for (const n of nets) {
      if (n.Driver !== 'bridge') continue;
      for (const cfg of n.IPAM?.Config || []) if (cfg.Subnet) out.push(cfg.Subnet);
    }
  } catch {
    // not JSON (docker error): no subnets
  }
  return Array.from(new Set(out));
}

/**
 * Drop conntrack entries of flows sourced from the container networks. Without this, a
 * service container's connections that predate the rules keep going via ESTABLISHED (the
 * forwarded-traffic counterpart of killPreexistingConnections).
 */
export async function flushContainerConntrack(): Promise<void> {
  const opts = { ignoreReturnCode: true, silent: true };
  const ids = await exec.getExecOutput('sudo', ['docker', 'network', 'ls', '-q', '--filter', 'driver=bridge'], opts);
  const netIds = ids.stdout.split('\n').filter(Boolean);
  let subnets = ['172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8'];
  if (netIds.length > 0) {
    const inspect = await exec.getExecOutput('sudo', ['docker', 'network', 'inspect', ...netIds], opts);
    const found = parseDockerSubnets(inspect.stdout);
    if (found.length > 0) subnets = found;
  }
  if ((await exec.exec('sh', ['-c', 'command -v conntrack'], opts)) !== 0) {
    core.warning('conntrack not installed: container connections that predate the rules may continue');
    return;
  }
  for (const s of subnets) {
    // exit 1 = nothing matched
    await exec.exec('sudo', ['conntrack', '-D', '-f', s.includes(':') ? 'ipv6' : 'ipv4', '-s', s], opts);
  }
  core.info(`Flushed container conntrack entries for ${subnets.join(', ')}`);
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
  await exec.exec('sudo', ['iptables', '-t', 'nat', '-S', CONTAINER_NAT_CHAIN], opts);
  await exec.exec('sudo', ['iptables', '-S', CONTAINER_FWD_CHAIN], opts);
  await exec.exec('sudo', ['iptables', '-S', DOCKER_USER_CHAIN], opts);
}
