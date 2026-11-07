/**
 * The firewall's pure config: iptables-restore rulesets (snapshot-tested), the rsyslog rule that
 * routes their LOG lines, and parsers for what the runner reports. No I/O.
 *
 * Rules are interface-agnostic ("allow lo + the proxy path, deny the rest") rather than
 * `-o eth0`-scoped, so a renamed or extra NIC fails closed instead of open (review M3).
 */

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
} from '../../constants';
import type { Mode } from '../../policy';

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
export const LOCAL_BRIDGES = ['docker0', 'br-+'];

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

export const MISSING_DOCKER_USER_MESSAGE =
  'Docker is running but the DOCKER-USER chain is missing (Docker started with iptables disabled, or a ' +
  'firewall backend other than iptables), so the container egress rules cannot be applied';

/** rsyslog rule file for the firewall's LOG lines */
export const LOGGING_RULE_FILE = '/etc/rsyslog.d/10-iptables-safer-runner-v2.conf';
/** the LOG prefixes the rulesets use (without their trailing space) */
export const LOG_PREFIXES = [LOG_PREFIX_DROP, LOG_PREFIX_ANALYZE, LOG_PREFIX_CDROP, LOG_PREFIX_CEGRESS].map(p =>
  p.trim()
);

/**
 * rsyslog: copy the kernel's LOG lines with our prefixes to `logFile`, readable without sudo.
 * Filtered on programname=kernel, so the sudo commands that set the rules up don't match.
 */
export function loggingRule(logFile: string, prefixes: string[] = LOG_PREFIXES): string {
  return `if $programname == 'kernel' and $msg contains ['${prefixes.join("', '")}'] then ${logFile}\n`;
}
