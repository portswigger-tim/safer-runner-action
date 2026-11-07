/**
 * v2 iptables: force 80/443 through the proxy, force all DNS through the resolver (CoreDNS), and (enforce)
 * deny everything else. Rulesets are generated as iptables-restore text (./config.ts, pure,
 * snapshot-tested) and applied atomically with `iptables-restore --noflush` into chains we own,
 * jumped to from position 1 of OUTPUT, so the image's own rules are left alone.
 *
 * The one entry point is configure(): it needs the resolver switched over and the CA trusted
 * first, and its FirewallOn token is what the self-tests need.
 */

import * as core from '@actions/core';
import {
  CONTAINER_FWD_CHAIN,
  CONTAINER_NAT_CHAIN,
  DOCKER_USER_CHAIN,
  FILTER_CHAIN,
  FIREWALL_LOG,
  NAT_CHAIN
} from '../../constants';
import { sudo, type Host } from '../../system/host';
import type { ResolverOn } from '../coredns';
import type { TrustInstalled } from '../mitmproxy/trust';
import {
  LOCAL_BRIDGES,
  LOGGING_RULE_FILE,
  MISSING_DOCKER_USER_MESSAGE,
  buildContainerForwardRules,
  buildContainerNatRules,
  buildFilterRules,
  buildIp6ContainerForwardRules,
  buildIp6FilterRules,
  buildNatRules,
  loggingRule,
  parseDefaultRouteInterfaces,
  parseDockerSubnets,
  type FirewallOptions
} from './config';

export * from './config';

declare const firewallOn: unique symbol;
/** The rules are in place: 80/443 to the proxy, :53 to CoreDNS, the rest rejected (enforce). Minted only by configure(). */
export type FirewallOn = { readonly [firewallOn]: true };

/** Whether a chain exists in the filter table (injectable for tests). */
export type ChainCheck = (bin: 'iptables' | 'ip6tables', chain: string) => Promise<boolean>;

/** Route the rules' LOG lines to the firewall log (rsyslog), readable without sudo. */
async function setupLogging(h: Host): Promise<void> {
  await sudo(['tee', LOGGING_RULE_FILE], { input: Buffer.from(loggingRule(FIREWALL_LOG)) }, h);
  // rsyslog runs as syslog:adm and writes the log
  await sudo(['touch', FIREWALL_LOG], {}, h);
  await sudo(['chown', 'syslog:adm', FIREWALL_LOG], {}, h);
  await sudo(['chmod', '644', FIREWALL_LOG], {}, h);
  await sudo(['systemctl', 'restart', 'rsyslog'], {}, h);
}

/**
 * Report where egress actually goes. Our rules are interface-agnostic so they fail closed
 * whatever the NIC is called; this is a loud diagnostic for the unexpected cases.
 */
async function detectEgressInterface(h: Host): Promise<string[]> {
  const { stdout } = await h.output('ip', ['-4', 'route', 'show', 'default'], {
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

/** Remove our chains and jumps if present (idempotency for a re-run in the main step). */
async function removeFirewall(h: Host): Promise<void> {
  const opts = { ignoreReturnCode: true, silent: true };
  for (const [bin, table, chain] of [
    ['iptables', 'nat', NAT_CHAIN],
    ['iptables', 'filter', FILTER_CHAIN],
    ['ip6tables', 'filter', FILTER_CHAIN]
  ]) {
    // -D removes one jump per call; loop until none remain.
    for (let i = 0; i < 5; i++) {
      if ((await sudo([bin, '-t', table, '-D', 'OUTPUT', '-j', chain], opts, h)) !== 0) break;
    }
    await sudo([bin, '-t', table, '-F', chain], opts, h);
    await sudo([bin, '-t', table, '-X', chain], opts, h);
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
        if ((await sudo([bin, '-t', table, '-D', from, '-i', b, '-j', chain], opts, h)) !== 0) break;
      }
    }
  }
  for (const [bin, table, chain] of [
    ['iptables', 'nat', CONTAINER_NAT_CHAIN],
    ['iptables', 'filter', CONTAINER_FWD_CHAIN],
    ['ip6tables', 'filter', CONTAINER_FWD_CHAIN]
  ]) {
    await sudo([bin, '-t', table, '-F', chain], opts, h);
    await sudo([bin, '-t', table, '-X', chain], opts, h);
  }
}

/** True if `chain` exists in the filter table of `bin`. */
async function chainExists(h: Host, bin: 'iptables' | 'ip6tables', chain: string): Promise<boolean> {
  const rc = await sudo(
    [bin, '-t', 'filter', '-n', '-L', chain],
    {
      ignoreReturnCode: true,
      silent: true
    },
    h
  );
  return rc === 0;
}

/**
 * Apply the full ruleset. Order matters: nat (redirect) and filter go in together per
 * table; IPv6 last. The proxy must already be listening.
 *
 * Returns whether the container rules were applied. enforce fails closed instead of running
 * with containers outside the rules: it throws before anything is changed.
 */
async function applyFirewall(h: Host, o: FirewallOptions, hasChain: ChainCheck): Promise<{ containerRules: boolean }> {
  let containerRules = false;
  let ip6Hook = 'FORWARD';
  if (o.containers) {
    if (await hasChain('iptables', DOCKER_USER_CHAIN)) {
      containerRules = true;
      if (await hasChain('ip6tables', DOCKER_USER_CHAIN)) ip6Hook = DOCKER_USER_CHAIN;
    } else if (o.mode === 'enforce') {
      throw new Error(`${MISSING_DOCKER_USER_MESSAGE}. Use docker: stop, or mode: analyze.`);
    } else {
      core.warning(`${MISSING_DOCKER_USER_MESSAGE}: container egress is not monitored`);
    }
  }
  await removeFirewall(h);
  // REDIRECT to 127.0.0.1 of packets that were routed to another interface
  await sudo(['sysctl', '-q', '-w', 'net.ipv4.conf.all.route_localnet=1'], {}, h);
  let v4 = buildNatRules(o) + buildFilterRules(o);
  let v6 = buildIp6FilterRules(o);
  if (containerRules) {
    v4 += buildContainerNatRules(o) + buildContainerForwardRules(o);
    v6 += buildIp6ContainerForwardRules(o, ip6Hook);
  }
  await sudo(['iptables-restore', '--noflush'], { input: Buffer.from(v4) }, h);
  const rc6 = await sudo(
    ['ip6tables-restore', '--noflush'],
    {
      input: Buffer.from(v6),
      ignoreReturnCode: true
    },
    h
  );
  if (rc6 !== 0) {
    const msg = 'ip6tables rules could not be applied';
    if (o.mode === 'enforce') throw new Error(msg);
    core.warning(msg);
  }
  return { containerRules };
}

/**
 * Drop conntrack entries of flows sourced from the container networks. Without this, a
 * service container's connections that predate the rules keep going via ESTABLISHED (the
 * forwarded-traffic counterpart of killPreexistingConnections).
 */
async function flushContainerConntrack(h: Host): Promise<void> {
  const opts = { ignoreReturnCode: true, silent: true };
  const ids = await h.output('sudo', ['docker', 'network', 'ls', '-q', '--filter', 'driver=bridge'], opts);
  const netIds = ids.stdout.split('\n').filter(Boolean);
  let subnets = ['172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8'];
  if (netIds.length > 0) {
    const inspect = await h.output('sudo', ['docker', 'network', 'inspect', ...netIds], opts);
    const found = parseDockerSubnets(inspect.stdout);
    if (found.length > 0) subnets = found;
  }
  if ((await h.run('sh', ['-c', 'command -v conntrack'], opts)) !== 0) {
    core.warning('conntrack not installed: container connections that predate the rules may continue');
    return;
  }
  for (const s of subnets) {
    // exit 1 = nothing matched
    await sudo(['conntrack', '-D', '-f', s.includes(':') ? 'ipv6' : 'ipv4', '-s', s], opts, h);
  }
  core.info(`Flushed container conntrack entries for ${subnets.join(', ')}`);
}

/**
 * Kill established :80/:443 connections that predate the REDIRECT (runner long-polls etc.),
 * so the cutover is immediate: they reconnect through the proxy instead of being rejected
 * mid-stream later.
 */
async function killPreexistingConnections(h: Host): Promise<void> {
  const rc = await sudo(
    ['ss', '-K', 'state', 'established', '( dport = :443 or dport = :80 )'],
    {
      ignoreReturnCode: true,
      silent: true
    },
    h
  );
  if (rc !== 0) core.warning('ss -K failed: pre-existing connections will be cut off by the firewall instead');
}

/** Human-readable dump of what we installed (job log). */
async function logFirewall(h: Host): Promise<void> {
  const opts = { ignoreReturnCode: true };
  await sudo(['iptables', '-t', 'nat', '-S', NAT_CHAIN], opts, h);
  await sudo(['iptables', '-S', FILTER_CHAIN], opts, h);
  await sudo(['ip6tables', '-S', FILTER_CHAIN], opts, h);
  await sudo(['iptables', '-t', 'nat', '-S', CONTAINER_NAT_CHAIN], opts, h);
  await sudo(['iptables', '-S', CONTAINER_FWD_CHAIN], opts, h);
  await sudo(['iptables', '-S', DOCKER_USER_CHAIN], opts, h);
}

/**
 * The firewall step: LOG routing, the rulesets (DOCKER-USER checked before anything changes),
 * then the cutover of connections that predate them. Only once the resolver points at CoreDNS
 * and the CA is trusted, so nothing is forced through the proxy or the resolver before they
 * are ready for it.
 */
export async function configure(
  h: Host,
  o: FirewallOptions,
  _after: { resolver: ResolverOn; trust: TrustInstalled },
  hasChain: ChainCheck = (bin, chain) => chainExists(h, bin, chain)
): Promise<{ containerRules: boolean; firewall: FirewallOn }> {
  await setupLogging(h);
  await detectEgressInterface(h);
  const { containerRules } = await applyFirewall(h, o, hasChain);
  await killPreexistingConnections(h);
  if (containerRules) await flushContainerConntrack(h);
  await logFirewall(h);
  return { containerRules, firewall: Object.freeze({}) as FirewallOn };
}
