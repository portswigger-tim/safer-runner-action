import * as core from '@actions/core';
import { FIREWALL_LOG } from '../../constants';
import { recordingHost } from '../../system/testing';
import type { ResolverOn } from '../coredns';
import type { DockerPrepared } from '../docker';
import type { TrustInstalled } from '../mitmproxy/trust';
import {
  LOGGING_RULE_FILE,
  LOG_PREFIXES,
  MISSING_DOCKER_USER_MESSAGE,
  configure,
  loggingRule,
  buildContainerForwardRules,
  buildContainerNatRules,
  buildFilterRules,
  buildIp6ContainerForwardRules,
  buildIp6FilterRules,
  buildNatRules,
  parseDefaultRouteInterfaces,
  parseDockerSubnets
} from '.';

jest.mock('@actions/core');

/** tokens for tests that call the step directly */
const AFTER = {
  resolver: Object.freeze({}) as ResolverOn,
  trust: Object.freeze({}) as TrustInstalled,
  docker: Object.freeze({}) as DockerPrepared
};

const base = {
  proxyUid: 990,
  dnsUid: 61234,
  proxyPort: 8080,
  containerProxyPort: 8081,
  containers: true,
  dnsServers: ['9.9.9.9', '149.112.112.112']
};

describe('buildNatRules', () => {
  const rules = buildNatRules({ ...base, mode: 'enforce' }).split('\n');

  it('exempts the proxy and dnsmasq uids before any redirect', () => {
    const proxy = rules.indexOf('-A SAFER_RUNNER_NAT -m owner --uid-owner 990 -j RETURN');
    const dns = rules.indexOf('-A SAFER_RUNNER_NAT -m owner --uid-owner 61234 -j RETURN');
    const firstRedirect = rules.findIndex(r => r.includes('REDIRECT'));
    expect(proxy).toBeGreaterThan(0);
    expect(dns).toBeGreaterThan(0);
    expect(proxy).toBeLessThan(firstRedirect);
    expect(dns).toBeLessThan(firstRedirect);
  });

  it('redirects all DNS to dnsmasq before the loopback/Azure exemptions', () => {
    const dnsRedirect = rules.indexOf('-A SAFER_RUNNER_NAT -p udp --dport 53 -j REDIRECT --to-ports 53');
    const azure = rules.indexOf('-A SAFER_RUNNER_NAT -d 168.63.129.16/32 -j RETURN');
    expect(dnsRedirect).toBeGreaterThan(0);
    expect(rules).toContain('-A SAFER_RUNNER_NAT -p tcp --dport 53 -j REDIRECT --to-ports 53');
    // so `dig @168.63.129.16` is answered by dnsmasq, not the open Azure resolver
    expect(dnsRedirect).toBeLessThan(azure);
  });

  it('redirects 80/443 to the proxy port last and hooks OUTPUT at position 1', () => {
    expect(rules).toContain('-A SAFER_RUNNER_NAT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8080');
    expect(rules).toContain('-I OUTPUT 1 -j SAFER_RUNNER_NAT');
    expect(rules[0]).toBe('*nat');
    expect(rules).toContain('COMMIT');
  });

  it('honours a custom proxy port', () => {
    expect(buildNatRules({ ...base, mode: 'enforce', proxyPort: 18080 })).toContain('--to-ports 18080');
  });
});

describe('buildFilterRules (enforce)', () => {
  const text = buildFilterRules({ ...base, mode: 'enforce' });
  const rules = text.split('\n');

  it('is interface-agnostic (no eth0 scoping)', () => {
    expect(text).not.toContain('eth0');
  });

  it('allows the proxy uid only on 80/443', () => {
    expect(rules).toContain(
      '-A SAFER_RUNNER_OUT -m owner --uid-owner 990 -p tcp -m multiport --dports 80,443 -j RETURN'
    );
    expect(rules.filter(r => r.includes('--uid-owner 990'))).toHaveLength(1);
  });

  it('allows dnsmasq only to its upstream servers on 53', () => {
    for (const s of base.dnsServers) {
      expect(rules).toContain(`-A SAFER_RUNNER_OUT -m owner --uid-owner 61234 -d ${s}/32 -p udp --dport 53 -j RETURN`);
      expect(rules).toContain(`-A SAFER_RUNNER_OUT -m owner --uid-owner 61234 -d ${s}/32 -p tcp --dport 53 -j RETURN`);
    }
  });

  it('scopes the Azure platform allows and never allows wireserver DNS', () => {
    expect(rules).toContain('-A SAFER_RUNNER_OUT -d 169.254.169.254/32 -p tcp --dport 80 -j RETURN');
    expect(rules).toContain('-A SAFER_RUNNER_OUT -d 168.63.129.16/32 -p tcp -m multiport --dports 80,32526 -j RETURN');
    expect(rules.filter(r => r.includes('168.63.129.16'))).toHaveLength(1);
  });

  it('allows REDIRECTed (post-NAT 127/8) traffic before any reject - `-o lo` does not match it', () => {
    const allow = rules.indexOf('-A SAFER_RUNNER_OUT -d 127.0.0.0/8 -j RETURN');
    const firstReject = rules.findIndex(r => r.includes('REJECT') || r.includes('LOG'));
    expect(allow).toBeGreaterThan(0);
    expect(allow).toBeLessThan(firstReject);
  });

  it('ends with log + reject (fail closed)', () => {
    const body = rules.filter(r => r.startsWith('-A'));
    expect(body.slice(-3)[0]).toMatch(/-j LOG --log-prefix "SaferRunner-Drop: "/);
    expect(body.slice(-2)).toEqual([
      '-A SAFER_RUNNER_OUT -p tcp -j REJECT --reject-with tcp-reset',
      '-A SAFER_RUNNER_OUT -j REJECT --reject-with icmp-port-unreachable'
    ]);
    expect(rules).toContain('-I OUTPUT 1 -j SAFER_RUNNER_OUT');
  });
});

describe('buildFilterRules (analyze)', () => {
  const text = buildFilterRules({ ...base, mode: 'analyze' });

  it('does not reject general egress, but rejects QUIC and logs new connections', () => {
    expect(text).not.toContain('--reject-with tcp-reset');
    expect(text).toContain('-A SAFER_RUNNER_OUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable');
    expect(text).toContain('--log-prefix "SaferRunner-Egress: "');
  });
});

describe('buildIp6FilterRules', () => {
  it('enforce rejects all non-loopback IPv6 egress', () => {
    const text = buildIp6FilterRules({ ...base, mode: 'enforce' });
    expect(text).toContain('-A SAFER_RUNNER_OUT -o lo -j RETURN');
    expect(text).toContain('-A SAFER_RUNNER_OUT -j REJECT --reject-with icmp6-port-unreachable');
  });

  it('analyze rejects only web ports so clients fall back to IPv4', () => {
    const text = buildIp6FilterRules({ ...base, mode: 'analyze' });
    expect(text).toContain('--dports 80,443 -j REJECT');
    expect(text).not.toContain('-A SAFER_RUNNER_OUT -j REJECT');
  });
});

describe('parseDefaultRouteInterfaces', () => {
  it('extracts the default route device', () => {
    expect(parseDefaultRouteInterfaces('default via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.4 metric 100\n')).toEqual([
      'eth0'
    ]);
  });
  it('handles multiple and no defaults', () => {
    expect(
      parseDefaultRouteInterfaces('default via 1.1.1.1 dev ens5\ndefault via 2.2.2.2 dev eth1 metric 200')
    ).toEqual(['ens5', 'eth1']);
    expect(parseDefaultRouteInterfaces('')).toEqual([]);
  });
});

describe('container rules', () => {
  it('nat: snapshot (enforce and analyze are identical - DNAT is for visibility too)', () => {
    const text = buildContainerNatRules({ ...base, mode: 'enforce' });
    expect(text).toMatchSnapshot();
    expect(buildContainerNatRules({ ...base, mode: 'analyze' })).toBe(text);
  });

  it('nat: leaves host-local and private destinations alone before any DNAT', () => {
    const rules = buildContainerNatRules({ ...base, mode: 'enforce' }).split('\n');
    const local = rules.indexOf('-A SAFER_RUNNER_CNAT -m addrtype --dst-type LOCAL -j RETURN');
    const priv = rules.indexOf('-A SAFER_RUNNER_CNAT -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j RETURN');
    const firstDnat = rules.findIndex(r => r.includes('DNAT'));
    expect(local).toBeGreaterThan(0);
    expect(priv).toBeGreaterThan(local);
    expect(firstDnat).toBeGreaterThan(priv);
  });

  it('nat: sends DNS to dnsmasq and 80/443 to the container listener', () => {
    const text = buildContainerNatRules({ ...base, mode: 'enforce', containerProxyPort: 18081 });
    expect(text).toContain('-A SAFER_RUNNER_CNAT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53');
    expect(text).toContain('-A SAFER_RUNNER_CNAT -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:53');
    expect(text).toContain(
      '-A SAFER_RUNNER_CNAT -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 127.0.0.1:18081'
    );
    expect(text).toContain('-I PREROUTING 1 -i docker0 -j SAFER_RUNNER_CNAT');
    expect(text).toContain('-I PREROUTING 1 -i br-+ -j SAFER_RUNNER_CNAT');
  });

  it('forward (enforce): snapshot; same-bridge and established first, then log + reject', () => {
    const text = buildContainerForwardRules({ ...base, mode: 'enforce' });
    expect(text).toMatchSnapshot();
    const body = text.split('\n').filter(r => r.startsWith('-A'));
    expect(body.slice(0, 3)).toEqual([
      '-A SAFER_RUNNER_CFWD -o docker0 -j RETURN',
      '-A SAFER_RUNNER_CFWD -o br-+ -j RETURN',
      '-A SAFER_RUNNER_CFWD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
    ]);
    expect(body.slice(-3)[0]).toContain('--log-prefix "SaferRunner-CDrop: "');
    expect(body.slice(-2)).toEqual([
      '-A SAFER_RUNNER_CFWD -p tcp -j REJECT --reject-with tcp-reset',
      '-A SAFER_RUNNER_CFWD -j REJECT --reject-with icmp-port-unreachable'
    ]);
    expect(text).toContain('-I DOCKER-USER 1 -i docker0 -j SAFER_RUNNER_CFWD');
    expect(text).toContain('-I DOCKER-USER 1 -i br-+ -j SAFER_RUNNER_CFWD');
    // never declares DOCKER-USER itself: iptables-restore would flush Docker's chain
    expect(text).not.toContain(':DOCKER-USER');
  });

  it('forward (analyze): logs, rejects only QUIC', () => {
    const text = buildContainerForwardRules({ ...base, mode: 'analyze' });
    expect(text).toMatchSnapshot();
    expect(text).toContain('--log-prefix "SaferRunner-CEgress: "');
    expect(text).not.toContain('tcp-reset');
    expect(text).toContain('-A SAFER_RUNNER_CFWD -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable');
  });

  it('ip6 forward: fails closed in enforce, hooks the given chain', () => {
    const text = buildIp6ContainerForwardRules({ ...base, mode: 'enforce' });
    expect(text).toMatchSnapshot();
    expect(text).toContain('-A SAFER_RUNNER_CFWD -j REJECT --reject-with icmp6-port-unreachable');
    expect(text).toContain('-I DOCKER-USER 1 -i docker0 -j SAFER_RUNNER_CFWD');
    const fwd = buildIp6ContainerForwardRules({ ...base, mode: 'enforce' }, 'FORWARD');
    expect(fwd).toContain('-I FORWARD 1 -i br-+ -j SAFER_RUNNER_CFWD');
    expect(fwd).not.toContain('DOCKER-USER');
  });

  it('ip6 forward (analyze): pushes web ports back to IPv4', () => {
    const text = buildIp6ContainerForwardRules({ ...base, mode: 'analyze' });
    expect(text).toContain('--dports 80,443 -j REJECT --reject-with tcp-reset');
    expect(text).not.toContain('-A SAFER_RUNNER_CFWD -j REJECT');
  });

  it('host rules do not change when containers are on', () => {
    expect(buildNatRules({ ...base, mode: 'enforce' })).toBe(
      buildNatRules({ ...base, mode: 'enforce', containers: false })
    );
    expect(buildNatRules({ ...base, mode: 'enforce' })).not.toContain('8081');
  });
});

describe('configure: container hook (C3)', () => {
  /** a runner where DOCKER-USER exists for iptables (v4) and/or ip6tables (v6) */
  const runner = (v4: boolean, v6: boolean) =>
    recordingHost(l => {
      if (l === 'sudo iptables -t filter -n -L DOCKER-USER') return v4 ? 0 : 1;
      if (l === 'sudo ip6tables -t filter -n -L DOCKER-USER') return v6 ? 0 : 1;
      return 0;
    });
  const restored = (stdin: Record<string, string>) =>
    `${stdin['sudo iptables-restore --noflush'] ?? ''}\n${stdin['sudo ip6tables-restore --noflush'] ?? ''}`;
  const changesRules = (c: string) => / -D | -F | -X |sysctl|-restore /.test(c);

  beforeEach(() => jest.clearAllMocks());

  it('enforce: fails closed before changing anything when DOCKER-USER is missing', async () => {
    const { host, calls } = runner(false, false);
    await expect(configure(host, { ...base, mode: 'enforce' }, AFTER)).rejects.toThrow(MISSING_DOCKER_USER_MESSAGE);
    expect(calls.filter(changesRules)).toEqual([]);
    expect(calls).toContain('sudo iptables -t filter -n -L DOCKER-USER [ignore-rc] [silent]');
  });

  it('analyze: warns, applies the host rules and reports no container rules', async () => {
    const { host, stdin } = runner(false, false);
    const r = await configure(host, { ...base, mode: 'analyze' }, AFTER);
    expect(r.containerRules).toBe(false);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining(MISSING_DOCKER_USER_MESSAGE));
    expect(restored(stdin)).toContain('SAFER_RUNNER_OUT');
    expect(restored(stdin)).not.toContain('SAFER_RUNNER_CFWD');
  });

  it.each(['enforce', 'analyze'] as const)('%s: applies and reports the container rules when hooked', async mode => {
    const { host, stdin } = runner(true, false);
    const r = await configure(host, { ...base, mode }, AFTER);
    expect(r.containerRules).toBe(true);
    expect(restored(stdin)).toContain('-I DOCKER-USER 1 -i docker0 -j SAFER_RUNNER_CFWD');
    // no IPv6 DOCKER-USER: hook FORWARD instead
    expect(restored(stdin)).toContain('-I FORWARD 1 -i docker0 -j SAFER_RUNNER_CFWD');
  });

  it('without docker: no hook lookup, no container rules', async () => {
    const { host, calls } = runner(false, false);
    const r = await configure(host, { ...base, mode: 'enforce', containers: false }, AFTER);
    expect(r.containerRules).toBe(false);
    expect(calls.some(c => c.includes('DOCKER-USER') && c.includes(' -n -L '))).toBe(false);
  });
});

describe('configure: the step', () => {
  it('logging rule, then the rules (v4 atomically before v6), then the cutover of old connections', async () => {
    const { host, calls, stdin } = recordingHost();
    await configure(host, { ...base, mode: 'enforce', containers: false }, AFTER);
    const at = (prefix: string) => calls.findIndex(c => c.startsWith(prefix));
    expect(calls[0]).toBe(`sudo tee ${LOGGING_RULE_FILE}`);
    expect(stdin[`sudo tee ${LOGGING_RULE_FILE}`]).toBe(loggingRule(FIREWALL_LOG));
    expect(calls.slice(1, 5)).toEqual([
      `sudo touch ${FIREWALL_LOG}`,
      `sudo chown syslog:adm ${FIREWALL_LOG}`,
      `sudo chmod 644 ${FIREWALL_LOG}`,
      'sudo systemctl restart rsyslog'
    ]);
    expect(at('sudo sysctl')).toBeLessThan(at('sudo iptables-restore'));
    expect(at('sudo iptables-restore')).toBeLessThan(at('sudo ip6tables-restore'));
    expect(at('sudo ip6tables-restore')).toBeLessThan(at('sudo ss -K'));
    // the v4 rules fail loudly; only ip6tables-restore's code is checked by hand
    expect(calls).toContain('sudo iptables-restore --noflush');
    expect(calls).toContain('sudo ip6tables-restore --noflush [ignore-rc]');
  });

  it('enforce: an ip6tables-restore failure fails the step; analyze warns', async () => {
    const failing = () => recordingHost(l => (l.startsWith('sudo ip6tables-restore') ? 2 : 0));
    await expect(configure(failing().host, { ...base, mode: 'enforce', containers: false }, AFTER)).rejects.toThrow(
      'ip6tables rules could not be applied'
    );
    await configure(failing().host, { ...base, mode: 'analyze', containers: false }, AFTER);
    expect(core.warning).toHaveBeenCalledWith('ip6tables rules could not be applied');
  });

  it('needs the resolver switched over, the CA trusted and dockerd settled first (a compile-time order check)', () => {
    const { host } = recordingHost();
    const o = { ...base, mode: 'enforce' as const };
    // @ts-expect-error - the firewall before the resolver points at CoreDNS does not compile
    const noResolver = () => configure(host, o, { trust: AFTER.trust, docker: AFTER.docker });
    // @ts-expect-error - nor before the CA is in the trust stores
    const noTrust = () => configure(host, o, { resolver: AFTER.resolver, trust: {}, docker: AFTER.docker });
    // @ts-expect-error - nor before dockerd is settled (its restart rebuilds Docker's chains)
    const noDocker = () => configure(host, o, { resolver: AFTER.resolver, trust: AFTER.trust });
    expect([noResolver, noTrust, noDocker]).toHaveLength(3);
  });
});

describe('loggingRule', () => {
  it("copies only the kernel's LOG lines with our prefixes to the log", () => {
    expect(loggingRule('/var/log/x.log', ['A-Drop', 'B-Egress'])).toBe(
      "if $programname == 'kernel' and $msg contains ['A-Drop', 'B-Egress'] then /var/log/x.log\n"
    );
  });

  it('covers every prefix the rulesets log with', () => {
    expect(LOG_PREFIXES).toEqual([
      'SaferRunner-Drop:',
      'SaferRunner-Egress:',
      'SaferRunner-CDrop:',
      'SaferRunner-CEgress:'
    ]);
    const rules = [buildFilterRules, buildIp6FilterRules, buildContainerForwardRules]
      .flatMap(f => (['enforce', 'analyze'] as const).map(mode => f({ ...base, mode })))
      .join('\n');
    for (const m of rules.matchAll(/--log-prefix "([^"]+) "/g)) expect(LOG_PREFIXES).toContain(m[1]);
  });
});

describe('parseDockerSubnets', () => {
  it('collects bridge subnets, skips host/null networks and junk', () => {
    const json = JSON.stringify([
      { Name: 'bridge', Driver: 'bridge', IPAM: { Config: [{ Subnet: '172.17.0.0/16', Gateway: '172.17.0.1' }] } },
      { Name: 'host', Driver: 'host', IPAM: { Config: [] } },
      { Name: 'gh-net', Driver: 'bridge', IPAM: { Config: [{ Subnet: '172.18.0.0/16' }, { Subnet: 'fd00::/64' }] } },
      { Name: 'dup', Driver: 'bridge', IPAM: { Config: [{ Subnet: '172.17.0.0/16' }] } }
    ]);
    expect(parseDockerSubnets(json)).toEqual(['172.17.0.0/16', '172.18.0.0/16', 'fd00::/64']);
    expect(parseDockerSubnets('Error: no such network')).toEqual([]);
    expect(parseDockerSubnets('')).toEqual([]);
  });
});
