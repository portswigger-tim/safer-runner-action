import { buildFilterRules, buildIp6FilterRules, buildNatRules, parseDefaultRouteInterfaces } from './firewall';

const base = { proxyUid: 990, dnsUid: 61234, proxyPort: 8080, dnsServers: ['9.9.9.9', '149.112.112.112'] };

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
