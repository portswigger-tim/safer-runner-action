import { parseFlowLog } from './flowlog';
import { buildReport, humanBytes, parseFirewallLog, suggestedAllowlist, summarizeFlows } from './report';

const log = [
  { ev: 'start', ok: true },
  { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'api.github.com', dst: '1.2.3.4:443' },
  {
    ev: 'https',
    verdict: 'ALLOW',
    host: 'api.github.com',
    sni: 'api.github.com',
    status: 200,
    req_bytes: 10,
    resp_bytes: 2048,
    dst: '1.2.3.4:443'
  },
  {
    ev: 'https',
    verdict: 'ALLOW',
    host: 'api.github.com',
    sni: 'api.github.com',
    status: 200,
    req_bytes: 0,
    resp_bytes: 1024
  },
  { ev: 'tls', verdict: 'BLOCK', reason: 'sni-not-allowed', layer: 'sni', sni: 'evil.example.com', dst: '9.9.9.9:443' },
  { ev: 'tls', verdict: 'BLOCK', reason: 'no-sni', layer: 'sni', sni: null, dst: '1.1.1.1:443' },
  {
    ev: 'https',
    verdict: 'BLOCK',
    reason: 'host-sni-mismatch',
    layer: 'http',
    host: 'api.github.com',
    sni: 'github.com',
    status: 403
  },
  {
    ev: 'tls',
    verdict: 'PASSTHROUGH',
    reason: 'passthrough',
    layer: 'sni',
    sni: 'hosted-compute-x.githubapp.com',
    passthrough: true
  },
  { ev: 'server-connect', address: 'api.github.com:443', peername: '1.2.3.4:443' }
]
  .map(r => JSON.stringify(r))
  .join('\n');

describe('summarizeFlows', () => {
  const hosts = summarizeFlows(parseFlowLog(log + '\n{"partial'));

  it('lists denied rows first', () => {
    expect(hosts[0].verdict).toBe('BLOCK');
    expect(hosts[hosts.length - 1].verdict).not.toBe('BLOCK');
  });

  it('keeps refused attempts and allowed traffic for the same name in separate rows', () => {
    const api = hosts.filter(h => h.name === 'api.github.com');
    expect(api).toHaveLength(2);
    const blocked = api.find(h => h.verdict === 'BLOCK')!;
    const allowed = api.find(h => h.verdict !== 'BLOCK')!;
    // the fronting attempt (Host api.github.com inside SNI github.com)
    expect(blocked.reasons).toEqual(['host-sni-mismatch']);
    expect(blocked.requests).toBe(1);
    expect(allowed.requests).toBe(2);
    expect(allowed.connections).toBe(1);
    expect(allowed.respBytes).toBe(3072);
    expect(allowed.statuses).toEqual({ '200': 2 });
  });

  it('names no-SNI connections by the dialled address', () => {
    expect(hosts.map(h => h.name)).toContain('(no name) 1.1.1.1:443');
  });

  it('records passthrough', () => {
    const p = hosts.find(h => h.name.startsWith('hosted-compute'))!;
    expect(p.verdict).toBe('PASSTHROUGH');
    expect(p.kinds).toEqual(['passthrough']);
  });

  it('ignores non-decision records', () => {
    expect(hosts.find(h => h.name.includes('server-connect'))).toBeUndefined();
    expect(hosts).toHaveLength(5);
  });
});

describe('parseFirewallLog', () => {
  it('extracts our kernel LOG lines', () => {
    const ev = parseFirewallLog(
      'Nov  4 18:00:00 vm kernel: [1.2] SaferRunner-Drop: IN= OUT=eth0 SRC=10.1.0.4 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=4 DPT=853 UID=1001 GID=1001\n' +
        'Nov  4 18:00:01 vm kernel: unrelated\n'
    );
    expect(ev).toEqual([{ prefix: 'SaferRunner-Drop', proto: 'TCP', dst: '1.1.1.1', dport: '853', uid: '1001' }]);
  });
});

describe('buildReport', () => {
  const hosts = summarizeFlows(parseFlowLog(log));

  it('enforce: blocked section first, nothing about suggestions', () => {
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts,
      firewall: [],
      dnsRefused: ['x.example'],
      selfTests: [],
      extraSections: []
    });
    expect(md.indexOf('Blocked')).toBeLessThan(md.indexOf('Allowed'));
    expect(md).toContain('evil.example.com');
    expect(md).toContain('`x.example`');
    expect(md).not.toContain('Suggested configuration');
  });

  it('analyze: suggests would-be-blocked names, never .invalid or nameless ones', () => {
    const wb = summarizeFlows(
      parseFlowLog(
        [
          { ev: 'tls', verdict: 'WOULD_BLOCK', reason: 'sni-not-allowed', layer: 'sni', sni: 'registry.npmjs.org' },
          {
            ev: 'tls',
            verdict: 'WOULD_BLOCK',
            reason: 'sni-not-allowed',
            layer: 'sni',
            sni: 'selftest.safer-runner.invalid'
          },
          { ev: 'tls', verdict: 'WOULD_BLOCK', reason: 'no-sni', layer: 'sni', sni: null, dst: '1.1.1.1:443' },
          { ev: 'https', verdict: 'WOULD_BLOCK', reason: 'host-sni-mismatch', layer: 'http', host: 'api.github.com' }
        ]
          .map(r => JSON.stringify(r))
          .join('\n')
      )
    );
    expect(suggestedAllowlist(wb)).toEqual(['registry.npmjs.org']);
    const md = buildReport({
      mode: 'analyze',
      job: 'j',
      hosts: wb,
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      extraSections: []
    });
    expect(md).toContain('Would be blocked (4)');
    expect(md).toContain('      registry.npmjs.org');
  });

  it('says explicitly when rows are cut', () => {
    const many = Array.from({ length: 305 }, (_, i) => ({
      ev: 'tls',
      verdict: 'BLOCK',
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: `h${i}.example.com`
    }));
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts: summarizeFlows(parseFlowLog(many.map(r => JSON.stringify(r)).join('\n'))),
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      extraSections: []
    });
    expect(md).toContain('+5 more not shown here');
  });

  it('escapes table-breaking characters in hostnames', () => {
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts: summarizeFlows(parseFlowLog(JSON.stringify({ ev: 'http', verdict: 'BLOCK', reason: 'x', host: 'a|<b>' }))),
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      extraSections: []
    });
    expect(md).toContain('a\\|&lt;b>');
  });
});

describe('humanBytes', () => {
  it('formats', () => {
    expect(humanBytes(10)).toBe('10 B');
    expect(humanBytes(2048)).toBe('2.0 KiB');
    expect(humanBytes(5 * 1024 * 1024)).toBe('5.0 MiB');
  });
});

describe('upstream IP guard records (H1)', () => {
  it('reports a name refused for resolving to an internal address as blocked', () => {
    const hosts = summarizeFlows(
      parseFlowLog(
        [
          {
            ev: 'upstream',
            verdict: 'BLOCK',
            reason: 'upstream-ip-forbidden',
            layer: 'ip',
            host: 'imds.example.org',
            dst: '169.254.169.254:80'
          },
          {
            ev: 'http',
            verdict: 'BLOCK',
            reason: 'upstream-ip-forbidden',
            layer: 'http',
            host: 'imds.example.org',
            error: 'Connection killed: safer-runner: upstream blocked (upstream-ip-forbidden)'
          }
        ]
          .map(r => JSON.stringify(r))
          .join('\n')
      )
    );
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({ name: 'imds.example.org', verdict: 'BLOCK', connections: 1, requests: 1 });
    expect(hosts[0].reasons).toEqual(['upstream-ip-forbidden']);
    expect(hosts[0].dsts).toEqual(['169.254.169.254']);
  });
});
