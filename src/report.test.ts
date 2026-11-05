import * as fs from 'fs';
import * as path from 'path';
import { parseFlowLog } from './flowlog';
import { buildReport, humanBytes, modeLabel, parseFirewallLog, suggestedAllowlist, summarizeFlows } from './report';

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
    // the resolved address is evidence of what the name points at, not what the client dialled
    expect(hosts[0].upstreamIps).toEqual(['169.254.169.254']);
    expect(hosts[0].dsts).toEqual([]);
  });
});

describe('reconciling refused connections (no host is both allowed and blocked)', () => {
  const real = summarizeFlows(
    parseFlowLog(fs.readFileSync(path.join(__dirname, '__fixtures__', 'beta2-enforce-flows.jsonl'), 'utf8'))
  );
  const allowedRows = real.filter(h => !['BLOCK', 'WOULD_BLOCK'].includes(h.verdict));
  const blockedRows = real.filter(h => ['BLOCK', 'WOULD_BLOCK'].includes(h.verdict));

  // beta.2 listed these under Allowed too: the SNI check passed, then the upstream IP guard refused
  it.each(['100.64.0.1.nip.io', '127.0.0.1.nip.io', '100-64-0-1.sslip.io'])(
    '%s is only blocked, never allowed',
    name => {
      expect(allowedRows.map(h => h.name)).not.toContain(name);
      expect(blockedRows.map(h => h.name)).toContain(name);
    }
  );

  it('moves an intercepted TLS connection refused upstream to the refusal', () => {
    const recs = [
      { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'x.nip.io', client: 'c:1' },
      {
        ev: 'upstream',
        verdict: 'BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'ip',
        host: 'x.nip.io',
        dst: '10.0.0.1:443',
        client: 'c:1'
      },
      {
        ev: 'https',
        verdict: 'BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'http',
        host: 'x.nip.io',
        sni: 'x.nip.io',
        client: 'c:1',
        req_bytes: 0,
        resp_bytes: 0
      }
    ];
    const hosts = summarizeFlows(parseFlowLog(recs.map(r => JSON.stringify(r)).join('\n')));
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({ name: 'x.nip.io', verdict: 'BLOCK', tries: 1, upstreamIps: ['10.0.0.1'] });
  });

  it('moves a passthrough connection refused upstream to the refusal', () => {
    const recs = [
      {
        ev: 'tls',
        verdict: 'PASSTHROUGH',
        reason: 'passthrough',
        layer: 'sni',
        sni: 'p.sslip.io',
        passthrough: true,
        client: 'c:2'
      },
      {
        ev: 'upstream',
        verdict: 'BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'ip',
        host: 'p.sslip.io',
        dst: '100.64.0.1:443',
        client: 'c:2'
      }
    ];
    const hosts = summarizeFlows(parseFlowLog(recs.map(r => JSON.stringify(r)).join('\n')));
    expect(hosts.map(h => h.verdict)).toEqual(['BLOCK']);
  });

  it('analyze: traffic on a connection the guard would refuse is reported as would-be-blocked', () => {
    const recs = [
      { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'x.nip.io', client: 'c:3' },
      {
        ev: 'upstream',
        verdict: 'WOULD_BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'ip',
        host: 'x.nip.io',
        dst: '10.0.0.1:443',
        client: 'c:3'
      },
      {
        ev: 'https',
        verdict: 'ALLOW',
        reason: 'allowed',
        layer: 'http',
        host: 'x.nip.io',
        sni: 'x.nip.io',
        client: 'c:3',
        status: 200,
        resp_bytes: 9
      }
    ];
    const hosts = summarizeFlows(parseFlowLog(recs.map(r => JSON.stringify(r)).join('\n')));
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({ verdict: 'WOULD_BLOCK', reasons: ['upstream-ip-forbidden'], requests: 1 });
  });

  it('a reused client port does not taint a later, unrelated connection', () => {
    const recs = [
      {
        ev: 'upstream',
        verdict: 'BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'ip',
        host: 'bad.nip.io',
        dst: '10.0.0.1:80',
        client: 'c:4'
      },
      {
        ev: 'http',
        verdict: 'BLOCK',
        reason: 'upstream-ip-forbidden',
        layer: 'http',
        host: 'bad.nip.io',
        client: 'c:4'
      },
      { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'pypi.org', client: 'c:4' },
      {
        ev: 'https',
        verdict: 'ALLOW',
        reason: 'allowed',
        layer: 'http',
        host: 'pypi.org',
        sni: 'pypi.org',
        client: 'c:4',
        status: 200
      }
    ];
    const hosts = summarizeFlows(parseFlowLog(recs.map(r => JSON.stringify(r)).join('\n')));
    expect(hosts.find(h => h.name === 'pypi.org')).toMatchObject({ verdict: 'INTERCEPT', requests: 1 });
  });

  it('records the TLS name that carried a fronted Host', () => {
    const evil = blockedRows.find(h => h.name === 'evil.example.com')!;
    expect(evil.reasons).toEqual(['sni-not-allowed', 'host-sni-mismatch']);
    expect(evil.snis).toEqual(['github.com']);
    expect(evil.tries).toBe(2);
  });
});

describe('enforce labelling (review H2)', () => {
  const base = { job: 'j', hosts: [], firewall: [], dnsRefused: [], selfTests: [], extraSections: [] };

  it('labels enforce with sudo retained as ADVISORY in the header and the mode', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true });
    expect(md.split('\n')[0]).toBe(
      '# Safer Runner v2 egress report — enforce (ADVISORY — sudo retained, not an enforced boundary)'
    );
    expect(md).toContain('> [!WARNING]');
    expect(md).toContain('**Mode:** ⚠️ ENFORCE (ADVISORY — sudo retained, not an enforced boundary)');
  });

  it('labels enforce with sudo removed as plain enforce', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: false });
    expect(md.split('\n')[0]).toBe('# Safer Runner v2 egress report');
    expect(md).not.toContain('ADVISORY');
    expect(md).toContain('**Mode:** 🔒 ENFORCE');
  });

  it('never labels analyze as advisory enforce', () => {
    expect(modeLabel('analyze', true)).toBe('📊 ANALYZE');
    expect(buildReport({ ...base, mode: 'analyze', sudoRetained: true })).not.toContain('ADVISORY —');
  });

  it('warns when enforce left docker (root-equivalent) in place', () => {
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: true })).toContain('> [!CAUTION]');
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: false })).not.toContain('[!CAUTION]');
  });

  it('analyze: tells a sudo-using job that enforce removes sudo by default', () => {
    const md = buildReport({ ...base, mode: 'analyze', sudoCommandCount: 3 });
    expect(md).toContain('**This job ran 3 sudo command(s)**');
    expect(md).toContain('disable-sudo: false');
    expect(md).not.toContain('should run unchanged');
    expect(buildReport({ ...base, mode: 'analyze', sudoCommandCount: 0 })).toContain('should run unchanged');
  });
});
