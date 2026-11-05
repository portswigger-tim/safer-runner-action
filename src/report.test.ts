import * as fs from 'fs';
import * as path from 'path';
import { parseFlowLog, parseFlowLogWithOffsets, type FlowRecord } from './flowlog';
import { withoutSelfTests } from './selftest';
import {
  addressClass,
  buildReport,
  containerSection,
  humanBytes,
  modeLabel,
  parseDnsRebind,
  parseFirewallLog,
  suggestedAllowlist,
  summarizeContainers,
  summarizeFlows,
  type FirewallEvent
} from './report';

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
    expect(ev).toEqual([
      { prefix: 'SaferRunner-Drop', proto: 'TCP', src: '10.1.0.4', dst: '1.1.1.1', dport: '853', uid: '1001' }
    ]);
  });
});

describe('buildReport', () => {
  const hosts = summarizeFlows(parseFlowLog(log));
  const base = { job: 'j', firewall: [], dnsRefused: [], selfTests: [] };

  it('enforce: bypass attempts before allowlist misses before allowed; no analyze suggestions', () => {
    const md = buildReport({ ...base, mode: 'enforce', hosts, dnsRefused: ['x.example'] });
    expect(md.indexOf('Bypass attempts')).toBeLessThan(md.indexOf('Not on the allowlist'));
    expect(md.indexOf('Not on the allowlist')).toBeLessThan(md.indexOf('### ✅ Allowed'));
    expect(md).toContain('`evil.example.com`');
    expect(md).toContain('`x.example`');
    expect(md).not.toContain('mode: enforce\n');
  });

  it('analyze: suggests would-be-blocked names, never .invalid, nameless or fronting ones', () => {
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
          { ev: 'https', verdict: 'WOULD_BLOCK', reason: 'host-sni-mismatch', layer: 'http', host: 'api.github.com' },
          // beta.2 suggested fronting names: they were also not on the allowlist
          { ev: 'tls', verdict: 'WOULD_BLOCK', reason: 'sni-not-allowed', layer: 'sni', sni: 'evil.example.com' },
          {
            ev: 'https',
            verdict: 'WOULD_BLOCK',
            reason: 'host-sni-mismatch',
            layer: 'http',
            host: 'evil.example.com',
            sni: 'github.com'
          }
        ]
          .map(r => JSON.stringify(r))
          .join('\n')
      )
    );
    expect(suggestedAllowlist(wb)).toEqual(['registry.npmjs.org']);
    const md = buildReport({ ...base, mode: 'analyze', hosts: wb });
    expect(md).toContain('> [!IMPORTANT]');
    expect(md).toContain('>       registry.npmjs.org');
    expect(md).toContain('### 🚨 Bypass attempts (2) — would be blocked');
    expect(md).toContain('not blocked (analyze)');
  });

  it('says explicitly when rows are cut, per group (attacks are never pushed out)', () => {
    const many = Array.from({ length: 305 }, (_, i) => ({
      ev: 'tls',
      verdict: 'BLOCK',
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: `h${i}.example.com`
    }));
    many.push({
      ev: 'https',
      verdict: 'BLOCK',
      reason: 'host-sni-mismatch',
      layer: 'http',
      host: 'zz.example',
      sni: 'github.com'
    } as never);
    const md = buildReport({
      ...base,
      mode: 'enforce',
      hosts: summarizeFlows(parseFlowLog(many.map(r => JSON.stringify(r)).join('\n')))
    });
    expect(md).toContain('+5 more not shown here');
    expect(md).toContain('`zz.example`');
  });

  it('escapes table-breaking characters in hostnames', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      hosts: summarizeFlows(parseFlowLog(JSON.stringify({ ev: 'http', verdict: 'BLOCK', reason: 'x', host: 'a|`b' })))
    });
    expect(md).toContain("`a\\|'b`");
    expect(md).toContain('### ⚙️ Other (1)'); // unknown reasons are never dropped
  });

  it('never pastes a malformed name into the YAML', () => {
    const h = summarizeFlows(
      parseFlowLog(JSON.stringify({ ev: 'http', verdict: 'BLOCK', reason: 'host-not-allowed', host: 'a b:c\nx' }))
    );
    expect(suggestedAllowlist(h)).toEqual([]);
  });

  it('a sudo command line cannot break out of its code fence', () => {
    const md = buildReport({
      ...base,
      mode: 'analyze',
      hosts: [],
      sudo: {
        ran: [{ timestamp: '', user: 'runner', targetUser: 'root', command: '/usr/bin/echo', args: '```\n> [!NOTE]' }],
        refused: [],
        internal: []
      }
    });
    expect(md).toContain('````console');
  });
});

describe('Option R layout', () => {
  const real = parseFlowLogWithOffsets(
    fs.readFileSync(path.join(__dirname, '__fixtures__', 'beta2-enforce-flows.jsonl'), 'utf8')
  );
  const dnsLog = fs.readFileSync(path.join(__dirname, '__fixtures__', 'beta2-enforce-dns.log'), 'utf8');
  const hosts = summarizeFlows(withoutSelfTests(real.records, real.offsets));
  const userDomains = [
    'pypi.org',
    'files.pythonhosted.org',
    'registry.npmjs.org',
    'docker.io',
    'production.cloudfront.docker.com',
    'nip.io',
    'sslip.io'
  ];
  const md = buildReport({
    mode: 'enforce',
    dockerRetained: true,
    job: 'enforce',
    hosts,
    firewall: [
      { prefix: 'SaferRunner-Drop', proto: 'TCP', src: '10.1.0.4', dst: '1.1.1.1', dport: '853', uid: '1001' }
    ],
    dnsRefused: ['example.org'],
    dnsRebind: parseDnsRebind(dnsLog),
    userDomains,
    selfTests: [
      { name: 'sni-block', ok: true, detail: 'x' },
      { name: 'repoint', ok: true, detail: 'y' }
    ],
    integrity: { status: 'verified', body: '(tables)' },
    now: new Date('2026-11-04T19:21:00Z')
  });

  it('opens with a title, a chip row and a CAUTION verdict for bypass attempts', () => {
    const lines = md.split('\n');
    expect(lines[0]).toBe('## 🛡️ Safer Runner — egress');
    expect(lines[2]).toBe('<kbd>🔒 ENFORCE</kbd> <kbd>⚠️ docker retained</kbd> <kbd>🧪 self-tests 2/2</kbd>');
    expect(md).toContain(
      '> [!CAUTION]\n> **Bypass attempts to 7 hosts were blocked** — 2 Host/SNI spoofs and 5 names that point at internal addresses.'
    );
    expect(md).toContain('> [!WARNING]\n> **The boundary was weaker than it looks.**');
  });

  it('counts only genuinely allowed traffic in the headline (beta.2 counted blocked requests and phantom hosts)', () => {
    const allowed = hosts.filter(h => !['BLOCK', 'WOULD_BLOCK'].includes(h.verdict));
    const requests = allowed.reduce((a, h) => a + h.requests, 0);
    const blockedRequests = hosts.filter(h => h.verdict === 'BLOCK').reduce((a, h) => a + h.requests, 0);
    expect(blockedRequests).toBeGreaterThan(0);
    expect(md).toContain(`| ✅ **Allowed** | ${allowed.length} hosts · ${requests} requests · `);
    expect(allowed.map(h => h.name)).not.toEqual(expect.arrayContaining(['100.64.0.1.nip.io']));
    expect(allowed).toHaveLength(15); // 18 in beta.2: 3 phantoms refused upstream
  });

  it('groups blocked traffic by cause, attacks first', () => {
    const order = [
      '### 🚨 Bypass attempts (7)',
      '### 🚫 Not on the allowlist (2)',
      '🔢 <b>No hostname</b> — 3 blocked'
    ];
    const at = order.map(o => md.indexOf(o));
    expect(at.every(i => i >= 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    expect(md).toContain('| `100.64.0.1.nip.io` | 🕳️ **Internal address** → `100.64.0.1` (CGNAT), refused | 2 |');
    expect(md).toContain('sent inside TLS for `github.com`');
  });

  it('names cross-referenced with a dnsmasq rebind drop are internal-address attempts', () => {
    expect(md).toContain(
      '| `127.0.0.1.nip.io` | 🕳️ **Internal address** — DNS answer dropped by DNS-rebind protection | 1 |'
    );
    expect(md).not.toContain('Did not resolve');
  });

  it('without the rebind log line an unresolved name is only "did not resolve", never an attack', () => {
    const md2 = buildReport({ mode: 'enforce', job: 'j', hosts, firewall: [], dnsRefused: [], selfTests: [] });
    expect(md2).toContain('### ❔ Did not resolve (3)');
    expect(md2).toContain('**Bypass attempts to 4 hosts were blocked**');
  });

  it('offers ready-to-paste allowed-domains YAML for allowlist misses only', () => {
    expect(md).toContain('```yaml\nallowed-domains: |\n  example.org\n  octocat.github.io\n```');
  });

  it("splits allowed traffic into the job's hosts (open) and GitHub platform (collapsed, result in the summary)", () => {
    expect(md).toContain("### ✅ Allowed — this job's hosts (7)");
    expect(md).toMatch(
      /<summary>🐙 <b>GitHub platform<\/b> — 8 hosts · \d+ requests · [\d.]+ MiB · expected for every job<\/summary>/
    );
    const platform = md.slice(md.indexOf('GitHub platform</b>'));
    expect(platform).toContain('`release-assets.githubusercontent.com`');
  });

  it('never prints a measurement that was not taken (beta.2 printed 0 B for passthrough)', () => {
    expect(md).toContain(
      '| `hosted-compute-watchdog-prod-iad-01.githubapp.com` <sub>🔀 passthrough</sub> | — | n/a | n/a |'
    );
    expect(md).toContain('| `broker.actions.githubusercontent.com` | 1 | — | 101 |');
    expect(md).not.toContain('0 B');
  });

  it('collapses diagnostics into one section whose summary states each result', () => {
    expect(md).toContain(
      '<summary>🔧 <b>Diagnostics</b> — self-tests 2/2 ✓ · 1 non-proxy destination rejected · 1 DNS refusal · config files ✓</summary>'
    );
    expect(md).toContain('| `1.1.1.1:853` | TCP | DNS-over-TLS | 1001 | 1 | ❌ rejected |');
  });

  it('ends with a metadata footer', () => {
    expect(md.trimEnd().split('\n').pop()).toBe(
      '<sub>enforce · job `enforce` · 2026-11-04 19:21 UTC · [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action) v2</sub>'
    );
  });

  it('keeps GitHub alerts at the top level (they do not render inside <details>)', () => {
    let depth = 0;
    for (const line of md.split('\n')) {
      depth += (line.match(/<details>/g) ?? []).length - (line.match(/<\/details>/g) ?? []).length;
      if (/^> \[!/.test(line)) expect(depth).toBe(0);
    }
  });

  it('a clean run is about five visible lines', () => {
    const clean = summarizeFlows(
      parseFlowLog(
        [
          { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'pypi.org', client: 'c:1' },
          {
            ev: 'https',
            verdict: 'ALLOW',
            reason: 'allowed',
            layer: 'http',
            host: 'pypi.org',
            sni: 'pypi.org',
            client: 'c:1',
            status: 200,
            resp_bytes: 2048
          },
          { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'github.com', client: 'c:2' },
          {
            ev: 'https',
            verdict: 'ALLOW',
            reason: 'allowed',
            layer: 'http',
            host: 'github.com',
            sni: 'github.com',
            client: 'c:2',
            status: 200,
            resp_bytes: 10
          }
        ]
          .map(r => JSON.stringify(r))
          .join('\n')
      )
    );
    const out = buildReport({
      mode: 'enforce',
      job: 'build',
      hosts: clean,
      firewall: [],
      dnsRefused: [],
      selfTests: [{ name: 'sni-block', ok: true, detail: '' }],
      userDomains: ['pypi.org'],
      sudo: { ran: [], refused: [], internal: [] },
      integrity: { status: 'verified', body: '' }
    });
    expect(out).not.toContain('[!');
    expect(out).toContain('<kbd>✅ boundary intact</kbd>');
    expect(out).toContain('**✅ Nothing blocked.** 2 hosts · 2 requests · 2.0 KiB through the proxy.');
    // outside <details>: title, chips, verdict line, one small table
    const visible = out
      .replace(/<details>[\s\S]*?<\/details>/g, '')
      .split('\n')
      .filter(l => l.trim() && !l.startsWith('|'));
    expect(visible.length).toBeLessThanOrEqual(5);
  });
});

describe('addressClass', () => {
  it.each([
    ['100.64.0.1', 'CGNAT'],
    ['127.0.0.1', 'loopback'],
    ['169.254.169.254', 'cloud metadata service'],
    ['10.1.2.3', 'private, RFC 1918'],
    ['172.31.0.1', 'private, RFC 1918'],
    ['172.32.0.1', 'internal'],
    ['fd00::1', 'private, ULA'],
    ['::1', 'loopback']
  ])('%s -> %s', (ip, cls) => expect(addressClass(ip)).toBe(cls));
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
  const base = { job: 'j', hosts: [], firewall: [], dnsRefused: [], selfTests: [] };

  it('labels enforce with sudo retained as ADVISORY in the title and the mode chip', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true });
    expect(md.split('\n')[0]).toBe(
      '## 🛡️ Safer Runner — egress — enforce (ADVISORY — sudo retained, not an enforced boundary)'
    );
    expect(md).toContain('> [!WARNING]');
    expect(md).toContain('<kbd>⚠️ ENFORCE · ADVISORY</kbd> <kbd>⚠️ sudo retained</kbd>');
    expect(md).not.toContain('boundary intact');
  });

  it('labels enforce with sudo removed as plain enforce', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: false });
    expect(md.split('\n')[0]).toBe('## 🛡️ Safer Runner — egress');
    expect(md).not.toContain('ADVISORY');
    expect(md).toContain('<kbd>🔒 ENFORCE</kbd>');
  });

  it('never labels analyze as advisory enforce', () => {
    expect(modeLabel('analyze', true)).toBe('📊 ANALYZE');
    expect(buildReport({ ...base, mode: 'analyze', sudoRetained: true })).not.toContain('ADVISORY —');
  });

  it('warns when enforce left docker (root-equivalent) in place', () => {
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: true })).toContain('> [!WARNING]');
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: false })).not.toContain('[!');
  });

  const cmd = (command: string) => ({ timestamp: '', user: 'runner', targetUser: 'root', command, args: '' });

  it('analyze: tells a sudo-using job that enforce removes sudo by default', () => {
    const sudo = { ran: [cmd('/usr/bin/apt-get'), cmd('/usr/bin/id'), cmd('/usr/bin/tee')], refused: [], internal: [] };
    const md = buildReport({ ...base, mode: 'analyze', sudo });
    expect(md).toContain('**This job ran 3 sudo commands.**');
    expect(md).toContain('disable-sudo: false');
    expect(md).not.toContain('should run unchanged');
    expect(buildReport({ ...base, mode: 'analyze', sudo: { ran: [], refused: [], internal: [] } })).toContain(
      'should run unchanged'
    );
  });

  // beta.2 said "Workflow executed 4 sudo commands": its own teardown plus three refused attempts
  it("the action's own and refused sudo never count as the workflow's usage", () => {
    const sudo = {
      ran: [],
      refused: [cmd('/usr/bin/true'), cmd('/usr/sbin/iptables-save')],
      internal: [cmd('/opt/safer-runner/bin/teardown')]
    };
    const analyze = buildReport({ ...base, mode: 'analyze', sudo });
    expect(analyze).not.toContain('This job ran');
    expect(analyze).toContain('should run unchanged');
    const enforce = buildReport({ ...base, mode: 'enforce', sudo });
    expect(enforce).toContain('workflow sudo 0 (1 by Safer Runner) · 2 sudo attempts refused');
    expect(enforce).toContain('Refused by sudo (2):');
  });
});

describe('self-test probes are not the job traffic', () => {
  const recs = [
    {
      ev: 'tls',
      verdict: 'BLOCK',
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: 'selftest.safer-runner.invalid',
      dst: '192.0.2.1:443'
    },
    { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'github.com', dst: '192.0.2.1:443' },
    {
      ev: 'https',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'github.com',
      sni: 'github.com',
      dst: '192.0.2.1:443',
      status: 200
    },
    // after setup: a job step dialling the same TEST-NET address must still be reported
    { ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', layer: 'sni', sni: 'github.com', dst: '192.0.2.1:443' },
    {
      ev: 'tls',
      verdict: 'BLOCK',
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: 'selftest.safer-runner.invalid',
      dst: '192.0.2.1:443'
    }
  ];
  const text = recs.map(r => JSON.stringify(r)).join('\n') + '\n';
  const { records, offsets } = parseFlowLogWithOffsets(text);
  const windowEnd = offsets[3];

  it('drops the probes written inside the self-test window', () => {
    const kept = withoutSelfTests(records, offsets, [0, windowEnd]);
    expect(kept).toEqual(records.slice(3));
  });

  it('never drops a look-alike written after setup (no hiding channel)', () => {
    const kept = withoutSelfTests(records, offsets, [0, windowEnd]);
    expect(kept.map(r => r.sni)).toEqual(['github.com', 'selftest.safer-runner.invalid']);
  });

  it('without a window, drops only the .invalid probe name', () => {
    const kept = withoutSelfTests(records, offsets);
    expect(kept.map(r => r.sni)).toEqual(['github.com', 'github.com', 'github.com']);
  });

  it('the beta.2 report listed selftest.safer-runner.invalid as Blocked; it is gone', () => {
    const real = parseFlowLogWithOffsets(
      fs.readFileSync(path.join(__dirname, '__fixtures__', 'beta2-enforce-flows.jsonl'), 'utf8')
    );
    const names = summarizeFlows(withoutSelfTests(real.records, real.offsets)).map(h => h.name);
    expect(names).not.toContain('selftest.safer-runner.invalid');
  });
});

describe('container egress (P2)', () => {
  const rec = (r: Partial<FlowRecord>): FlowRecord => ({ ts: 1, ev: 'tls', ...r }) as FlowRecord;
  const records: FlowRecord[] = [
    rec({
      verdict: 'PASSTHROUGH',
      reason: 'container-sni-only',
      sni: 'github.com',
      client: '172.18.0.2:4000',
      source: 'container',
      passthrough: true
    }),
    rec({
      verdict: 'BLOCK',
      reason: 'sni-not-allowed',
      sni: 'example.org',
      client: '172.18.0.2:4001',
      source: 'container'
    }),
    rec({
      ev: 'http',
      verdict: 'BLOCK',
      reason: 'host-not-allowed',
      host: 'evil.test',
      client: '172.17.0.3:5000',
      source: 'container'
    }),
    rec({
      verdict: 'INTERCEPT',
      reason: 'container-front-door',
      sni: 'productionresultssa1.blob.core.windows.net',
      client: '172.17.0.3:5001',
      source: 'container'
    }),
    rec({
      ev: 'tls-client-fail',
      sni: 'productionresultssa1.blob.core.windows.net',
      client: '172.17.0.3:5001',
      source: 'container'
    }),
    // host traffic never shows up in the container section (its client is the VM's private eth0 address)
    rec({ verdict: 'INTERCEPT', reason: 'allowed', sni: 'api.github.com', client: '10.1.0.4:6000', source: 'host' }),
    rec({ verdict: 'INTERCEPT', reason: 'allowed', sni: 'api.github.com', client: '10.1.0.4:6001' })
  ];
  const firewall: FirewallEvent[] = [
    { prefix: 'SaferRunner-CDrop', proto: 'TCP', src: '172.18.0.2', dst: '1.1.1.1', dport: '853', uid: '' },
    { prefix: 'SaferRunner-CDrop', proto: 'TCP', src: '172.18.0.2', dst: '1.1.1.1', dport: '853', uid: '' },
    { prefix: 'SaferRunner-Drop', proto: 'TCP', src: '10.1.0.4', dst: '8.8.8.8', dport: '853', uid: '1001' }
  ];

  it('groups container records and firewall events by container address', () => {
    const c = summarizeContainers(records, firewall, new Map([['172.18.0.2', 'redis']]));
    expect(c.map(x => x.ip)).toEqual(['172.17.0.3', '172.18.0.2']);
    const [svc, redis] = [c[0], c[1]];
    expect(redis).toMatchObject({
      name: 'redis',
      allowed: ['github.com'],
      sniOnly: ['github.com'],
      denied: ['example.org'],
      firewall: [{ dst: '1.1.1.1:853', proto: 'TCP', n: 2, rejected: true }]
    });
    expect(svc.untrusted).toEqual(['productionresultssa1.blob.core.windows.net']);
    expect(svc.denied).toEqual(['evil.test']);
  });

  it('renders a section with the CA hint, and nothing when there were no containers', () => {
    const md = containerSection(summarizeContainers(records, firewall), 'enforce');
    expect(md).toContain('🐳 <b>Container egress</b> — 2 containers');
    expect(md).toContain('did not trust the CA');
    expect(md).toContain('🔀 `github.com`');
    expect(md).toContain('❌ `1.1.1.1:853` TCP ×2');
    expect(md).toContain('<details open>');
    expect(containerSection([], 'enforce')).toBe('');
  });

  it('keeps container firewall events out of the host "outside the proxy" counts', () => {
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts: summarizeFlows(records),
      firewall,
      dnsRefused: [],
      selfTests: [],
      containers: summarizeContainers(records, firewall)
    });
    expect(md).toContain('1 rejected');
    expect(md).not.toContain('allowed, not proxied');
    expect(md).toContain('Container egress');
  });
});
