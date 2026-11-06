import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { parseFlowLog, parseFlowLogWithOffsets, type FlowRecord } from './flowlog';
import { parseHttpFilter } from './inputs';
import { buildHttpFilter, type HttpFilterConfig } from './policy';
import { withoutSelfTests } from './selftest';
import {
  ADVISORY_REPORT_NOTE,
  addressClass,
  buildReport,
  containerSection,
  humanBytes,
  httpFilterYaml,
  modeLabel,
  blockedName,
  type HostSummary,
  parseFirewallLog,
  suggestedAllowlist,
  summarizeContainers,
  summarizeFlows,
  summarizeHttpFilter,
  type FirewallEvent,
  type HttpFilterSuggestion
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
    expect(md.indexOf('Not on the allowlist')).toBeLessThan(md.indexOf('### Allowed'));
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
  const hosts = summarizeFlows(withoutSelfTests(real.records, real.offsets));
  const userDomains = [
    'pypi.org',
    'files.pythonhosted.org',
    'registry.npmjs.org',
    '.docker.io',
    'production.cloudfront.docker.com',
    '*.nip.io',
    '*.sslip.io'
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
    // docker: keep under enforce is ADVISORY, like retained sudo (G4)
    expect(lines[0]).toBe(
      '## 🛡️ Safer Runner — egress — enforce (ADVISORY — docker retained, not an enforced boundary)'
    );
    expect(lines[2]).toBe(
      '<kbd>⚠️ ENFORCE · ADVISORY</kbd> <kbd>⚠️ docker retained</kbd> <kbd>🔎 no config change seen (advisory)</kbd> <kbd>🧪 self-tests 2/2</kbd>'
    );
    expect(md).toContain(
      '> [!CAUTION]\n> **Bypass attempts to 4 hosts were blocked** — 2 Host/SNI spoofs and 2 names that point at internal addresses.'
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
      '### 🚨 Bypass attempts (4)',
      '### 🚫 Not on the allowlist (2)',
      '### ❔ Did not resolve (3)',
      '🔢 <b>No hostname</b> — 3 blocked'
    ];
    const at = order.map(o => md.indexOf(o));
    expect(at.every(i => i >= 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    expect(md).toContain('| `100.64.0.1.nip.io` | 🕳️ **Internal address** → `100.64.0.1` (CGNAT), refused | 2 |');
    expect(md).toContain('sent inside TLS for `github.com`');
  });

  it('an unresolved name is only "did not resolve", never an attack (no DNS-layer rebind drop any more)', () => {
    // beta.2's dnsmasq dropped these answers; the proxy's IP guard now refuses them with the IP
    expect(md).toContain('### ❔ Did not resolve (3)');
    expect(md).not.toContain('DNS-rebind');
  });

  it('offers ready-to-paste allowed-domains YAML for allowlist misses only', () => {
    expect(md).toContain('```yaml\nallowed-domains: |\n  example.org\n  octocat.github.io\n```');
  });

  it("splits allowed traffic into the job's hosts (open) and GitHub platform (collapsed, result in the summary)", () => {
    expect(md).toContain("### Allowed — this job's hosts (7)");
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
    expect(md).toContain('| `broker.actions.githubusercontent.com` | 1 | — | 1xx (1) |');
    expect(md).not.toContain('0 B');
  });

  it('collapses diagnostics into one section whose summary states each result', () => {
    expect(md).toContain(
      '<summary>🔧 <b>Diagnostics</b> — self-tests 2/2 ✓ · 1 non-proxy destination rejected · 1 DNS refusal · config unchanged ✓</summary>'
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
    expect(out).toContain('<kbd>✅ controls applied at setup</kbd> <kbd>🔎 no config change seen (advisory)</kbd>');
    expect(out).toContain('**✅ Nothing blocked.** 2 hosts · 2 requests · 2.0 KiB through the proxy.');
    // outside <details>: title, chips, verdict line, one small table
    const visible = out
      .replace(/<details>[\s\S]*?<\/details>/g, '')
      .split('\n')
      .filter(l => l.trim() && !l.startsWith('|'));
    expect(visible.length).toBeLessThanOrEqual(5);
  });

  it('labels the tamper check advisory, in the diagnostics', () => {
    const out = buildReport({
      mode: 'enforce',
      job: 'build',
      hosts: [],
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      integrity: { status: 'verified', body: '' }
    });
    const diagnostics = out.match(/<details>[\s\S]*<\/details>/)?.[0] ?? '';
    expect(diagnostics).toContain('**Config file tamper check** (advisory) — all verified');
    expect(diagnostics).toContain(ADVISORY_REPORT_NOTE);
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
    expect(md).not.toContain('controls applied at setup');
  });

  it.each([
    ['unavailable', '❔ config unverified'],
    [undefined, '❔ config unverified'],
    ['tampered', '🚨 config tampered'],
    ['verified', '🔎 no config change seen (advisory)']
  ] as const)('shows the post-run tamper check (%s) as its own chip, never as an intact boundary', (status, chip) => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      sudoRetained: false,
      integrity: status ? { status, body: '' } : undefined
    });
    expect(md).toContain(`<kbd>✅ controls applied at setup</kbd> <kbd>${chip}</kbd>`);
    expect(md).not.toContain('intact');
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

  it('labels enforce with docker retained (verified) as ADVISORY, like sudo (G4)', () => {
    const md = buildReport({ ...base, mode: 'enforce', dockerRetained: true });
    expect(md.split('\n')[0]).toBe(
      '## 🛡️ Safer Runner — egress — enforce (ADVISORY — docker retained, not an enforced boundary)'
    );
    expect(md).toContain('<kbd>⚠️ ENFORCE · ADVISORY</kbd> <kbd>⚠️ docker retained</kbd>');
    expect(md).toContain('> [!WARNING]');
    expect(md).toContain('**ADVISORY: docker was retained** (`docker: keep`; verified on the runner)');
    expect(md).toContain('`docker: remove-group`');
    expect(md).not.toMatch(/disable-docker|stop-docker|sudo-config/);
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: false })).not.toContain('[!');
  });

  it('names both when sudo and docker were retained', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true, dockerRetained: true });
    expect(md.split('\n')[0]).toContain('ADVISORY — sudo and docker retained');
    expect(modeLabel('enforce', true, true)).toBe(
      '⚠️ ENFORCE (ADVISORY — sudo and docker retained, not an enforced boundary)'
    );
    expect(modeLabel('enforce', false, true)).toContain('docker retained');
    expect(modeLabel('enforce')).toBe('🔒 ENFORCE');
  });

  it('never labels analyze ADVISORY for kept docker', () => {
    expect(buildReport({ ...base, mode: 'analyze', dockerRetained: true })).not.toContain('ADVISORY');
  });

  it('reports the verified docker state, not just the input (G4)', () => {
    const removed = buildReport({
      ...base,
      mode: 'enforce',
      docker: { requested: 'remove-group', access: 'group-removed' }
    });
    expect(removed).toContain('docker removed ✓');
    expect(removed).toContain(
      '**Docker** — `docker: remove-group`; verified at setup: runner user removed from the docker group, socket root-only'
    );
    const stopped = buildReport({ ...base, mode: 'enforce', docker: { requested: 'stop', access: 'not-running' } });
    expect(stopped).toContain('docker stopped ✓');
    expect(stopped).toContain('verified at setup: docker daemon not running');
    const kept = buildReport({
      ...base,
      mode: 'enforce',
      dockerRetained: true,
      docker: { requested: 'keep', access: 'retained' }
    });
    expect(kept).toContain('verified at setup: runner user can use docker');
  });

  it('the sudo ADVISORY wording no longer mentions sudo-config', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true });
    expect(md).toContain('**ADVISORY: sudo was retained** (`disable-sudo: false`)');
    expect(md).not.toContain('sudo-config');
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
    expect(enforce).toContain('no workflow sudo (1 by Safer Runner) · 2 sudo attempts refused');
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

describe('blocked names and DNS refusals', () => {
  it('redacts payload-looking labels and keeps ordinary ones', () => {
    expect(blockedName('www.example.com')).toBe('www.example.com');
    expect(blockedName('aghvsbg8gd29ybgq.api.example.com')).toBe('‹redacted›.api.example.com');
    expect(blockedName('0dd2149bb6f23853.objects.githubusercontent.com')).toBe(
      '‹redacted›.objects.githubusercontent.com'
    );
    expect(blockedName('1.2.3.4')).toBe('1.2.3.4');
  });

  const base = { job: 'j', hosts: [], firewall: [], selfTests: [] };

  it('enforce: refused subdomains of allowlisted names are listed in the DNS diagnostics only, redacted', () => {
    const secret = 'c2VjcmV0LXRva2VuLTEyMzQ';
    const md = buildReport({
      ...base,
      mode: 'enforce',
      dnsRefused: [`${secret.toLowerCase()}.objects.githubusercontent.com`, 'www.example.com', 'example.org']
    });
    expect(md).not.toContain('Subdomains of exact entries');
    expect(md).not.toContain('`*.');
    expect(md.toLowerCase()).not.toContain(secret.toLowerCase());
    const diagnostics = md.match(/<details>[\s\S]*<\/details>/)?.[0] ?? '';
    expect(diagnostics).toContain(
      '**DNS refused** (3): `‹redacted›.objects.githubusercontent.com`, `www.example.com`, `example.org`'
    );
  });

  it('redacts encoded labels in every blocked-name display, and never suggests such a name', () => {
    const secret = '0dd2149bb6f23853a1b2';
    const h = (name: string, reason: string): HostSummary => ({
      name,
      verdict: 'BLOCK',
      reasons: [reason],
      layers: ['sni'],
      kinds: ['tls'],
      connections: 1,
      requests: 0,
      tries: 1,
      reqBytes: 0,
      respBytes: 0,
      statuses: {},
      dsts: [],
      snis: [],
      upstreamIps: []
    });
    const md = buildReport({
      ...base,
      mode: 'enforce',
      hosts: [
        h(`${secret}.attacker.com`, 'sni-not-allowed'),
        h('cdn.a1b2c3d4e5.com', 'sni-not-allowed'),
        h('ok.attacker.com', 'sni-not-allowed')
      ],
      dnsRefused: [`${secret}.evil.example.net`]
    });
    expect(md).not.toContain(secret);
    expect(md).toContain('`‹redacted›.attacker.com`');
    expect(md).toContain('`‹redacted›.evil.example.net`');
    // the registrable domain is not exempt
    expect(md).toContain('`cdn.‹redacted›.com`');
    expect(md).not.toContain('a1b2c3d4e5');
    expect(md).toContain('allowed-domains: |\n  ok.attacker.com\n```');
  });

  it('analyze: says what enforce would do', () => {
    const md = buildReport({ ...base, mode: 'analyze', dnsRefused: ['www.example.com'] });
    expect(md).toContain('1 DNS lookup enforce would refuse');
    expect(md).toContain('**DNS would refuse** (1): `www.example.com`');
  });
});

describe('http-filter', () => {
  let port = 40000;
  /** an intercepted request, on its own client connection */
  const req = (host: string, method: string, path: string, extra: Partial<FlowRecord> = {}): FlowRecord => ({
    ts: 0,
    ev: 'https',
    verdict: 'ALLOW',
    reason: 'allowed',
    layer: 'http',
    host,
    sni: host,
    method,
    path,
    status: 200,
    client: `10.1.0.4:${port++}`,
    ...extra
  });
  const refused = (host: string, method: string, path: string, verdict = 'BLOCK', reason = 'path-not-allowed') =>
    req(host, method, path, { verdict: verdict as FlowRecord['verdict'], reason, status: 403 });
  const rulesFor = (s: HttpFilterSuggestion, host: string) =>
    Object.fromEntries((s.hosts.find(h => h.host === host)?.rules ?? []).map(r => [r.path, r.methods.join(', ')]));
  const base = { job: 'j', firewall: [], dnsRefused: [], selfTests: [] };

  describe('suggested http-filter (level B)', () => {
    it('collapses a read-only host to one line', () => {
      const recs = [
        ...Array.from({ length: 30 }, (_, i) => req('registry.npmjs.org', 'GET', `/pkg-${i}`)),
        req('registry.npmjs.org', 'HEAD', '/lodash')
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'registry.npmjs.org')).toEqual({ '*': 'GET, HEAD' });
      expect(suggestion).toMatchObject({ requests: 31, rules: 1, specific: 0, coarse: false });
    });

    it('splits reads from writes and templates the write paths (ids never echoed)', () => {
      const recs = [
        req('api.github.com', 'GET', '/repos/o/r'),
        req('api.github.com', 'OPTIONS', '/repos/o/r'),
        req('api.github.com', 'POST', '/repos/o/r/issues/123/comments'),
        req('api.github.com', 'POST', '/repos/o/r/issues/456/comments'),
        req('api.github.com', 'PATCH', '/repos/o/r/issues/123/comments'),
        req('api.github.com', 'PUT', '/repos/o/r/contents/550e8400-e29b-41d4-a716-446655440000')
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'api.github.com')).toEqual({
        '*': 'GET, HEAD, OPTIONS',
        // reads stay open on a write path too (the most specific rule decides)
        'repos/o/r/contents/*': 'GET, HEAD, OPTIONS, PUT',
        'repos/o/r/issues/*/comments': 'GET, HEAD, OPTIONS, POST, PATCH'
      });
      const yaml = httpFilterYaml(suggestion);
      expect(yaml).not.toMatch(/123|456|550e8400/);
    });

    it('templates a position only when it has many distinct values', () => {
      const few = summarizeHttpFilter(['a', 'b'].map(x => req('uploads.example.com', 'PUT', `/files/${x}`)));
      expect(rulesFor(few.suggestion, 'uploads.example.com')).toEqual({ 'files/a': 'PUT', 'files/b': 'PUT' });
      const many = summarizeHttpFilter(['a', 'b', 'c', 'd'].map(x => req('uploads.example.com', 'PUT', `/files/${x}`)));
      expect(rulesFor(many.suggestion, 'uploads.example.com')).toEqual({ 'files/*': 'PUT' });
    });

    it('keeps a git push path-specific, pinned to the repo written to (not folded into a method baseline)', () => {
      const recs = [
        req('github.com', 'GET', '/myorg/app.git/info/refs'),
        req('github.com', 'POST', '/myorg/app.git/git-upload-pack'),
        req('github.com', 'POST', '/myorg/app.git/git-receive-pack'),
        req('github.com', 'POST', '/other/lib.git/git-upload-pack')
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'github.com')).toEqual({
        '*': 'GET, HEAD',
        // github.com: one spelling per repository (case and `.git` don't matter there)
        'myorg/app/git-receive-pack': 'POST',
        'myorg/app/git-upload-pack': 'POST',
        'other/lib/git-upload-pack': 'POST'
      });
      expect(suggestion.specific).toBe(3);
      expect(suggestion.coarse).toBe(false);
    });

    it('templates pushed-to repos only when several are seen, and then says it is coarse', () => {
      const owners = ['a', 'b', 'c', 'd'];
      const { suggestion } = summarizeHttpFilter(
        owners.map(o => req('github.com', 'POST', `/${o}/${o}-repo.git/git-receive-pack`))
      );
      expect(rulesFor(suggestion, 'github.com')).toEqual({ '*/git-receive-pack': 'POST' });
      expect(suggestion.coarse).toBe(true);
    });

    it('method-boundary trap: a broad POST rule never re-opens pushes on a host that pushes', () => {
      const recs = [
        req('github.com', 'POST', '/myorg/app.git/git-receive-pack'),
        // a write whose only segment is an id: templates to "*"
        req('github.com', 'POST', '/0dd2149bb6f23853')
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'github.com')).toEqual({
        '*': 'POST',
        '*/git-receive-pack': '',
        '*/git-upload-pack': '',
        'myorg/app/git-receive-pack': 'POST'
      });
      expect(httpFilterYaml(suggestion)).toContain('"*/git-receive-pack": NONE');
      expect(suggestion.coarse).toBe(true);
    });

    it('scopes the NONE rule under a broad rule, so it outranks it (most literal characters wins)', () => {
      const recs = [
        req('github.com', 'POST', '/myorg/app.git/git-receive-pack'),
        ...['a', 'b', 'c', 'd'].map(x => req('github.com', 'POST', `/myorg/${x}`))
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'github.com')).toEqual({
        'myorg/*': 'POST',
        'myorg/*/git-receive-pack': '',
        'myorg/*/git-upload-pack': '',
        'myorg/app/git-receive-pack': 'POST'
      });
    });

    it('adds no NONE rule where nothing broad could match a pack path', () => {
      const recs = [
        req('api.github.com', 'POST', '/repos/o/r/issues'),
        req('github.com', 'POST', '/myorg/app.git/git-receive-pack')
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(rulesFor(suggestion, 'api.github.com')).toEqual({ 'repos/o/r/issues': 'POST' });
      expect(rulesFor(suggestion, 'github.com')).toEqual({ 'myorg/app/git-receive-pack': 'POST' });
    });

    it('leaves out refused requests, GitHub platform hosts, refused connections and unsafe names', () => {
      const recs: FlowRecord[] = [
        req('registry.npmjs.org', 'GET', '/lodash'),
        refused('registry.npmjs.org', 'PUT', '/lodash'),
        req('results-receiver.actions.githubusercontent.com', 'POST', '/twirp/x.Svc/Method'),
        req('productionresultssa1.blob.core.windows.net', 'PUT', '/actions-results/abc'),
        req('0dd2149bb6f23853abcdef.example.com', 'POST', '/x'),
        { ts: 0, ev: 'tls', verdict: 'INTERCEPT', reason: 'allowed', sni: 'meta.example.com', client: '10.1.0.4:1' },
        req('meta.example.com', 'POST', '/x', { client: '10.1.0.4:1' }),
        {
          ts: 0,
          ev: 'upstream',
          verdict: 'BLOCK',
          reason: 'upstream-ip-forbidden',
          host: 'meta.example.com',
          dst: '169.254.169.254:443',
          client: '10.1.0.4:1'
        }
      ];
      const { suggestion } = summarizeHttpFilter(recs);
      expect(suggestion.hosts.map(h => h.host)).toEqual(['registry.npmjs.org']);
      expect(rulesFor(suggestion, 'registry.npmjs.org')).toEqual({ '*': 'GET, HEAD' });
    });

    it('leaves out what the built-in platform list allowed on a filtered host', () => {
      const { suggestion } = summarizeHttpFilter([
        req('api.github.com', 'GET', '/repos/o/r'),
        req('api.github.com', 'POST', '/repos/o/r/check-runs', { filter: 'platform', filter_rule: null })
      ]);
      expect(rulesFor(suggestion, 'api.github.com')).toEqual({ '*': 'GET, HEAD' });
      expect(suggestion.requests).toBe(1);
    });

    it('never pastes a segment that could break the YAML or the engine', () => {
      const { suggestion } = summarizeHttpFilter([
        req('api.example.com', 'POST', '/a"b/x'),
        req('api.example.com', 'POST', '/c:d/y'),
        // the engine refuses a dot segment whatever the rules say: nothing to suggest
        req('api.example.com', 'POST', '/../z')
      ]);
      expect(rulesFor(suggestion, 'api.example.com')).toEqual({ '*/x': 'POST', '*/y': 'POST' });
    });
  });

  describe('refused requests', () => {
    const secret = 'c2VjcmV0LXRva2VuLTEyMzQ1Njc4';
    const recs = [
      req('registry.npmjs.org', 'GET', '/lodash'),
      req('github.com', 'POST', '/myorg/app.git/git-upload-pack'),
      refused('github.com', 'POST', `/evil/${secret}.git/git-receive-pack`),
      refused('github.com', 'POST', `/evil/${secret}.git/git-receive-pack`),
      refused('registry.npmjs.org', 'PUT', '/lodash', 'BLOCK', 'method-not-allowed')
    ];
    const hf = summarizeHttpFilter(recs);

    it('groups refusals by host, method and reason (the path is never kept)', () => {
      expect(hf.blocks).toEqual([
        {
          host: 'github.com',
          method: 'POST',
          reason: 'path-not-allowed',
          verdict: 'BLOCK',
          tries: 2
        },
        {
          host: 'registry.npmjs.org',
          method: 'PUT',
          reason: 'method-not-allowed',
          verdict: 'BLOCK',
          tries: 1
        }
      ]);
    });

    it('never turns a refusal into a rule', () => {
      expect(rulesFor(hf.suggestion, 'github.com')).toEqual({ 'myorg/app/git-upload-pack': 'POST' });
      expect(rulesFor(hf.suggestion, 'registry.npmjs.org')).toEqual({ '*': 'GET, HEAD' });
    });

    it('enforce: lists refusals without their path, then the suggested filter', () => {
      const md = buildReport({ ...base, mode: 'enforce', hosts: summarizeFlows(recs), httpFilter: hf });
      expect(md).not.toContain(secret);
      expect(md).toContain('> **3 requests were refused by `http-filter`.** If this job failed');
      expect(md).toContain('| 🔒 **HTTP filter** | 3 requests blocked — `github.com`, `registry.npmjs.org` |');
      expect(md).toContain('### 🔒 Refused by `http-filter` (2)\n');
      expect(md).not.toContain('evil');
      expect(md).toContain('| `github.com` | `POST` ‹path hidden› | path not allowed | 2 |');
      expect(md).toContain('| `registry.npmjs.org` | `PUT` ‹path hidden› | method not allowed on this path | 1 |');
      expect(md).toContain('The path of a refused request is never shown');
      expect(md).not.toContain('add these rules');
      expect(md).toContain(
        '🧰 <b>Suggested <code>http-filter</code></b> — collapsed 2 requests → 2 rules (level B); 1 write endpoint kept specific'
      );
      expect(md.indexOf('Refused by `http-filter`')).toBeLessThan(md.indexOf('Suggested <code>http-filter'));
    });

    it('analyze: says the filter would refuse them, not that hosts would be blocked', () => {
      const wb = recs.map(r => (r.verdict === 'BLOCK' ? { ...r, verdict: 'WOULD_BLOCK' as const, status: 200 } : r));
      const md = buildReport({
        ...base,
        mode: 'analyze',
        hosts: summarizeFlows(wb),
        httpFilter: summarizeHttpFilter(wb)
      });
      expect(md).toContain('<kbd>3 requests the http-filter would refuse</kbd>');
      expect(md).not.toContain('would be blocked</kbd>');
      expect(md).toContain('### 🔒 Refused by `http-filter` (2) — would be blocked');
      expect(md).toContain('<details open>\n<summary>🧰 <b>Suggested <code>http-filter</code>');
    });
  });

  describe('what a refused request can show', () => {
    it('labels a non-standard method instead of printing it', () => {
      const token = 'A1B2C3D4E5F6';
      const recs = [
        refused('api.example.com', token, '/x', 'BLOCK', 'method-not-allowed'),
        refused('api.example.com', 'X' + token, '/x', 'BLOCK', 'method-not-allowed'),
        refused('api.example.com', 'delete', '/x', 'BLOCK', 'method-not-allowed')
      ];
      const hf = summarizeHttpFilter(recs);
      expect(hf.blocks.map(b => [b.method, b.tries])).toEqual([
        ['INVALID', 2],
        ['DELETE', 1]
      ]);
      // never suggested either: only standard methods go into a rule
      const allowed = summarizeHttpFilter([
        req('api.example.com', token, '/y'),
        req('api.example.com', 'PROPFIND', '/z')
      ]);
      expect(allowed.suggestion.hosts).toEqual([]);
      expect(httpFilterYaml(allowed.suggestion)).not.toMatch(/INVALID|A1B2|PROPFIND/);
      const md = buildReport({ ...base, mode: 'enforce', hosts: summarizeFlows(recs), httpFilter: hf });
      expect(md).not.toMatch(/A1B2C3D4E5F6/i);
      expect(md).toContain('| `api.example.com` | `INVALID` ‹path hidden› | method not allowed on this path | 2 |');
    });

    it('never shows a refused path, in the summary, the job log or any rule', () => {
      // hex of a secret, one byte per segment: every segment on its own looks harmless
      const chunks = '/73/65/63/72/65/74';
      const recs = [
        req('api.example.com', 'GET', '/status'),
        refused('api.example.com', 'POST', chunks),
        refused('api.example.com', 'POST', `/up${chunks}`),
        refused('api.example.com', 'PUT', '/plain/words/only')
      ];
      const hf = summarizeHttpFilter(recs);
      // grouped without the path, so neither its text nor how many distinct ones there were shows
      expect(hf.blocks).toEqual([
        { host: 'api.example.com', method: 'POST', reason: 'path-not-allowed', verdict: 'BLOCK', tries: 2 },
        { host: 'api.example.com', method: 'PUT', reason: 'path-not-allowed', verdict: 'BLOCK', tries: 1 }
      ]);
      // everything post.ts logs a refusal from
      expect(JSON.stringify(hf)).not.toMatch(/73|65|63|72|74|plain|words/);
      for (const mode of ['enforce', 'analyze'] as const) {
        const md = buildReport({ ...base, mode, hosts: summarizeFlows(recs), httpFilter: hf });
        expect(md).toContain('| `api.example.com` | `POST` ‹path hidden› | path not allowed | 2 |');
        expect(md).not.toMatch(/73\/65|\b74\b|plain|words/);
      }
      expect(rulesFor(hf.suggestion, 'api.example.com')).toEqual({ '*': 'GET, HEAD' });
    });
  });

  describe('round trip: suggestion → http-filter input → policy.json → the addon allows the request', () => {
    /** proxy/policy_core.py HttpFilter.decide for each request ("allow:allowed", "block:<reason>", null) */
    const engine = (config: HttpFilterConfig, reqs: { host: string; method: string; path: string }[]) => {
      const script = [
        'import json, sys',
        'sys.path.insert(0, sys.argv[1])',
        'from policy_core import HttpFilter',
        'd = json.load(sys.stdin)',
        'f = HttpFilter.from_config(d["config"])',
        'out = [f.decide(r["host"], r["method"], r["path"]) for r in d["reqs"]]',
        'print(json.dumps([x and f"{x.action}:{x.reason}" for x in out]))'
      ].join('\n');
      const run = spawnSync('python3', ['-I', '-c', script, path.join(__dirname, '..', 'proxy')], {
        input: JSON.stringify({ config, reqs }),
        encoding: 'utf8'
      });
      if (run.status !== 0) throw new Error(run.stderr);
      return JSON.parse(run.stdout) as (string | null)[];
    };
    /** the YAML the report prints, read back as the action reads the input */
    const asPolicy = (s: HttpFilterSuggestion): HttpFilterConfig => {
      const hosts = parseHttpFilter(httpFilterYaml(s).split('\n').slice(1).join('\n'));
      const warnings: string[] = [];
      const config = buildHttpFilter(
        hosts,
        false,
        hosts.map(h => h.host),
        [],
        warnings
      );
      expect(warnings).toEqual([]);
      return config;
    };
    const longSegment = 'session-'.repeat(40);
    /** [host, method, path as sent, path as logged] */
    const traffic: [string, string, string, string?][] = [
      ['upload.pypi.org', 'POST', '/legacy/'],
      ['pypi.org', 'GET', '/simple/requests/'],
      ['uploads.example.com', 'PUT', '/files/a%2Fb/c'],
      ['uploads.example.com', 'PUT', '/files/%41pp/c'],
      ['paths.example.com', 'POST', '/a//b'],
      ['forms.example.com', 'POST', '/report;jsessionid=x'],
      ['drafts.example.com', 'PUT', '/draft;v=2/'],
      ['github.com', 'POST', '/MyOrg//Tools.git/git-upload-pack'],
      ['uploads.example.com', 'POST', '/'],
      ['github.com', 'GET', '/MyOrg/App.git/info/refs'],
      ['github.com', 'POST', '/MyOrg/App.git/git-receive-pack'],
      ['github.com', 'POST', '/myorg/app/git-upload-pack'],
      ['github.com', 'POST', '/myorg/App/git-upload-pack'],
      ['api.github.com', 'GET', '/repos/o/r/issues/1/comments'],
      ...[1, 2, 3, 4, 5].map((n): [string, string, string] => [
        'api.github.com',
        'POST',
        `/repos/o/r/issues/${n}/comments`
      ]),
      ...(['a', 'b', 'c', 'd'].map(o => ['codeberg.org', 'POST', `/${o}/repo/git-receive-pack`]) as [
        string,
        string,
        string
      ][]),
      [
        'blobs.example.com',
        'PUT',
        `/v2/acme/app/blobs/uploads/${longSegment}/part/2`,
        `/v2/acme/app/blobs/uploads/${longSegment}`.slice(0, 256)
      ],
      // cut short in the middle of an escape
      [
        'logs.example.com',
        'PUT',
        `/runs/${'chunk-'.repeat(60)}%41/end`,
        `/runs/${'chunk-'.repeat(60)}%41`.slice(0, 256)
      ]
    ];
    // a `//` is replayed collapsed: the engine refuses the raw form unless a `*` spans it, which
    // the suggestion never adds (it covers the request as a client normally sends it)
    const sent = traffic.map(([host, method, p]) => ({ host, method, path: p.replace(/\/{2,}/g, '/') }));

    it('the suggested http-filter allows every request it was built from', () => {
      const recs = traffic.map(([host, method, p, logged]) => req(host, method, logged ?? p));
      expect(recs[recs.length - 1].path).toHaveLength(256);
      const { suggestion } = summarizeHttpFilter(recs);
      const config = asPolicy(suggestion);
      const got = engine(config, sent);
      expect(sent.filter((_, i) => got[i] !== 'allow:allowed')).toEqual([]);
      // a pattern can't end in `/`: the request and its relaxed form each need a rule
      expect(rulesFor(suggestion, 'upload.pypi.org')).toEqual({ legacy: 'POST', 'legacy/*': 'POST' });
      expect(rulesFor(suggestion, 'forms.example.com')).toEqual({ report: 'POST', 'report*': 'POST' });
      // every form must be allowed: params and trailing slash, each with and without the other
      expect(rulesFor(suggestion, 'drafts.example.com')).toEqual({
        draft: 'PUT',
        'draft*': 'PUT',
        'draft*/*': 'PUT',
        'draft/*': 'PUT'
      });
      expect(rulesFor(suggestion, 'paths.example.com')).toEqual({ 'a/b': 'POST' });
      expect(engine(config, [{ host: 'paths.example.com', method: 'POST', path: '/a//b' }])).toEqual([
        'block:path-not-allowed'
      ]);
      expect(rulesFor(suggestion, 'blobs.example.com')).toEqual({ 'v2/acme/app/blobs/uploads/*': 'PUT' });
      // and still refuses what it should: a push nobody made, a write the job never did
      expect(
        engine(config, [
          { host: 'github.com', method: 'POST', path: '/other/repo.git/git-receive-pack' },
          { host: 'upload.pypi.org', method: 'PUT', path: '/legacy/' },
          { host: 'pypi.org', method: 'POST', path: '/simple/requests/' }
        ])
      ).toEqual(['block:method-not-allowed', 'block:method-not-allowed', 'block:method-not-allowed']);
    });
  });

  it('analyze: suggests a filter even when none is configured; enforce only on a refusal', () => {
    const recs = [req('registry.npmjs.org', 'GET', '/lodash'), req('pypi.org', 'GET', '/simple/requests/')];
    const httpFilter = summarizeHttpFilter(recs);
    const hosts = summarizeFlows(recs);
    const analyze = buildReport({ ...base, mode: 'analyze', hosts, httpFilter });
    expect(analyze).toContain(
      '<details>\n<summary>🧰 <b>Suggested <code>http-filter</code></b> — collapsed 2 requests → 2 rules (level B)</summary>'
    );
    expect(analyze).toContain(
      'http-filter: |\n  pypi.org:\n    "*": GET, HEAD\n  registry.npmjs.org:\n    "*": GET, HEAD'
    );
    expect(analyze).toContain('**✅ Nothing would be blocked.**');
    expect(buildReport({ ...base, mode: 'enforce', hosts, httpFilter })).not.toContain('Suggested <code>http-filter');
  });

  it('shows the platform endpoints the built-in list auto-allowed', () => {
    const md = buildReport({ ...base, mode: 'enforce', hosts: [], platformEndpoints: 7 });
    expect(md).toMatch(/<summary>🔧 <b>Diagnostics<\/b> — .*7 platform endpoints auto-allowed/);
    expect(md).toContain('`allow-github-platform: false` turns it off');
  });
});
