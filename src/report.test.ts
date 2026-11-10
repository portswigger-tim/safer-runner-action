import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { parseFlowLog, parseFlowLogWithOffsets, type FlowRecord } from './flowlog';
import { parseHttpFilter } from './config/inputs';
import { parse as parseYaml } from 'yaml';
import { buildPolicyConfig, type PolicyConfig } from './policy';
import { withoutSelfTests } from './setup/selftest';
import { suggestHttpFilter, suggestSudoConfig } from './report';
import { evaluateSudo, parseSudoConfig, ruleText } from './services/sudo/config';
import {
  allowedRequests,
  buildReport,
  containerDetails,
  humanBytes,
  httpFilterValue,
  suggestedBlock,
  blockedName,
  type HostSummary,
  parseFirewallLog,
  suggestedAllowlist,
  summarizeContainers,
  summarizeFlows,
  summarizeHttpFilter,
  type AllowedRequest,
  type FirewallEvent,
  type HttpFilterSuggestion,
  type Suggester
} from './report';

const PROXY_DIR = path.join(__dirname, '..', 'proxy');

/** A suggested filter as the summary prints it: its lines of the uses: block, here without their indent. */
const printedFilter = (s: HttpFilterSuggestion) =>
  suggestedBlock('o/r@v1', [{ input: 'http-filter', value: httpFilterValue(s) }])
    .split('\n')
    .slice(3)
    .map(l => l.replace(/^ {4}/, ''))
    .join('\n');
/** proxy/test-vectors.json "suggest": allowed requests -> the suggestion (proxy/suggest.py) */
interface SuggestVector {
  name: string;
  requests: AllowedRequest[];
  expect: HttpFilterSuggestion;
  replay?: AllowedRequest[];
  refuse?: AllowedRequest[];
}
const SUGGEST: SuggestVector[] = JSON.parse(fs.readFileSync(path.join(PROXY_DIR, 'test-vectors.json'), 'utf8')).suggest;

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
      {
        prefix: 'SaferRunner-Drop',
        proto: 'TCP',
        src: '10.1.0.4',
        dst: '1.1.1.1',
        dport: '853',
        sport: '4',
        uid: '1001'
      }
    ]);
  });
});

describe('buildReport', () => {
  const hosts = summarizeFlows(parseFlowLog(log));
  const base = { job: 'j', firewall: [], dnsRefused: [], selfTests: [] };

  it('enforce: every blocked host and name in the Blocked table; no analyze suggestions', () => {
    const md = buildReport({ ...base, mode: 'enforce', hosts, dnsRefused: ['x.example'] });
    const blocked = md.slice(md.indexOf('#### Blocked'), md.indexOf('<details>'));
    expect(blocked).toContain('`evil.example.com`');
    expect(blocked).toContain('| `BLOCK` | dns | — | `x.example` |');
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
    // the job's own entries were not recorded here: the block says to keep them
    expect(md).toContain(
      '    allowed-domains: | # keep your existing allowed-domains entries too\n      registry.npmjs.org\n```'
    );
    // the fronting attempts are rows with their reason; no alert explains them
    expect(md).toContain('| `host-sni-mismatch` | http | 1 | `api.github.com` |');
    expect(md).not.toContain('[!CAUTION]');
  });

  it('says explicitly when rows are cut (attacks sort first, so they are never pushed out)', () => {
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
    expect(md).toContain('+6 more not shown here');
    expect(md).toContain('| **306** |');
    // the attack sorts first, so the cut never pushes it out
    expect(md).toContain('`zz.example`');
  });

  it('escapes table-breaking characters in hostnames', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      hosts: summarizeFlows(parseFlowLog(JSON.stringify({ ev: 'http', verdict: 'BLOCK', reason: 'x', host: 'a|`b' })))
    });
    expect(md).toContain("`a\\|'b`");
    expect(md).toContain('| `x` |'); // unknown reasons are never dropped: the code as the log wrote it
  });

  it('never pastes a malformed name into the YAML', () => {
    const h = summarizeFlows(
      parseFlowLog(JSON.stringify({ ev: 'http', verdict: 'BLOCK', reason: 'host-not-allowed', host: 'a b:c\nx' }))
    );
    expect(suggestedAllowlist(h)).toEqual([]);
  });

  it('a sudo command line cannot break out of its table cell', () => {
    const md = buildReport({
      ...base,
      mode: 'analyze',
      hosts: [],
      sudo: {
        ran: [{ timestamp: '', user: 'runner', targetUser: 'root', command: '/usr/bin/echo', args: '`x` | [!NOTE]' }],
        refused: [],
        internal: []
      }
    });
    // a table cell: backticks and pipes cannot close the code span or the cell
    expect(md).toContain("| `/usr/bin/echo 'x' \\| [!NOTE]` |");
  });
});

describe('the layout, on a real flow log (beta.2)', () => {
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

  it('opens with the title and the row of numbers; ADVISORY in the title and a warning', () => {
    const lines = md.split('\n');
    // docker: keep under enforce is ADVISORY, like retained sudo (G4)
    expect(lines[0]).toBe('### Safer Runner · `enforce` · ADVISORY · job `enforce`');
    expect(lines[2]).toBe('| Blocked | Hosts | Requests | ↑ Out | ↓ In | sudo | docker |');
    expect(md).toContain(
      '> [!WARNING]\n> **ADVISORY: not an enforced boundary** (docker kept).\n>\n> `docker: keep` kept docker'
    );
  });

  it('puts the parts in order: numbers, Blocked, the collapsed parts, footer', () => {
    const order = [
      '| Blocked |',
      '#### Blocked',
      '<summary>Allowed:',
      '<summary>GitHub',
      '<summary>Safer Runner:',
      '<sub>2026'
    ].map(h => md.indexOf(h));
    expect(order.every(i => i >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it('counts only genuinely allowed traffic (beta.2 counted blocked requests and phantom hosts)', () => {
    const allowed = hosts.filter(h => !['BLOCK', 'WOULD_BLOCK'].includes(h.verdict));
    const blockedRequests = hosts.filter(h => h.verdict === 'BLOCK').reduce((a, h) => a + h.requests, 0);
    expect(blockedRequests).toBeGreaterThan(0);
    expect(allowed.map(h => h.name)).not.toEqual(expect.arrayContaining(['100.64.0.1.nip.io']));
    expect(allowed).toHaveLength(15); // 18 in beta.2: 3 phantoms refused upstream
    expect(md).toContain('| **13** | 7 + 8 GitHub | 109 |');
    expect(md).toContain('<summary>Allowed: 7 hosts · 26 requests ·');
  });

  it("lists blocked traffic in one table, by the flow log's reason, with its data", () => {
    const order = [
      '`host-sni-mismatch`',
      '`upstream-ip-forbidden`',
      '`sni-not-allowed`',
      '`no-sni`',
      '`upstream-unresolved`',
      '`Drop`'
    ];
    const at = order.map(o => md.indexOf(`| ${o}`));
    expect(at.every(i => i >= 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    expect(md).toContain('| `upstream-ip-forbidden` | ip, http | 2 | `100.64.0.1.nip.io` → `100.64.0.1` |');
    expect(md).toContain('`api.github.com` inside TLS for `github.com`, dialled `140.82.112.3`');
    expect(md).toContain('| `Drop` | firewall | 1 | `1.1.1.1:853` TCP · DNS over TLS · uid 1001 |');
  });

  it('an unresolved name is only `upstream-unresolved`, never an attack (no DNS-layer rebind drop any more)', () => {
    // beta.2's dnsmasq dropped these answers; the proxy's IP guard now refuses them with the IP
    expect(md).toContain('| `upstream-unresolved` | ip, http | 1 | `10.0.0.1.nip.io` <sub>plain HTTP</sub> |');
    expect(md).not.toContain('DNS-rebind');
  });

  it('enforce offers nothing to paste: what it blocked needs a look, and the table names it', () => {
    expect(md).not.toContain('```');
    expect(md).toContain('| `sni-not-allowed` | sni | 1 | `octocat.github.io` |');
  });

  it("splits allowed traffic into the job's hosts and GitHub's, both collapsed", () => {
    const github = md.slice(md.indexOf('<summary>GitHub, always allowed: 8 hosts'));
    expect(github).toContain('`release-assets.githubusercontent.com`');
  });

  it('never prints a measurement that was not taken (beta.2 printed 0 B for passthrough)', () => {
    expect(md).toContain('| `hosted-compute-watchdog-prod-iad-01.githubapp.com` | — |  |  | `passthrough` |');
    expect(md).toContain('| `broker.actions.githubusercontent.com` | 1 |  |  | 101 ×1 |');
  });

  it('ends with a footer: the time and the action, linked to its repository', () => {
    expect(md.trimEnd().split('\n').pop()).toBe(
      '<sub>2026-11-04 19:21 UTC · [Safer Runner](https://github.com/portswigger-tim/safer-runner-action)</sub>'
    );
  });

  it('keeps GitHub alerts at the top level (they do not render inside <details>)', () => {
    let depth = 0;
    for (const line of md.split('\n')) {
      depth += (line.match(/<details>/g) ?? []).length - (line.match(/<\/details>/g) ?? []).length;
      if (/^> \[!/.test(line)) expect(depth).toBe(0);
    }
  });

  it('a clean enforce run is short: no alert, no YAML, everything else collapsed', () => {
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
      docker: { requested: 'remove-group', access: 'group-removed' },
      integrity: { status: 'verified', body: '' }
    });
    expect(out).not.toContain('[!');
    expect(out).not.toContain('```');
    expect(out).not.toContain('####');
    expect(out).toContain('| 0 | 1 + 1 GitHub | 2 | 0 B | 2.0 KiB | removed | removed |');
    // outside <details> and the table of numbers: the title and the footer
    const visible = out
      .replace(/<details>[\s\S]*?<\/details>/g, '')
      .split('\n')
      .filter(l => l.trim() && !l.startsWith('|'));
    expect(visible).toHaveLength(2);
  });

  it("shows the tamper check, with its own tables, in Safer Runner's part", () => {
    const out = buildReport({
      mode: 'enforce',
      job: 'build',
      hosts: [],
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      integrity: { status: 'verified', body: '**Configuration Files**\n' }
    });
    const checks = out.slice(out.indexOf('<summary>Safer Runner:'));
    expect(checks).toContain('| ✅ | tamper check | no change seen |');
    expect(checks).toContain('**Configuration Files**');
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

  it('carries a layer "ip" record end to end, as proxy/policy.py writes it', () => {
    // an allowlisted name that resolves to the metadata service (SSRF): TLS allowed by name,
    // then the upstream refused; the request on that connection never left the runner
    const records = parseFlowLog(
      [
        {
          ts: 1,
          ev: 'tls',
          verdict: 'INTERCEPT',
          reason: 'allowed',
          layer: 'sni',
          sni: 'meta.example.org',
          dst: '1.2.3.4:443',
          client: '10.1.0.4:5000',
          source: 'host'
        },
        {
          ts: 2,
          ev: 'upstream',
          verdict: 'BLOCK',
          reason: 'upstream-ip-forbidden',
          layer: 'ip',
          host: 'meta.example.org',
          dst: '169.254.169.254:443',
          resolved: ['169.254.169.254'],
          client: '10.1.0.4:5000',
          source: 'host'
        },
        {
          ts: 3,
          ev: 'https',
          verdict: 'ALLOW',
          reason: 'allowed',
          layer: 'http',
          host: 'meta.example.org',
          sni: 'meta.example.org',
          method: 'POST',
          path: '/latest/api/token',
          client: '10.1.0.4:5000'
        }
      ]
        .map(r => JSON.stringify(r))
        .join('\n')
    );
    const layer: FlowRecord['layer'] = records[1].layer;
    expect(layer).toBe('ip');
    const hosts = summarizeFlows(records);
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({ name: 'meta.example.org', verdict: 'BLOCK', layers: ['ip'] });
    expect(allowedRequests(records)).toEqual([]);
    const md = buildReport({ mode: 'enforce', job: 'j', hosts, firewall: [], dnsRefused: [], selfTests: [] });
    expect(md).toContain('| `upstream-ip-forbidden` | ip | 1 | `meta.example.org` → `169.254.169.254` |');
    expect(md).not.toContain('/latest/api/token');
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
  const numbers = (md: string) => md.split('\n').find(l => /^\| (\*\*\d+\*\*|\d+) \|/.test(l));

  it('labels enforce with sudo retained as ADVISORY in the title, with the reason', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true });
    expect(md).toContain('### Safer Runner · `enforce` · ADVISORY · job `j`');
    expect(md).toContain(
      '> [!WARNING]\n> **ADVISORY: not an enforced boundary** (sudo kept).\n>\n> `disable-sudo: false` kept sudo'
    );
    expect(numbers(md)).toContain('| ⚠️ kept |');
  });

  it.each([
    ['unavailable', 'no baseline', '⚠️'],
    [undefined, 'not run', '⚠️'],
    ['tampered', 'CHANGED', '⚠️'],
    ['verified', 'no change seen', '✅']
  ] as const)(
    'shows the post-run tamper check (%s) as its own result, never as an intact boundary',
    (status, text, icon) => {
      const md = buildReport({
        ...base,
        mode: 'enforce',
        sudoRetained: false,
        integrity: status ? { status, body: '' } : undefined
      });
      expect(md).toContain(`| ${icon} | tamper check | ${text} |`);
      expect(md).toContain(`<summary>Safer Runner: self-tests not run · tamper check: ${text}</summary>`);
      expect(md).not.toContain('intact');
    }
  );

  it('labels enforce with sudo removed as plain enforce', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      sudoRetained: false,
      sudo: { ran: [], refused: [], internal: [] }
    });
    expect(md).not.toContain('ADVISORY');
    expect(md).toContain('### Safer Runner · `enforce` · job `j`');
    expect(numbers(md)).toContain('| removed |');
  });

  it('never labels analyze as advisory enforce', () => {
    expect(buildReport({ ...base, mode: 'analyze', sudoRetained: true })).not.toContain('ADVISORY: not an enforced');
  });

  it('labels enforce with docker retained (verified) as ADVISORY, like sudo (G4)', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      dockerRetained: true,
      docker: { requested: 'keep', access: 'retained' }
    });
    expect(md).toContain('· ADVISORY ·');
    expect(md).toContain('**ADVISORY: not an enforced boundary** (docker kept).');
    expect(md).toContain('`docker: keep` kept docker, which is root-equivalent');
    expect(numbers(md)).toMatch(/\| ⚠️ kept \|$/);
    expect(md).not.toMatch(/disable-docker|stop-docker|sudo-config/);
    expect(buildReport({ ...base, mode: 'enforce', dockerRetained: false })).not.toContain('[!');
  });

  it('names both when sudo and docker were retained', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true, dockerRetained: true });
    expect(md).toContain('**ADVISORY: not an enforced boundary** (sudo kept, docker kept).');
  });

  it('never labels analyze ADVISORY for kept docker', () => {
    expect(buildReport({ ...base, mode: 'analyze', dockerRetained: true })).not.toContain('ADVISORY: not an enforced');
  });

  it('analyze: the docker policy is shown as not applied, with the state as it is', () => {
    const md = buildReport({ ...base, mode: 'analyze', docker: { requested: 'remove-group', access: 'retained' } });
    expect(md).toContain('| ✅ | `docker: remove-group` | not applied (analyze); runner user can use docker |');
    expect(md).not.toContain('docker kept');
  });

  it('reports the verified docker state, not just the input (G4)', () => {
    const removed = buildReport({
      ...base,
      mode: 'enforce',
      docker: { requested: 'remove-group', access: 'group-removed' }
    });
    expect(numbers(removed)).toMatch(/\| removed \|$/);
    expect(removed).toContain(
      '| ✅ | `docker: remove-group` | runner user removed from the docker group, socket root-only |'
    );
    const stopped = buildReport({ ...base, mode: 'enforce', docker: { requested: 'stop', access: 'not-running' } });
    expect(numbers(stopped)).toMatch(/\| stopped \|$/);
    expect(stopped).toContain('| ✅ | `docker: stop` | docker daemon not running |');
    const kept = buildReport({
      ...base,
      mode: 'enforce',
      dockerRetained: true,
      docker: { requested: 'keep', access: 'retained' }
    });
    expect(kept).toContain('| ⚠️ | `docker: keep` | runner user can use docker |');
  });

  it('shows the dockerd restart for CA trust as the action’s own docker change', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      docker: { requested: 'remove-group', access: 'group-removed', caRestart: true }
    });
    expect(md).toContain('| ✅ | dockerd restart | restarted so it trusts the proxy CA |');
  });

  it('the sudo ADVISORY wording does not mention sudo-config', () => {
    const md = buildReport({ ...base, mode: 'enforce', sudoRetained: true });
    expect(md).toContain('`disable-sudo: false` kept sudo');
    expect(md).not.toContain('sudo-config');
  });

  const cmd = (command: string) => ({ timestamp: '', user: 'runner', targetUser: 'root', command, args: '' });

  it('analyze: tells a sudo-using job what enforce would block', () => {
    const sudo = { ran: [cmd('/usr/bin/apt-get'), cmd('/usr/bin/id'), cmd('/usr/bin/tee')], refused: [], internal: [] };
    const md = buildReport({ ...base, mode: 'analyze', sudo });
    expect(md).toContain('| `disable-sudo` | sudo | 1 | `/usr/bin/apt-get` |');
    expect(numbers(md)).toMatch(/^\| \*\*3\*\* \|/);
    const none = buildReport({ ...base, mode: 'analyze', sudo: { ran: [], refused: [], internal: [] } });
    expect(numbers(none)).toMatch(/^\| 0 \|.*\| 0 \| not recorded \|$/);
  });

  it('analyze: the policy decides what would be blocked (sudo-config, disable-sudo: false)', () => {
    const sudo = { ran: [cmd('/usr/bin/apt-get'), cmd('/usr/bin/id')], refused: [], internal: [] };
    const covered = buildReport({
      ...base,
      mode: 'analyze',
      sudo,
      sudoPolicy: { rules: ['/usr/bin/apt-get', '/usr/bin/id'], kept: false, wouldBlock: [] }
    });
    expect(covered).not.toMatch(/\| sudo \| \d/);
    // a sudo-config is never a boundary: enforce with it would be ADVISORY
    expect(numbers(covered)).toContain('| ⚠️ 2 |');
    expect(covered).toContain('The job sets `sudo-config`, so enforce would be ADVISORY.');
    expect(covered).toContain('<summary>Sudo, allowed: 2 commands · 2 runs</summary>');
    const kept = buildReport({ ...base, mode: 'analyze', sudo, sudoPolicy: { rules: [], kept: true, wouldBlock: [] } });
    expect(numbers(kept)).toContain('| ⚠️ 2 |');
    expect(kept).toContain('Remove `disable-sudo: false`: it keeps sudo, so enforce would be ADVISORY.');
  });

  it('analyze: the suggested sudo-config pastes back as printed, never with a *, with the caveat', () => {
    const ran = [
      { ...cmd('/usr/bin/apt-get'), args: 'install -y jq' },
      { ...cmd('/usr/bin/apt-get'), args: 'update' },
      // a secret-looking argument (the C5 canary) is never suggested
      { ...cmd('/usr/bin/tool'), args: '--id 5ec7e7c0ffee1234' },
      { ...cmd('/usr/bin/psql'), targetUser: 'postgres', args: '-c select' }
    ];
    const suggestion = suggestSudoConfig(ran, PROXY_DIR);
    expect(suggestion).toEqual({
      rules: ['/usr/bin/apt-get install -y jq', '/usr/bin/apt-get update'],
      omitted: { secret: 1, unrepresentable: 0, other_user: 1, over_cap: 0 }
    });
    const md = buildReport({
      ...base,
      mode: 'analyze',
      sudo: { ran, refused: [], internal: [] },
      sudoPolicy: {
        rules: [],
        kept: false,
        wouldBlock: ran,
        suggestion,
        flagged: { '/usr/bin/apt-get update': 'gives the job root (apt-get can run or write anything)' }
      }
    });
    expect(md).toContain('Sudo lines not suggested: 1 with arguments that look like a secret, 1 run as another user.');
    // the block, read back the way the action reads the input
    const block = md.match(/```yaml\n([\s\S]*?)\n```/)![1];
    expect(block).not.toContain('5ec7e7c0ffee1234');
    expect(block).toContain('sudo-config: | # ⚠️ ADVISORY');
    expect(block).toContain('- /usr/bin/apt-get update # ⚠️ gives the job root');
    // the warnings are YAML comments: the block still reads back as the same lines
    const rules = parseSudoConfig(parseYaml(block)[0].with['sudo-config']);
    expect(rules.map(ruleText)).toEqual(suggestion.rules);
    expect(evaluateSudo(rules, false, ran.slice(0, 2)).wouldBlock).toEqual([]);
  });

  it('enforce with a sudo-config allowlist is ADVISORY', () => {
    const md = buildReport({
      ...base,
      mode: 'enforce',
      sudo: { ran: [], refused: [], internal: [] },
      sudoPolicy: { rules: ['/usr/bin/apt-get update'], kept: false, wouldBlock: [] }
    });
    expect(md).toContain('**ADVISORY: not an enforced boundary** (1 sudo-config line).');
    expect(md).toContain('`sudo-config` kept sudo for 1 command line');
  });

  // beta.2 said "Workflow executed 4 sudo commands": one of its own plus three refused attempts
  it("the action's own and refused sudo never count as the workflow's usage", () => {
    const sudo = {
      ran: [],
      refused: [cmd('/usr/bin/true'), cmd('/usr/sbin/iptables-save')],
      internal: [cmd('/usr/bin/cat')]
    };
    const analyze = buildReport({ ...base, mode: 'analyze', sudo });
    expect(numbers(analyze)).toMatch(/^\| 0 \|.*\| 0 \| not recorded \|$/);
    const enforce = buildReport({ ...base, mode: 'enforce', sudo });
    expect(enforce).toContain('| `disable-sudo` | sudo | 1 | `/usr/bin/true` |');
    expect(numbers(enforce)).toMatch(/^\| \*\*2\*\* \|/);
    expect(enforce).toContain('| ✅ | own sudo | `/usr/bin/cat` |');
    expect(enforce).not.toContain('Sudo, allowed');
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
      firewall: [{ dst: '1.1.1.1:853', dport: '853', proto: 'TCP', n: 2, rejected: true }]
    });
    expect(svc.untrusted).toEqual(['productionresultssa1.blob.core.windows.net']);
    expect(svc.denied).toEqual(['evil.test']);
  });

  it('renders a collapsed part with the CA hint, and nothing when there were no containers', () => {
    const d = containerDetails(summarizeContainers(records, firewall))!;
    expect(d.summary).toBe('Containers: 2 containers');
    expect(d.body).toContain('⚠️ **TLS failed: the container does not trust the proxy CA:**');
    expect(d.body).toContain('`github.com` <sub>`container-sni-only`</sub>');
    expect(containerDetails([])).toBeUndefined();
  });

  it('a container firewall event is one row, with its container; a host one has its uid', () => {
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts: summarizeFlows(records),
      firewall,
      dnsRefused: [],
      selfTests: [],
      containers: summarizeContainers(records, firewall)
    });
    expect(md).toContain('| `Drop` | firewall | 1 | `8.8.8.8:853` TCP · DNS over TLS · uid 1001 |');
    expect(md).toContain('| `CDrop` | firewall | 2 | `1.1.1.1:853` TCP · DNS over TLS · from `172.18.0.2` |');
    expect(md).toContain('<summary>Containers: 2 containers</summary>');
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

  it('enforce: blocked subdomains of allowlisted names are rows of their own, redacted', () => {
    const secret = 'c2VjcmV0LXRva2VuLTEyMzQ';
    const md = buildReport({
      ...base,
      mode: 'enforce',
      dnsRefused: [`${secret.toLowerCase()}.objects.githubusercontent.com`, 'www.example.com', 'example.org']
    });
    expect(md).not.toContain('Subdomains of exact entries');
    expect(md).not.toContain('`*.');
    expect(md.toLowerCase()).not.toContain(secret.toLowerCase());
    for (const n of ['`‹redacted›.objects.githubusercontent.com`', '`www.example.com`', '`example.org`']) {
      expect(md).toContain(`| \`BLOCK\` | dns | — | ${n} |`);
    }
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
    // enforce suggests nothing; analyze suggests only the name that does not look like data
    expect(md).not.toContain('allowed-domains: |');
    const analyze = buildReport({
      ...base,
      mode: 'analyze',
      hosts: [h(`${secret}.attacker.com`, 'sni-not-allowed'), h('ok.attacker.com', 'sni-not-allowed')],
      dnsRefused: []
    });
    expect(analyze).toContain(
      '    allowed-domains: | # keep your existing allowed-domains entries too\n      ok.attacker.com\n```'
    );
    expect(analyze).not.toContain(secret);
  });

  it('analyze: says what enforce would do', () => {
    const md = buildReport({ ...base, mode: 'analyze', dnsRefused: ['www.example.com'] });
    expect(md).toContain('#### Enforce would block');
    expect(md).toContain('| `WOULD_BLOCK` | dns | — | `www.example.com` |');
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
  const rulesFor = (s: HttpFilterSuggestion | undefined, host: string) =>
    Object.fromEntries((s?.hosts.find(h => h.host === host)?.rules ?? []).map(r => [r.path, r.methods.join(', ')]));
  /** the post step's suggester: proxy/suggest.py */
  const py: Suggester = reqs => suggestHttpFilter(reqs, PROXY_DIR);
  const summarize = (recs: FlowRecord[]) => summarizeHttpFilter(recs, py);
  const base = { job: 'j', firewall: [], dnsRefused: [], selfTests: [] };

  describe('suggested http-filter (proxy/suggest.py, shared vectors)', () => {
    // the synthesis itself is checked by proxy/suggest_test.py; this runs the same vectors
    // through the flow-log path the post step uses (records -> allowedRequests -> suggest.py)
    it.each(SUGGEST.map(c => [c.name, c] as const))('%s', (_, c) => {
      const { suggestion } = summarize(c.requests.map(r => req(r.host, r.method, r.path)));
      expect(suggestion).toEqual(c.expect);
    });

    it('renders a NONE rule as NONE', () => {
      const trap = SUGGEST.find(c => c.name.startsWith('method-boundary trap'))!;
      expect(printedFilter(trap.expect)).toBe(
        'http-filter: |\n  github.com:\n    "*": POST\n    "*/git-receive-pack": NONE\n    "*/git-upload-pack": NONE\n' +
          '    "myorg/app/git-receive-pack": POST'
      );
    });

    it('prints any text so that YAML reads it back unchanged (the yaml library escapes it)', () => {
      // suggest.py and parseSuggestion never let these through; the printer must not rely on that
      const paths = ['a"b', 'x: y', ' #c', "it's", '-', '? q', 'a\\nb', 'tab\there', '\n', '*', '&a', '!t', '%'];
      const s = {
        hosts: [
          { host: 'a.example.com', rules: paths.map(path => ({ path, methods: ['GET', 'HEAD'] })) },
          { host: '- x: y', rules: [{ path: '*', methods: [] }] }
        ],
        requests: 0,
        rules: 0,
        specific: 0,
        coarse: false
      };
      const back = parseYaml(parseYaml(printedFilter(s))['http-filter']);
      expect(back).toEqual({
        'a.example.com': Object.fromEntries(paths.map(p => [p, 'GET, HEAD'])),
        '- x: y': { '*': 'NONE' }
      });
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
          layer: 'ip',
          host: 'meta.example.com',
          dst: '169.254.169.254:443',
          client: '10.1.0.4:1'
        }
      ];
      expect(allowedRequests(recs).map(r => r.host)).toEqual([
        'registry.npmjs.org',
        'results-receiver.actions.githubusercontent.com',
        'productionresultssa1.blob.core.windows.net',
        '0dd2149bb6f23853abcdef.example.com'
      ]);
      const { suggestion } = summarize(recs);
      expect(suggestion?.hosts.map(h => h.host)).toEqual(['registry.npmjs.org']);
      expect(rulesFor(suggestion, 'registry.npmjs.org')).toEqual({ '*': 'GET, HEAD' });
    });

    it('leaves out what the built-in platform list allowed on a filtered host', () => {
      const { suggestion } = summarize([
        req('api.github.com', 'GET', '/repos/o/r'),
        req('api.github.com', 'POST', '/repos/o/r/check-runs', { filter: 'platform', filter_rule: null })
      ]);
      expect(rulesFor(suggestion, 'api.github.com')).toEqual({ '*': 'GET, HEAD' });
      expect(suggestion?.requests).toBe(1);
    });

    it('builds no suggestion without a suggester, and the report still renders', () => {
      const recs = [req('registry.npmjs.org', 'GET', '/lodash'), refused('registry.npmjs.org', 'PUT', '/x')];
      for (const httpFilter of [summarizeHttpFilter(recs), summarizeHttpFilter(recs, () => undefined)]) {
        expect(httpFilter.suggestion).toBeUndefined();
        expect(httpFilter.blocks).toHaveLength(1);
        const md = buildReport({ ...base, mode: 'analyze', hosts: summarizeFlows(recs), httpFilter });
        expect(md).toContain('| `path-not-allowed` | http-filter | 1 | `registry.npmjs.org` `PUT` ‹path hidden› |');
        expect(md).not.toContain('http-filter: |');
      }
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
    const hf = summarize(recs);

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
      expect(allowedRequests(recs).map(r => r.path)).toEqual(['/lodash', '/myorg/app.git/git-upload-pack']);
      expect(rulesFor(hf.suggestion, 'github.com')).toEqual({ 'myorg/app/git-upload-pack': 'POST' });
      expect(rulesFor(hf.suggestion, 'registry.npmjs.org')).toEqual({ '*': 'GET, HEAD' });
    });

    it('enforce: lists refusals without their path, and suggests no filter', () => {
      const md = buildReport({ ...base, mode: 'enforce', hosts: summarizeFlows(recs), httpFilter: hf });
      expect(md).not.toContain(secret);
      expect(md).not.toContain(secret);
      expect(md).not.toContain('evil');
      expect(md).toContain('| `path-not-allowed` | http-filter | 2 | `github.com` `POST` ‹path hidden› |');
      expect(md).toContain('| `method-not-allowed` | http-filter | 1 | `registry.npmjs.org` `PUT` ‹path hidden› |');
      // a filter built from the allowed requests can never allow a blocked one: none in enforce
      expect(md).not.toContain('http-filter: |');
    });

    it('analyze: says the filter would refuse them, not that hosts would be blocked', () => {
      const wb = recs.map(r => (r.verdict === 'BLOCK' ? { ...r, verdict: 'WOULD_BLOCK' as const, status: 200 } : r));
      const md = buildReport({
        ...base,
        mode: 'analyze',
        hosts: summarizeFlows(wb),
        httpFilter: summarize(wb)
      });
      expect(md).toContain('| `path-not-allowed` | http-filter | 2 | `github.com` `POST` ‹path hidden› |');
      // the hosts themselves are allowed: no row says they would be blocked
      expect(md.match(/^\| `[a-z-]+` \| /gm)).toHaveLength(2);
      // the suggested filter is in the block, not an option under it
      expect(md).toContain('    http-filter: |\n');
      expect(md).not.toContain('Optional:');
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
      const hf = summarize(recs);
      expect(hf.blocks.map(b => [b.method, b.tries])).toEqual([
        ['INVALID', 2],
        ['DELETE', 1]
      ]);
      // never suggested either: only standard methods go into a rule
      const allowed = summarize([req('api.example.com', token, '/y'), req('api.example.com', 'PROPFIND', '/z')]);
      expect(allowed.suggestion?.hosts).toEqual([]);
      expect(printedFilter(allowed.suggestion!)).not.toMatch(/INVALID|A1B2|PROPFIND/);
      const md = buildReport({ ...base, mode: 'enforce', hosts: summarizeFlows(recs), httpFilter: hf });
      expect(md).not.toMatch(/A1B2C3D4E5F6/i);
      expect(md).toContain('| `method-not-allowed` | http-filter | 2 | `api.example.com` `INVALID` ‹path hidden› |');
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
      const hf = summarize(recs);
      // grouped without the path, so neither its text nor how many distinct ones there were shows
      expect(hf.blocks).toEqual([
        { host: 'api.example.com', method: 'POST', reason: 'path-not-allowed', verdict: 'BLOCK', tries: 2 },
        { host: 'api.example.com', method: 'PUT', reason: 'path-not-allowed', verdict: 'BLOCK', tries: 1 }
      ]);
      // everything post.ts logs a refusal from
      expect(JSON.stringify(hf)).not.toMatch(/73|65|63|72|74|plain|words/);
      for (const mode of ['enforce', 'analyze'] as const) {
        const md = buildReport({ ...base, mode, hosts: summarizeFlows(recs), httpFilter: hf });
        expect(md).toContain('| `path-not-allowed` | http-filter | 2 | `api.example.com` `POST` ‹path hidden› |');
        expect(md).not.toMatch(/73\/65|\b74\b|plain|words/);
      }
      expect(rulesFor(hf.suggestion, 'api.example.com')).toEqual({ '*': 'GET, HEAD' });
    });
  });

  describe('round trip: printed suggestion → http-filter input → policy.json → the addon', () => {
    /**
     * proxy/policy_core.py: policy.json checked and loaded as the addon does, then the decision
     * for each request ("allow:allowed", "block:<reason>"). `logged[i]`, when given, is `reqs[i]`
     * as logged: a request suggest.py left out (suggest.observe) decides as null.
     */
    const engine = (config: PolicyConfig, reqs: AllowedRequest[], logged?: AllowedRequest[]) => {
      const script = [
        'import json, sys',
        'sys.path.insert(0, sys.argv[1])',
        'import policy_core as pc, suggest',
        'd = json.load(sys.stdin)',
        'pc.validate_config(d["config"])',
        'p = pc.Policy.from_config(d["config"])',
        'def decide(r, logged):',
        '    if logged is not None and not suggest.observe([logged]):',
        '        return None',
        '    x = p.decide_filter(r["host"].lower(), r["method"].upper(), r["path"])',
        '    return x and f"{x.action}:{x.reason}"',
        'logged = d["logged"] or [None] * len(d["reqs"])',
        'print(json.dumps([decide(r, l) for r, l in zip(d["reqs"], logged)]))'
      ].join('\n');
      const run = spawnSync('python3', ['-I', '-c', script, PROXY_DIR], {
        input: JSON.stringify({ config, reqs, logged: logged ?? null }),
        encoding: 'utf8'
      });
      if (run.status !== 0) throw new Error(run.stderr);
      return JSON.parse(run.stdout) as (string | null)[];
    };
    /**
     * The YAML the report prints, pasted into a workflow (the runner passes the block scalar's
     * text as the input), read back as the action reads it, written as policy.json.
     */
    const asPolicy = (s: HttpFilterSuggestion): PolicyConfig => {
      const printed = printedFilter(s);
      const input = parseYaml(printed)['http-filter'];
      // the indented block as it stands in the summary reads the same
      expect(parseHttpFilter(printed.split('\n').slice(1).join('\n'))).toEqual(parseHttpFilter(input));
      const httpFilter = parseHttpFilter(input);
      const { config, warnings } = buildPolicyConfig({
        mode: 'enforce',
        githubDomains: [],
        allowedDomains: s.hosts.map(h => h.host).join('\n'),
        passthroughDomains: '',
        blockRiskySubdomains: false,
        containerPort: 20001,
        httpFilter,
        allowGithubPlatform: false
      });
      expect(warnings).toEqual([]);
      return JSON.parse(JSON.stringify(config));
    };

    it.each(SUGGEST.map(c => [c.name, c] as const))('%s', (_, c) => {
      const config = asPolicy(c.expect);
      // every request the suggestion was built from (as sent: replay, when the vector has one)
      const sent = c.replay ?? c.requests;
      const got = engine(config, sent, c.requests);
      expect(got.some(d => d !== null)).toBe(c.expect.hosts.length > 0);
      expect(sent.filter((_, i) => got[i] !== null && got[i] !== 'allow:allowed')).toEqual([]);
      if (c.refuse) {
        expect(
          engine(config, c.refuse).every(d => d === 'block:method-not-allowed' || d === 'block:path-not-allowed')
        ).toBe(true);
      }
    });
  });

  it('analyze: the suggested filter is in the block, configured or not; enforce only on a refusal', () => {
    const recs = [req('registry.npmjs.org', 'GET', '/lodash'), req('pypi.org', 'GET', '/simple/requests/')];
    const httpFilter = summarize(recs);
    const hosts = summarizeFlows(recs);
    const analyze = buildReport({
      ...base,
      mode: 'analyze',
      hosts,
      httpFilter,
      sudo: { ran: [], refused: [], internal: [] }
    });
    expect(analyze).toContain(
      '    http-filter: |\n      pypi.org:\n        "*": GET, HEAD\n      registry.npmjs.org:\n        "*": GET, HEAD'
    );
    expect(analyze).not.toContain('#### Enforce would block');
    // enforce, nothing blocked: no suggestion at all
    expect(buildReport({ ...base, mode: 'enforce', hosts, httpFilter })).not.toContain('http-filter: |');
  });

  it('shows the platform endpoints the built-in list auto-allowed', () => {
    const md = buildReport({ ...base, mode: 'enforce', hosts: [], platformEndpoints: 7 });
    expect(md).toMatch(/<summary>GitHub, always allowed: .* · 7 platform endpoints<\/summary>/);
  });
});
