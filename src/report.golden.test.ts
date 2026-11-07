/**
 * Golden snapshots of the whole job summary, and a redaction canary.
 *
 * report.test.ts checks pieces of the output; these pin the exact Markdown for a handful of
 * representative jobs, so a refactor of report.ts can be shown to change nothing. Update a
 * snapshot only when the change to the summary is intended.
 *
 * The canary puts an encoded-looking label, a refused path and a custom method into every
 * section that prints a refused name, and checks that none of them appears anywhere in the
 * summary (src/redact.ts: the C5 disclosure boundary).
 */

import type { FlowRecord } from './flowlog';
import type { SudoUsage } from './parsers/sudo-parser';
import {
  buildReport,
  parseFirewallLog,
  summarizeContainers,
  summarizeFlows,
  summarizeHttpFilter,
  type HttpFilterSuggestion,
  type ReportInput
} from './report';

const NOW = new Date('2026-11-07T12:34:56Z');

/** Hex with digits: always redacted (redact.ts SHORT_HEX_LEN / HEX_MIN_LEN). */
const CANARY = '5ec7e7c0ffee1234';
const PATH_CANARY = 'pathcanary-0f1e2d3c4b5a';
const METHOD_CANARY = 'EXFILMETHODCANARY';

const fw = (prefix: string, src: string, dst: string, proto: string, dport: string, uid = '1001') =>
  `Nov  7 12:00:00 vm kernel: [1.2] ${prefix}: IN= OUT=eth0 SRC=${src} DST=${dst} LEN=60 PROTO=${proto} SPT=4 DPT=${dport} UID=${uid} GID=${uid}`;

const SUGGESTION: HttpFilterSuggestion = {
  hosts: [
    {
      host: 'api.github.com',
      rules: [
        { path: '*', methods: ['GET', 'HEAD'] },
        { path: 'repos/*/*/issues/*/comments', methods: ['POST'] }
      ]
    }
  ],
  requests: 12,
  rules: 2,
  specific: 1,
  coarse: false
};

const SUDO: SudoUsage = {
  ran: [
    {
      timestamp: 'Nov  7 12:00:00',
      user: 'runner',
      targetUser: 'root',
      command: '/usr/bin/apt-get',
      args: 'install -y jq'
    }
  ],
  refused: [],
  internal: [
    {
      timestamp: 'Nov  7 12:00:01',
      user: 'runner',
      targetUser: 'root',
      command: '/usr/bin/cat',
      args: '/etc/resolv.conf'
    }
  ]
};

const SELF_TESTS = [
  { name: 'sni-block', ok: true, detail: 'SNI selftest.safer-runner.invalid -> BLOCK (sni-not-allowed); curl exit 35' },
  { name: 'repoint', ok: true, detail: 'client dialled 192.0.2.1, proxy connected to 140.82.112.3:443 (HTTP 200)' },
  { name: 'dns-exact', ok: true, detail: 'srst-abc.objects.githubusercontent.com -> NXDOMAIN; DNS log labels it BLOCK' }
];

/** Allowed traffic every job has: GitHub platform, the job's own host, a passthrough host, plain HTTP. */
function allowedTraffic(): FlowRecord[] {
  return [
    {
      ts: 1,
      ev: 'tls',
      verdict: 'INTERCEPT',
      reason: 'allowed',
      layer: 'sni',
      sni: 'api.github.com',
      client: '10.1.0.4:1000',
      dst: '140.82.112.6:443'
    },
    {
      ts: 2,
      ev: 'https',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'api.github.com',
      sni: 'api.github.com',
      method: 'GET',
      path: '/zen',
      status: 200,
      req_bytes: 120,
      resp_bytes: 4096,
      client: '10.1.0.4:1000',
      dst: '140.82.112.6:443'
    },
    {
      ts: 3,
      ev: 'https',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'api.github.com',
      sni: 'api.github.com',
      method: 'GET',
      path: '/meta',
      status: 304,
      req_bytes: 120,
      resp_bytes: 0,
      client: '10.1.0.4:1000',
      dst: '140.82.112.6:443'
    },
    {
      ts: 4,
      ev: 'tls',
      verdict: 'INTERCEPT',
      reason: 'allowed',
      layer: 'sni',
      sni: 'registry.npmjs.org',
      client: '10.1.0.4:1001',
      dst: '104.16.0.35:443'
    },
    {
      ts: 5,
      ev: 'https',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'registry.npmjs.org',
      sni: 'registry.npmjs.org',
      method: 'GET',
      path: '/yaml',
      status: 200,
      req_bytes: 300,
      resp_bytes: 3 * 1024 * 1024,
      client: '10.1.0.4:1001',
      dst: '104.16.0.35:443'
    },
    {
      ts: 6,
      ev: 'https',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'registry.npmjs.org',
      sni: 'registry.npmjs.org',
      method: 'GET',
      path: '/nope',
      status: 404,
      req_bytes: 300,
      resp_bytes: 50,
      client: '10.1.0.4:1001',
      dst: '104.16.0.35:443'
    },
    {
      ts: 7,
      ev: 'tls',
      verdict: 'PASSTHROUGH',
      reason: 'passthrough',
      layer: 'sni',
      sni: 'hosted-compute-abc.githubapp.com',
      passthrough: true,
      client: '10.1.0.4:1002',
      dst: '20.1.2.3:443'
    },
    {
      ts: 8,
      ev: 'http',
      verdict: 'ALLOW',
      reason: 'allowed',
      layer: 'http',
      host: 'archive.ubuntu.com',
      method: 'GET',
      path: '/ubuntu/dists/noble/InRelease',
      status: 200,
      req_bytes: 200,
      resp_bytes: 256 * 1024,
      client: '10.1.0.4:1003',
      dst: '91.189.91.82:80'
    }
  ];
}

/** Refused traffic, one cause per block; `name(x)` lets the canary swap in encoded names. */
function refusedTraffic(v: 'BLOCK' | 'WOULD_BLOCK', name: (x: string) => string): FlowRecord[] {
  return [
    // fronting: allowed SNI, other Host inside it
    {
      ts: 10,
      ev: 'tls',
      verdict: 'INTERCEPT',
      reason: 'allowed',
      layer: 'sni',
      sni: 'cdn.jsdelivr.net',
      client: '10.1.0.4:2000',
      dst: '151.101.1.229:443'
    },
    {
      ts: 11,
      ev: 'https',
      verdict: v,
      reason: 'host-sni-mismatch',
      layer: 'http',
      host: name('front.example.org'),
      sni: 'cdn.jsdelivr.net',
      method: 'POST',
      path: `/${PATH_CANARY}`,
      client: '10.1.0.4:2000',
      dst: '151.101.1.229:443'
    },
    // internal address behind an allowed name
    {
      ts: 12,
      ev: 'upstream',
      verdict: v,
      reason: 'upstream-ip-forbidden',
      layer: 'ip',
      host: name('imds.example.org'),
      dst: '169.254.169.254:80',
      client: '10.1.0.4:2001'
    },
    {
      ts: 13,
      ev: 'http',
      verdict: v,
      reason: 'upstream-ip-forbidden',
      layer: 'http',
      host: name('imds.example.org'),
      method: 'GET',
      path: `/latest/${PATH_CANARY}`,
      client: '10.1.0.4:2001'
    },
    // not on the allowlist (TLS and plain HTTP), and the risky-subdomain denylist
    {
      ts: 14,
      ev: 'tls',
      verdict: v,
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: name('exfil.example.net'),
      client: '10.1.0.4:2002',
      dst: '203.0.113.9:443'
    },
    {
      ts: 15,
      ev: 'tls',
      verdict: v,
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: name('exfil.example.net'),
      client: '10.1.0.4:2003',
      dst: '203.0.113.9:443'
    },
    {
      ts: 16,
      ev: 'http',
      verdict: v,
      reason: 'host-not-allowed',
      layer: 'http',
      host: 'pypi.example.com',
      method: 'GET',
      path: '/simple/',
      client: '10.1.0.4:2004',
      dst: '203.0.113.10:80'
    },
    {
      ts: 17,
      ev: 'tls',
      verdict: v,
      reason: 'sni-denied',
      layer: 'sni',
      sni: 'gist.githubusercontent.com',
      client: '10.1.0.4:2005',
      dst: '185.199.108.133:443'
    },
    // http-filter: host allowed, method / path refused
    {
      ts: 18,
      ev: 'tls',
      verdict: 'INTERCEPT',
      reason: 'allowed',
      layer: 'sni',
      sni: name('uploads.example.com'),
      client: '10.1.0.4:2006',
      dst: '203.0.113.11:443'
    },
    {
      ts: 19,
      ev: 'https',
      verdict: v,
      reason: 'path-not-allowed',
      layer: 'http',
      host: name('uploads.example.com'),
      sni: name('uploads.example.com'),
      method: 'PUT',
      path: `/bucket/${PATH_CANARY}`,
      filter: 'block',
      client: '10.1.0.4:2006',
      dst: '203.0.113.11:443'
    },
    {
      ts: 20,
      ev: 'https',
      verdict: v,
      reason: 'method-not-allowed',
      layer: 'http',
      host: name('uploads.example.com'),
      sni: name('uploads.example.com'),
      method: METHOD_CANARY,
      path: `/${PATH_CANARY}`,
      filter: 'block',
      client: '10.1.0.4:2006',
      dst: '203.0.113.11:443'
    },
    // allowed name that did not resolve
    {
      ts: 21,
      ev: 'upstream',
      verdict: v,
      reason: 'upstream-unresolved',
      layer: 'ip',
      host: name('typo.example.com'),
      client: '10.1.0.4:2007'
    },
    // no hostname
    {
      ts: 22,
      ev: 'tls',
      verdict: v,
      reason: 'no-sni',
      layer: 'sni',
      sni: null,
      client: '10.1.0.4:2008',
      dst: '1.1.1.1:443'
    },
    {
      ts: 23,
      ev: 'tls',
      verdict: v,
      reason: 'ip-literal-sni',
      layer: 'sni',
      sni: '8.8.8.8',
      client: '10.1.0.4:2009',
      dst: '8.8.8.8:443'
    },
    // a reason the report doesn't know
    {
      ts: 24,
      ev: 'tls',
      verdict: v,
      reason: 'future-reason',
      layer: 'sni',
      sni: name('other.example.com'),
      client: '10.1.0.4:2010',
      dst: '203.0.113.12:443'
    }
  ];
}

function containerTraffic(v: 'BLOCK' | 'WOULD_BLOCK', name: (x: string) => string): FlowRecord[] {
  return [
    {
      ts: 30,
      ev: 'tls',
      verdict: 'PASSTHROUGH',
      reason: 'container-sni-only',
      layer: 'sni',
      sni: 'registry.npmjs.org',
      passthrough: true,
      source: 'container',
      client: '172.17.0.2:4000',
      dst: '104.16.0.35:443'
    },
    {
      ts: 31,
      ev: 'tls',
      verdict: v,
      reason: 'sni-not-allowed',
      layer: 'sni',
      sni: name('ctr-exfil.example.net'),
      source: 'container',
      client: '172.17.0.2:4001',
      dst: '203.0.113.20:443'
    },
    {
      ts: 32,
      ev: 'tls',
      verdict: 'INTERCEPT',
      reason: 'allowed',
      layer: 'sni',
      sni: 'productionresultssa1.blob.core.windows.net',
      source: 'container',
      client: '172.17.0.3:4002',
      dst: '20.60.1.1:443'
    },
    {
      ts: 33,
      ev: 'tls-client-fail',
      sni: name('productionresultssa1.blob.core.windows.net'),
      source: 'container',
      client: '172.17.0.3:4002'
    }
  ];
}

const FIREWALL = [
  fw('SaferRunner-Drop', '10.1.0.4', '1.1.1.1', 'TCP', '853'),
  fw('SaferRunner-Drop', '10.1.0.4', '1.1.1.1', 'TCP', '853'),
  fw('SaferRunner-Drop', '10.1.0.4', '198.51.100.7', 'TCP', '22'),
  fw('SaferRunner-CDrop', '172.17.0.2', '198.51.100.8', 'UDP', '123')
].join('\n');

const FIREWALL_ANALYZE = [
  fw('SaferRunner-Egress', '10.1.0.4', '198.51.100.7', 'TCP', '22'),
  fw('SaferRunner-CEgress', '172.17.0.2', '198.51.100.8', 'UDP', '123')
].join('\n');

const plain = (x: string) => x;
const encoded = (x: string) => `${CANARY}.${x}`;

function report(overrides: Partial<ReportInput> & Pick<ReportInput, 'mode' | 'hosts'>): string {
  return buildReport({
    job: 'build',
    firewall: [],
    dnsRefused: [],
    selfTests: SELF_TESTS,
    userDomains: ['registry.npmjs.org', 'archive.ubuntu.com', 'uploads.example.com', '.example.org'],
    integrity: {
      status: 'verified',
      body: '**Configuration Files**\n\n| File | Status |\n|--|--|\n| /etc/resolv.conf | VERIFIED |\n'
    },
    sudo: { ran: [], refused: [], internal: SUDO.internal },
    docker: { requested: 'remove-group', access: 'group-removed' },
    actionRef: 'v2.3.0',
    now: NOW,
    ...overrides
  });
}

describe('job summary golden snapshots', () => {
  it('enforce, nothing blocked', () => {
    const records = allowedTraffic();
    expect(
      report({ mode: 'enforce', hosts: summarizeFlows(records), httpFilter: summarizeHttpFilter(records) })
    ).toMatchSnapshot();
  });

  it('enforce: bypass attempts, not-allowed hosts, http-filter refusals and the rest', () => {
    const records = [...allowedTraffic(), ...refusedTraffic('BLOCK', plain)];
    expect(
      report({
        mode: 'enforce',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records, () => SUGGESTION),
        firewall: parseFirewallLog(FIREWALL),
        dnsRefused: ['exfil.example.net', 'srst-x.objects.githubusercontent.com', 'tunnel.example.com'],
        platformEndpoints: 5
      })
    ).toMatchSnapshot();
  });

  it('analyze: suggestions, sudo usage, docker kept', () => {
    const records = [...allowedTraffic(), ...refusedTraffic('WOULD_BLOCK', plain)];
    expect(
      report({
        mode: 'analyze',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records, () => SUGGESTION),
        firewall: parseFirewallLog(FIREWALL_ANALYZE),
        dnsRefused: ['exfil.example.net', 'tunnel.example.com'],
        sudo: SUDO,
        docker: { requested: 'keep', access: 'retained' },
        integrity: undefined
      })
    ).toMatchSnapshot();
  });

  it('containers: SNI-only, refused, untrusted CA, outside the proxy', () => {
    const records = [...allowedTraffic(), ...containerTraffic('BLOCK', plain)];
    const firewall = parseFirewallLog(FIREWALL);
    expect(
      report({
        mode: 'enforce',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records),
        firewall,
        containers: summarizeContainers(records, firewall, new Map([['172.17.0.2', 'redis']]))
      })
    ).toMatchSnapshot();
  });

  it('integrity tampered, self-test failed', () => {
    const records = allowedTraffic();
    expect(
      report({
        mode: 'enforce',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records),
        selfTests: [...SELF_TESTS.slice(0, 2), { name: 'dns-exact', ok: false, detail: 'no BLOCK line' }],
        integrity: { status: 'tampered', body: '| /etc/resolv.conf | ⚠️ TAMPERED | abc -> def |\n' }
      })
    ).toMatchSnapshot();
  });

  it('integrity unavailable, no self-tests', () => {
    const records = allowedTraffic();
    expect(
      report({
        mode: 'enforce',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records),
        selfTests: [],
        integrity: { status: 'unavailable', body: 'No validation data available.\n\n' }
      })
    ).toMatchSnapshot();
  });

  it('enforce ADVISORY: sudo and docker retained', () => {
    const records = [...allowedTraffic(), ...refusedTraffic('BLOCK', plain).slice(4, 8)];
    expect(
      report({
        mode: 'enforce',
        hosts: summarizeFlows(records),
        httpFilter: summarizeHttpFilter(records),
        sudoRetained: true,
        dockerRetained: true,
        sudo: SUDO,
        docker: { requested: 'keep', access: 'retained' }
      })
    ).toMatchSnapshot();
  });
});

describe('redaction canary (C5)', () => {
  /** Every section that prints a refused name, in both modes, with encoded names everywhere. */
  function canaryReport(mode: 'enforce' | 'analyze'): string {
    const v = mode === 'enforce' ? 'BLOCK' : 'WOULD_BLOCK';
    const records = [
      ...allowedTraffic(),
      // an allowed name under a wildcard entry can carry data too
      {
        ts: 40,
        ev: 'https',
        verdict: 'ALLOW',
        reason: 'allowed',
        layer: 'http',
        host: encoded('wild.example.org'),
        sni: encoded('wild.example.org'),
        method: 'GET',
        path: `/${PATH_CANARY}`,
        status: 200,
        client: '10.1.0.4:3000'
      } as FlowRecord,
      ...refusedTraffic(v, encoded),
      ...containerTraffic(v, encoded)
    ];
    const firewall = parseFirewallLog(FIREWALL);
    return report({
      mode,
      hosts: summarizeFlows(records),
      httpFilter: summarizeHttpFilter(records, () => SUGGESTION),
      firewall,
      containers: summarizeContainers(records, firewall),
      dnsRefused: [encoded('dns-only.example.net'), encoded('exfil.example.net')]
    });
  }

  it.each(['enforce', 'analyze'] as const)('%s: no encoded label, refused path or custom method is printed', mode => {
    const md = canaryReport(mode);
    // the sections are there, so the canary was really exercised
    for (const section of [
      'Bypass attempts',
      'Not on the allowlist',
      'Refused by `http-filter`',
      'Did not resolve',
      'Other',
      'Container egress',
      'DNS '
    ]) {
      expect(md).toContain(section);
    }
    expect(md).toContain('‹redacted›');
    expect(md).toContain('‹path hidden›');
    expect(md).not.toContain(CANARY);
    expect(md).not.toContain(PATH_CANARY);
    expect(md).not.toContain(METHOD_CANARY);
  });

  // Allowed names are redacted too, as in the host tables: a name under an allowed wildcard
  // entry can carry data.
  it('container table: an allowed name carrying data is redacted', () => {
    const records: FlowRecord[] = [
      {
        ts: 1,
        ev: 'tls',
        verdict: 'PASSTHROUGH',
        reason: 'container-sni-only',
        layer: 'sni',
        sni: encoded('wild.example.org'),
        passthrough: true,
        source: 'container',
        client: '172.17.0.2:4000'
      }
    ];
    const md = report({
      mode: 'enforce',
      hosts: summarizeFlows(records),
      containers: summarizeContainers(records, [])
    });
    expect(md).toContain('Container egress');
    expect(md).not.toContain(CANARY);
  });
});
