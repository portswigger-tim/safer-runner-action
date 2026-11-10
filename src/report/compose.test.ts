import { parse as parseYaml } from 'yaml';
import type { FlowRecord } from '../flowlog';
import { readInputs } from '../config/inputs';
import { buildPolicyConfig, parseAllowedDomains, validatePattern } from '../policy';
import { ruleText } from '../services/sudo/config';
import { evaluateDocker } from '../services/docker/config';
import { summarizeFlows } from '../services/mitmproxy/flows';
import { summarizeHttpFilter, type HttpFilterSuggestion } from '../services/mitmproxy/http-filter';
import {
  banner,
  buildReport,
  emojiOutsideAllowlist,
  reportSections,
  safeRef,
  suggestedForLog,
  type ReportInput
} from './compose';

const tls = (sni: string, verdict: string, reason: string, client: string): FlowRecord => ({
  ts: 1,
  ev: 'tls',
  verdict: verdict as FlowRecord['verdict'],
  reason,
  layer: 'sni',
  sni,
  client
});
const get = (host: string, client: string, verdict = 'ALLOW'): FlowRecord => ({
  ts: 2,
  ev: 'https',
  verdict: verdict as FlowRecord['verdict'],
  reason: 'allowed',
  layer: 'http',
  host,
  sni: host,
  method: 'GET',
  path: '/x',
  status: 200,
  client
});

const SUGGESTION: HttpFilterSuggestion = {
  hosts: [{ host: 'registry.npmjs.org', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] }],
  requests: 3,
  rules: 1,
  specific: 0,
  coarse: false
};

/** An analyze job that would need every input changed. */
function analyzeInput(overrides: Partial<ReportInput> = {}): ReportInput {
  const records = [
    tls('registry.npmjs.org', 'INTERCEPT', 'allowed', 'c:1'),
    get('registry.npmjs.org', 'c:1'),
    tls('pypi.org', 'WOULD_BLOCK', 'sni-not-allowed', 'c:2'),
    tls('files.pythonhosted.org', 'WOULD_BLOCK', 'sni-not-allowed', 'c:3')
  ];
  const ran = [
    { timestamp: '', user: 'runner', targetUser: 'root', command: '/usr/bin/apt-get', args: 'install -y jq' },
    { timestamp: '', user: 'runner', targetUser: 'root', command: '/usr/bin/nproc', args: '' }
  ];
  const observed = { uses: { container: 2 }, images: ['alpine:3.20'], services: 0, partial: false };
  return {
    mode: 'analyze',
    job: 'build',
    hosts: summarizeFlows(records),
    firewall: [],
    dnsRefused: [],
    selfTests: [],
    userDomains: ['registry.npmjs.org'],
    allowedDomains: ['registry.npmjs.org'],
    httpFilter: summarizeHttpFilter(records, () => SUGGESTION),
    sudo: { ran, refused: [], internal: [] },
    sudoPolicy: {
      rules: [],
      kept: false,
      wouldBlock: ran,
      suggestion: {
        rules: ['/usr/bin/apt-get install -y jq', '/usr/bin/nproc'],
        omitted: { secret: 0, unrepresentable: 0, other_user: 0, over_cap: 0 }
      },
      flagged: { '/usr/bin/apt-get install -y jq': 'gives the job root (apt-get can run or write anything)' }
    },
    docker: { requested: 'remove-group', access: 'retained' },
    dockerPolicy: { policy: 'remove-group', observed, evaluation: evaluateDocker('remove-group', observed) },
    actionRepository: 'portswigger-tim/safer-runner-action',
    actionRef: 'v2.5.0',
    now: new Date('2026-11-08T12:00:00Z'),
    ...overrides
  };
}

/** The `with:` inputs of the one YAML block under For enforce. */
function pastedInputs(md: string): Record<string, string> {
  const section = md.slice(md.indexOf('#### For enforce'));
  const blocks = section.match(/```yaml\n([\s\S]*?)\n```/g) ?? [];
  expect(blocks.length).toBeGreaterThanOrEqual(1);
  const step = parseYaml(blocks[0]!.replace(/^```yaml\n|\n```$/g, ''))[0];
  expect(step.uses).toBe('portswigger-tim/safer-runner-action@v2.5.0');
  return step.with;
}

/** Read inputs the way the action does: core.getInput reads INPUT_<NAME>. */
function withInputs<T>(inputs: Record<string, string>, fn: () => T): T {
  const keys = Object.keys(inputs).map(k => `INPUT_${k.toUpperCase()}`);
  Object.entries(inputs).forEach(([k, v]) => (process.env[`INPUT_${k.toUpperCase()}`] = v));
  try {
    return fn();
  } finally {
    keys.forEach(k => delete process.env[k]);
  }
}

describe('Suggested Enforce Configuration: the block pastes back as printed', () => {
  it('every suggested input reads back, through the action’s own input parsing, as the suggestion', () => {
    const md = buildReport(analyzeInput());
    const w = pastedInputs(md);
    expect(Object.keys(w)).toEqual(['mode', 'allowed-domains', 'http-filter', 'sudo-config', 'docker']);
    const inputs = withInputs(w, readInputs);
    expect(inputs.mode).toBe('enforce');
    // the job's own entry kept, the would-be-blocked names added; never a GitHub host
    const domains = parseAllowedDomains(inputs.allowedDomains);
    expect(domains).toEqual(['registry.npmjs.org', 'files.pythonhosted.org', 'pypi.org']);
    domains.forEach(d => expect(() => validatePattern(d)).not.toThrow());
    expect(inputs.httpFilter).toEqual([
      { host: 'registry.npmjs.org', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] }
    ]);
    // the ⚠️ comments are YAML comments: the lines read back unchanged
    expect(inputs.sudoConfig.map(ruleText)).toEqual(['/usr/bin/apt-get install -y jq', '/usr/bin/nproc']);
    expect(inputs.docker).toBe('keep');
  });

  it('an entry built from a secret prints masked: pasted back, it is refused, never widened', () => {
    const md = buildReport(analyzeInput({ allowedDomains: ['svc.vault-a1.corp.example.com'] }));
    // what the summary shows once the runner has masked the secret part
    const masked = md.replace('svc.vault-a1.corp.example.com', 'svc.***.corp.example.com');
    const w = pastedInputs(masked);
    const inputs = withInputs(w, readInputs);
    const { config, warnings } = buildPolicyConfig({
      mode: 'enforce',
      githubDomains: [],
      allowedDomains: inputs.allowedDomains,
      passthroughDomains: '',
      blockRiskySubdomains: true,
      containerPort: 1
    });
    expect(config.allow).not.toContain('svc.***.corp.example.com');
    expect(config.allow.some(p => p.includes('*'))).toBe(false);
    expect(warnings).toContainEqual(expect.stringContaining('svc.***.corp.example.com'));
  });

  it('marks the inputs that make enforce ADVISORY on their own line', () => {
    const md = buildReport(analyzeInput());
    expect(md).toContain('    sudo-config: | # ⚠️ ADVISORY\n');
    expect(md).toContain('    docker: keep # ⚠️ ADVISORY\n');
    expect(md).toContain('      - /usr/bin/apt-get install -y jq # ⚠️ gives the job root');
  });

  it('the job log gets the same block', () => {
    const md = buildReport(analyzeInput());
    const block = suggestedForLog(reportSections(analyzeInput()));
    expect(md).toContain('```yaml\n' + block + '\n```');
  });

  it('echoes the action the workflow used: a fork or a mirror stays itself, never swapped for upstream', () => {
    const sha = 'e939400047ab163b522acb202191ec01af9aa9f7';
    const md = buildReport(analyzeInput({ actionRepository: 'acme-corp/safer-runner-action', actionRef: sha }));
    // a SHA is pinned: no reminder, and no version (a fork's commit, or one between releases)
    expect(md).toContain(`- uses: acme-corp/safer-runner-action@${sha}\n`);
    expect(md).not.toContain('portswigger-tim/safer-runner-action@');
    expect(buildReport(analyzeInput({ actionRef: 'main' }))).toContain(
      '- uses: portswigger-tim/safer-runner-action@main # pin an exact version or commit SHA\n'
    );
  });

  it.each([
    [
      'an unpinnable ref',
      'portswigger-tim/safer-runner-action',
      'v1 # x\n- run: evil',
      'portswigger-tim/safer-runner-action@<pin an exact version or SHA>'
    ],
    ['a local `uses: ./`', '', '', '<owner>/<repo>@<pin an exact version or SHA>'],
    ['an injection-y repository', 'acme/x" onerror="y', 'v1', '<owner>/<repo>@<pin an exact version or SHA>'],
    ['a repository with ..', 'acme/..', 'v1', '<owner>/<repo>@<pin an exact version or SHA>']
  ])('%s: a placeholder, never the raw value, and the block still parses', (_, repo, ref, uses) => {
    const md = buildReport(analyzeInput({ actionRepository: repo, actionRef: ref }));
    expect(md).toContain(`- uses: ${uses} # pin an exact version or commit SHA`);
    expect(md).not.toContain('evil');
    expect(md).not.toContain('onerror');
    const block = md.match(/```yaml\n([\s\S]*?)\n```/)![1];
    expect(parseYaml(block)[0].uses).toBe(uses);
  });

  it('nothing to change: no Blocked table, and the block is just mode: enforce', () => {
    const md = buildReport({
      mode: 'analyze',
      job: 'j',
      hosts: [],
      firewall: [],
      dnsRefused: [],
      selfTests: [],
      sudo: { ran: [], refused: [], internal: [] }
    });
    expect(md).not.toContain('#### Enforce would block');
    expect(md).toContain(
      '```yaml\n- uses: <owner>/<repo>@<pin an exact version or SHA> # pin an exact version or commit SHA\n' +
        '  with:\n    mode: enforce\n```'
    );
  });
});

describe('the row of numbers and the Blocked table', () => {
  const unresolved: FlowRecord = {
    ts: 3,
    ev: 'upstream',
    verdict: 'BLOCK',
    reason: 'upstream-unresolved',
    layer: 'ip',
    host: 'typo.example.com',
    client: 'c:9'
  };
  const base = { mode: 'enforce' as const, job: 'j', firewall: [], dnsRefused: [], selfTests: [] };

  it('the Blocked count is the number of rows in the Blocked table', () => {
    const md = buildReport({
      ...base,
      hosts: summarizeFlows([unresolved, tls('pypi.org', 'BLOCK', 'sni-not-allowed', 'c:8')]),
      dnsRefused: ['tunnel.example.com']
    });
    expect(md).toContain('| **3** | 0 | 0 | 0 B | 0 B |');
    expect(md).toContain(
      '#### Blocked\n\n| Reason | Layer | Tries | Names |\n|:--|:--|--:|:--|\n' +
        '| `sni-not-allowed` | sni | 1 | `pypi.org` |\n' +
        '| `upstream-unresolved` | ip | 1 | `typo.example.com` |\n' +
        '| `BLOCK` | dns | — | `tunnel.example.com` |\n'
    );
  });

  it('a clean run is the row of numbers, and the rest collapsed', () => {
    const md = buildReport({ ...base, hosts: summarizeFlows([tls('a.example.com', 'INTERCEPT', 'allowed', 'c:1')]) });
    const open = md.replace(/<details>[\s\S]*?<\/details>\n\n/g, '');
    expect(open).toBe(
      '### Safer Runner · `enforce` · job `j`\n\n' +
        '| Blocked | Hosts | Requests | ↑ Out | ↓ In | sudo | docker |\n|--:|--:|--:|--:|--:|--:|--:|\n' +
        '| 0 | 1 | 0 | 0 B | 0 B | removed | not recorded |\n\n' +
        open.slice(open.indexOf('<sub>'))
    );
  });

  it('analyze: the count and the table are what enforce would block', () => {
    const md = buildReport({
      ...base,
      mode: 'analyze',
      hosts: summarizeFlows([tls('pypi.org', 'WOULD_BLOCK', 'sni-not-allowed', 'c:8')])
    });
    expect(md).toContain('| Enforce would block | Hosts |');
    expect(md).toContain('#### Enforce would block\n');
  });
});

describe('enforce: no suggested configuration', () => {
  it.each([
    ['sudo kept', { sudoRetained: true }],
    ['docker kept', { dockerRetained: true }],
    ['clean', {}]
  ])('%s', (_, extra) => {
    const md = buildReport({ ...analyzeInput(), mode: 'enforce', ...extra });
    expect(md).not.toContain('- uses:');
    expect(md).not.toContain('#### For enforce');
  });

  it('a blocked host is a row of the table, and nothing is offered to paste', () => {
    const records = [tls('pypi.org', 'BLOCK', 'sni-not-allowed', 'c:2')];
    const md = buildReport({ ...analyzeInput(), mode: 'enforce', hosts: summarizeFlows(records) });
    expect(md).toContain('| `sni-not-allowed` | sni | 1 | `pypi.org` |');
    expect(md).not.toContain('```');
  });

  it('ADVISORY: in the title, and a warning with every reason', () => {
    const md = buildReport({ ...analyzeInput(), mode: 'enforce', sudoRetained: true, dockerRetained: true });
    expect(md).toContain('### Safer Runner · `enforce` · ADVISORY · job `build`');
    expect(md).toContain('> [!WARNING]\n> **ADVISORY: not an enforced boundary** (sudo kept, docker kept).');
  });
});

describe('emoji are functional only', () => {
  it.each(['analyze', 'enforce'] as const)('%s: only the heading and verdict emoji', mode => {
    const md = buildReport({
      ...analyzeInput(),
      mode,
      integrity: { status: 'tampered', body: '| /etc/resolv.conf | ⚠️ TAMPERED |' },
      selfTests: [{ name: 'repoint', ok: false, detail: 'x' }],
      firewall: [
        { prefix: 'SaferRunner-Drop', proto: 'TCP', src: '10.1.0.4', dst: '1.1.1.1', dport: '853', uid: '1001' }
      ],
      dnsRefused: ['example.org']
    });
    expect(emojiOutsideAllowlist(md)).toEqual([]);
  });
});

describe('size', () => {
  it('the worst case (every table at its cap) stays under the 1 MiB job summary limit', () => {
    const name = (i: number, kind: string) => `${kind}-${i}-${'a'.repeat(40)}.example.com`;
    const records: FlowRecord[] = [];
    for (let i = 0; i < 400; i++) {
      records.push(tls(name(i, 'blocked'), 'BLOCK', 'sni-not-allowed', `b:${i}`));
      records.push(tls(name(i, 'allowed'), 'INTERCEPT', 'allowed', `a:${i}`), get(name(i, 'allowed'), `a:${i}`));
      records.push(tls(name(i, 'platform'), 'INTERCEPT', 'allowed', `p:${i}`), get(name(i, 'platform'), `p:${i}`));
    }
    const cmd = (i: number) => ({
      timestamp: '',
      user: 'runner',
      targetUser: 'root',
      command: '/usr/bin/x',
      args: `${'arg '.repeat(30)}${i}`
    });
    const md = buildReport({
      mode: 'enforce',
      job: 'j',
      hosts: summarizeFlows(records),
      userDomains: Array.from({ length: 400 }, (_, i) => name(i, 'allowed')),
      firewall: Array.from({ length: 400 }, (_, i) => ({
        prefix: 'SaferRunner-Drop',
        proto: 'TCP',
        src: '10.1.0.4',
        dst: `10.0.${i >> 8}.${i & 255}`,
        dport: '22',
        uid: '1001'
      })),
      dnsRefused: Array.from({ length: 400 }, (_, i) => name(i, 'dns')),
      selfTests: [],
      sudo: {
        ran: Array.from({ length: 400 }, (_, i) => cmd(i)),
        refused: Array.from({ length: 400 }, (_, i) => cmd(i)),
        internal: []
      }
    });
    expect(md).toContain('more not shown here');
    expect(Buffer.byteLength(md, 'utf8')).toBeLessThan(1024 * 1024);
  });
});

describe('banner', () => {
  it('the repository and ref the workflow used: its banner at that ref, linked to the repository', () => {
    expect(banner('portswigger-tim/safer-runner-action', 'v2.5.0')).toBe(
      '<a href="https://github.com/portswigger-tim/safer-runner-action"><img src="https://raw.githubusercontent.com/portswigger-tim/safer-runner-action/v2.5.0/docs/assets/banner.svg" width="480" alt="Safer Runner Action"></a>\n\n'
    );
    // a fork shows its own banner, at its own ref, and links to itself
    const fork = banner('acme-corp/safer-runner-action', 'a'.repeat(40));
    expect(fork).toContain(`raw.githubusercontent.com/acme-corp/safer-runner-action/${'a'.repeat(40)}/docs/`);
    expect(fork).toContain('href="https://github.com/acme-corp/safer-runner-action"');
  });

  it.each([
    ['a local `uses: ./`', '', ''],
    ['no repository', undefined, 'v2.5.0'],
    ['no ref', 'portswigger-tim/safer-runner-action', ''],
    ['a ref with a quote', 'portswigger-tim/safer-runner-action', 'v1" onerror="x'],
    ['a ref with ..', 'portswigger-tim/safer-runner-action', 'main/../../x'],
    ['a ref with a space', 'portswigger-tim/safer-runner-action', 'v1 x'],
    ['a ref with markup', 'portswigger-tim/safer-runner-action', '<img>'],
    ['a repository with a quote', 'acme/x" onerror="y', 'v1'],
    ['a repository with markup', '<img>/x', 'v1'],
    ['a repository with a space', 'acme/a b', 'v1'],
    ['a repository with ..', 'acme/..', 'v1'],
    ['a repository with a path', 'acme/x/y', 'v1'],
    ['an owner too long', `${'a'.repeat(40)}/x`, 'v1']
  ])('%s: no banner', (_, repo, ref) => {
    expect(banner(repo, ref)).toBe('');
  });

  it('the footer names the action as the workflow used it, linked to the repository', () => {
    expect(buildReport(analyzeInput({ actionRepository: 'acme-corp/safer-runner-action' }))).toContain(
      '[acme-corp/safer-runner-action@v2.5.0](https://github.com/acme-corp/safer-runner-action)</sub>'
    );
    // unknown or not safe to print: upstream, by name only
    expect(buildReport(analyzeInput({ actionRepository: 'x" y' }))).toContain(
      '[Safer Runner](https://github.com/portswigger-tim/safer-runner-action)</sub>'
    );
  });

  it('heads the summary', () => {
    expect(buildReport(analyzeInput()).startsWith('<a href="https://github.com/')).toBe(true);
    expect(buildReport(analyzeInput({ actionRef: '' })).startsWith('### Safer Runner')).toBe(true);
    expect(buildReport(analyzeInput({ actionRepository: '' })).startsWith('### Safer Runner')).toBe(true);
  });

  it('safeRef accepts tags, branches and SHAs only', () => {
    expect(['v2.5.0', 'main', 'feature/x-y_z.1', 'e939400047ab163b522acb202191ec01af9aa9f7'].map(safeRef)).toEqual([
      'v2.5.0',
      'main',
      'feature/x-y_z.1',
      'e939400047ab163b522acb202191ec01af9aa9f7'
    ]);
    expect(['-x', '.x', 'a b', 'a`b', 'a..b', 'a'.repeat(101)].map(safeRef)).toEqual(['', '', '', '', '', '']);
  });
});
