import type { FlowRecord } from '../../flowlog';
import { parseAllowedDomains } from '../../policy';
import type { ReportContext } from '../../report/section';
import { summarizeFlows } from './flows';
import { jobLog, report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };

const allowed: FlowRecord = {
  ts: 1,
  ev: 'https',
  verdict: 'ALLOW',
  reason: 'allowed',
  layer: 'http',
  host: 'registry.npmjs.org',
  sni: 'registry.npmjs.org',
  method: 'GET',
  path: '/x',
  status: 200,
  resp_bytes: 2048,
  client: '10.1.0.4:1000'
};
const notListed = (verdict: 'BLOCK' | 'WOULD_BLOCK', sni = 'pypi.example.com'): FlowRecord => ({
  ts: 2,
  ev: 'tls',
  verdict,
  reason: 'sni-not-allowed',
  layer: 'sni',
  sni,
  client: '10.1.0.4:1001'
});
const fronting = (verdict: 'BLOCK' | 'WOULD_BLOCK'): FlowRecord => ({
  ts: 3,
  ev: 'https',
  verdict,
  reason: 'host-sni-mismatch',
  layer: 'http',
  host: 'front.example.org',
  sni: 'cdn.example.net',
  client: '10.1.0.4:1002'
});

describe('proxy report (its Section)', () => {
  it('allowed traffic only: no blocked row, no suggestion, the totals', () => {
    const s = report({ hosts: summarizeFlows([allowed]) }, ENFORCE);
    expect([s.blocked, s.alerts, s.suggestions, s.deniedNames]).toEqual([[], [], [], []]);
    expect(s.totals).toEqual({ hosts: '1', requests: 1, out: 0, in: 2048 });
    expect(s.details.map(d => d.summary)).toEqual(['Allowed: 1 host · 1 request · ↑ 0 B · ↓ 2.0 KiB']);
  });

  it("splits the job's hosts from GitHub's when the job has its own allowlist", () => {
    const s = report({ hosts: summarizeFlows([allowed]), userDomains: ['registry.npmjs.org'] }, ENFORCE);
    expect(s.totals.hosts).toBe('1 + 0 GitHub');
    expect(
      report({ hosts: summarizeFlows([allowed]), userDomains: ['other.example'] }, ENFORCE).details[0].summary
    ).toBe('GitHub, always allowed: 1 host · 1 request · ↑ 0 B · ↓ 2.0 KiB');
  });

  it("enforce: a host not on the allowlist is a row with the flow log's reason, and the line to add", () => {
    const s = report({ hosts: summarizeFlows([allowed, notListed('BLOCK')]) }, ENFORCE);
    expect(s.blocked).toEqual([{ reason: '`sni-not-allowed`', layer: 'sni', tries: 1, what: '`pypi.example.com`' }]);
    expect(s.alerts).toEqual([]);
    expect(s.deniedNames).toEqual(['pypi.example.com']);
    // only what would allow what was blocked
    expect(s.suggestions).toEqual([{ input: 'allowed-domains', value: 'pypi.example.com\n' }]);
  });

  it('analyze: suggests the whole allowed-domains value, the job’s own entries kept', () => {
    const s = report(
      {
        hosts: summarizeFlows([allowed, notListed('WOULD_BLOCK')]),
        allowedDomains: parseAllowedDomains('registry.npmjs.org')
      },
      ANALYZE
    );
    expect(s.blocked.map(r => r.reason)).toEqual(['`sni-not-allowed`']);
    expect(s.suggestions).toEqual([{ input: 'allowed-domains', value: 'registry.npmjs.org\npypi.example.com\n' }]);
  });

  it('never repeats an entry that looks like data or a masked secret: says to keep it instead', () => {
    const s = report(
      {
        hosts: summarizeFlows([notListed('WOULD_BLOCK')]),
        allowedDomains: ['registry.npmjs.org', '5ec7e7c0ffee1234.internal.example', '***']
      },
      ANALYZE
    );
    expect(s.suggestions).toEqual([
      {
        input: 'allowed-domains',
        value: 'registry.npmjs.org\npypi.example.com\n',
        comment: 'keep your existing allowed-domains entries too'
      }
    ]);
  });

  it('without a record of the job’s entries: only the new names, and a comment to keep the rest', () => {
    const s = report({ hosts: summarizeFlows([notListed('WOULD_BLOCK')]) }, ANALYZE);
    expect(s.suggestions[0]).toMatchObject({
      value: 'pypi.example.com\n',
      comment: 'keep your existing allowed-domains entries too'
    });
  });

  it('never suggests a name that looks like data, and redacts it in its row', () => {
    const s = report({ hosts: summarizeFlows([notListed('WOULD_BLOCK', '5ec7e7c0ffee1234.example.com')]) }, ANALYZE);
    expect(s.suggestions).toEqual([]);
    expect(s.notes[0]).toMatch(/^1 blocked name not suggested/);
    expect(s.blocked[0].what).toBe('`‹redacted›.example.com`');
  });

  it('fronting: the TLS name that carried the Host and the address dialled, as data', () => {
    const s = report({ hosts: summarizeFlows([{ ...fronting('BLOCK'), dst: '151.101.1.229:443' }]) }, ENFORCE);
    expect(s.blocked).toEqual([
      {
        reason: '`host-sni-mismatch`',
        layer: 'http',
        tries: 1,
        what: '`front.example.org` inside TLS for `cdn.example.net`, dialled `151.101.1.229`'
      }
    ]);
  });

  it('rows are ordered by reason (attempts round the proxy first, then by layer), then by tries', () => {
    const unresolved: FlowRecord = {
      ts: 4,
      ev: 'upstream',
      verdict: 'BLOCK',
      reason: 'upstream-unresolved',
      layer: 'ip',
      host: 'typo.example.com',
      client: '10.1.0.4:1003'
    };
    const s = report({ hosts: summarizeFlows([unresolved, fronting('BLOCK'), notListed('BLOCK')]) }, ENFORCE);
    expect(s.blocked.map(r => r.reason)).toEqual(['`host-sni-mismatch`', '`sni-not-allowed`', '`upstream-unresolved`']);
  });

  it("a request the http-filter blocked: its method, never its path, and the filter's reason", () => {
    const s = report(
      {
        hosts: [],
        httpFilter: {
          blocks: [
            { host: 'uploads.example.com', method: 'PUT', reason: 'path-not-allowed', verdict: 'BLOCK', tries: 2 }
          ]
        }
      },
      ENFORCE
    );
    expect(s.blocked).toEqual([
      {
        reason: '`path-not-allowed`',
        layer: 'http-filter',
        tries: 2,
        what: '`uploads.example.com` `PUT` ‹path hidden›'
      }
    ]);
  });

  it('the platform endpoint count goes in the GitHub summary line', () => {
    expect(report({ hosts: [] }, ENFORCE).details).toEqual([]);
    expect(report({ hosts: [], platformEndpoints: 3 }, ENFORCE).details[0].summary).toBe(
      'GitHub, always allowed: 0 hosts · 0 requests · ↑ 0 B · ↓ 0 B · 3 platform endpoints'
    );
  });

  it('job log: one line per host', () => {
    expect(jobLog({ hosts: summarizeFlows([allowed]) })).toEqual([
      expect.stringMatching(/^ALLOW +registry\.npmjs\.org conns=0 reqs=1 tries=0 $/)
    ]);
  });
});
