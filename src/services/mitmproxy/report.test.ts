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
  it('allowed traffic only: one allowed row, no alert, no suggestion', () => {
    const s = report({ hosts: summarizeFlows([allowed]) }, ENFORCE);
    expect(s.score).toEqual([{ verdict: 'allowed', area: 'Network', text: '1 host · 1 request · 2.0 KiB' }]);
    expect([s.alerts, s.suggestions, s.deniedNames]).toEqual([[], [], []]);
  });

  it('counts the hosts beyond GitHub when the job has its own allowlist', () => {
    const s = report({ hosts: summarizeFlows([allowed]), userDomains: ['registry.npmjs.org'] }, ENFORCE);
    expect(s.score[0].text).toBe('1 host beyond GitHub · 1 request · 2.0 KiB');
  });

  it('enforce: a host not on the allowlist is a blocked row, an IMPORTANT alert, and no suggestion', () => {
    const s = report({ hosts: summarizeFlows([allowed, notListed('BLOCK')]) }, ENFORCE);
    expect(s.score.map(r => r.verdict)).toEqual(['blocked', 'allowed']);
    expect(s.alerts.map(a => a.kind)).toEqual(['IMPORTANT']);
    expect(s.suggestions).toEqual([]);
    expect(s.deniedNames).toEqual(['pypi.example.com']);
    // the likely reason the job failed, in the detail
    expect(s.body).toContain('allowed-domains: |\n  pypi.example.com');
  });

  it('analyze: suggests the whole allowed-domains value, the job’s own entries kept', () => {
    const s = report(
      {
        hosts: summarizeFlows([allowed, notListed('WOULD_BLOCK')]),
        allowedDomains: parseAllowedDomains('registry.npmjs.org, not a pattern')
      },
      ANALYZE
    );
    expect(s.score[0].verdict).toBe('would-block');
    expect(s.suggestions).toEqual([{ input: 'allowed-domains', value: 'registry.npmjs.org\npypi.example.com\n' }]);
  });

  it('never suggests a name that looks like data', () => {
    const s = report({ hosts: summarizeFlows([notListed('WOULD_BLOCK', '5ec7e7c0ffee1234.example.com')]) }, ANALYZE);
    expect(s.suggestions).toEqual([]);
    expect(s.notes[0]).toMatch(/^1 blocked name not suggested/);
  });

  it('a bypass attempt is a CAUTION in either mode, and stops the "not on the allowlist" alert', () => {
    for (const [ctx, v] of [
      [ENFORCE, 'BLOCK'],
      [ANALYZE, 'WOULD_BLOCK']
    ] as const) {
      const s = report({ hosts: summarizeFlows([fronting(v), notListed(v)]) }, ctx);
      expect(s.alerts.map(a => a.kind)).toEqual(['CAUTION']);
    }
  });

  it('the platform allowlist count goes under Runner System only when it allowed anything', () => {
    expect(report({ hosts: [] }, ENFORCE).runnerSystem).toEqual([]);
    const [r] = report({ hosts: [], platformEndpoints: 3 }, ENFORCE).runnerSystem;
    expect(r.summary).toBe('3 platform endpoints auto-allowed');
  });

  it('job log: one line per host', () => {
    expect(jobLog({ hosts: summarizeFlows([allowed]) })).toEqual([
      expect.stringMatching(/^ALLOW +registry\.npmjs\.org conns=0 reqs=1 tries=0 $/)
    ]);
  });
});
