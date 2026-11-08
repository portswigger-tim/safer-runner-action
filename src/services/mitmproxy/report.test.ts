import type { FlowRecord } from '../../flowlog';
import type { ReportContext } from '../../report/section';
import { summarizeFlows } from './flows';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false, actionRef: 'v9.9.9' };

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
const notListed = (verdict: 'BLOCK' | 'WOULD_BLOCK'): FlowRecord => ({
  ts: 2,
  ev: 'tls',
  verdict,
  reason: 'sni-not-allowed',
  layer: 'sni',
  sni: 'pypi.example.com',
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
  it('allowed traffic only: nothing blocking, no alert, the allowed line', () => {
    const s = report({ hosts: summarizeFlows([allowed]), dnsRefused: [] }, ENFORCE);
    expect(s.blocking).toBe(false);
    expect(s.alerts).toEqual([]);
    expect(s.chips).toEqual([]);
    expect(s.allowedLine).toBe('1 host · 1 request · 2.0 KiB');
    expect(s.deniedNames).toEqual([]);
    expect(s.jobLog).toEqual([expect.stringMatching(/^ALLOW +registry\.npmjs\.org conns=0 reqs=1 tries=0 $/)]);
  });

  it('enforce: a host not on the allowlist is blocking, with an IMPORTANT alert and no chip', () => {
    const s = report({ hosts: summarizeFlows([allowed, notListed('BLOCK')]), dnsRefused: [] }, ENFORCE);
    expect(s.blocking).toBe(true);
    expect(s.chips).toEqual([]);
    expect(s.alerts.map(a => a.kind)).toEqual(['IMPORTANT']);
    expect(s.deniedNames).toEqual(['pypi.example.com']);
    expect(s.score.map(r => r[0])).toEqual(['🚫 **Not on allowlist**', '✅ **Allowed**']);
  });

  it('analyze: a would-be-blocked host is a chip and a quoted suggestion pinned to the ref', () => {
    const s = report({ hosts: summarizeFlows([allowed, notListed('WOULD_BLOCK')]), dnsRefused: [] }, ANALYZE);
    expect(s.chips).toEqual(['1 host would be blocked']);
    const [alert] = s.alerts;
    expect(alert).toMatchObject({ kind: 'IMPORTANT', quoted: true });
    expect(alert.text).toContain('safer-runner-action@v9.9.9');
    expect(alert.text).toContain('      pypi.example.com');
  });

  it('a bypass attempt is a CAUTION in either mode, and stops the "not on the allowlist" alert', () => {
    for (const [ctx, v] of [
      [ENFORCE, 'BLOCK'],
      [ANALYZE, 'WOULD_BLOCK']
    ] as const) {
      const s = report({ hosts: summarizeFlows([fronting(v), notListed(v)]), dnsRefused: [] }, ctx);
      expect(s.alerts[0].kind).toBe('CAUTION');
      expect(s.alerts.filter(a => a.kind === 'IMPORTANT' && !a.quoted)).toEqual([]);
    }
  });

  it('the platform allowlist count is a diagnostic only when it allowed anything', () => {
    expect(report({ hosts: [], dnsRefused: [] }, ENFORCE).diagnostics).toEqual([]);
    const [d] = report({ hosts: [], dnsRefused: [], platformEndpoints: 3 }, ENFORCE).diagnostics;
    expect(d.summary).toBe('3 platform endpoints auto-allowed');
  });
});
