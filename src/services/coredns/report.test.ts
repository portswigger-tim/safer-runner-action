import type { ReportContext } from '../../report/section';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };

describe('DNS report (its Section)', () => {
  it('no refusal: no diagnostic', () => {
    expect(report({ refused: [] }, ENFORCE).diagnostics).toEqual([]);
  });

  it('lists only the names the proxy part has not already shown', () => {
    const [d] = report({ refused: ['shown.example.com', 'only-dns.example.com'] }, ENFORCE, [
      'shown.example.com'
    ]).diagnostics;
    expect(d.summary).toBe('2 DNS refusals');
    expect(d.body).toContain('`only-dns.example.com`');
    expect(d.body).not.toContain('shown.example.com');
  });

  it('says so when every name is shown above; analyze words it as would-refuse', () => {
    const [d] = report({ refused: ['a.example.com'] }, ANALYZE, ['a.example.com']).diagnostics;
    expect(d.summary).toBe('1 DNS lookup enforce would refuse');
    expect(d.body).toContain('all of them are listed with their blocked connection above');
  });

  it('never decides a verdict or adds a chip', () => {
    const s = report({ refused: ['a.example.com'] }, ENFORCE);
    expect([s.blocking, s.chips, s.alerts, s.score]).toEqual([false, [], [], []]);
  });
});
