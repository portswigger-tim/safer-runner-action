import type { ReportContext } from '../../report/section';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };

describe('DNS report (its Section)', () => {
  it('no refusal: nothing to show', () => {
    expect(report({ refused: [] }, ENFORCE).runnerSystem).toEqual([]);
  });

  it('lists only the names the proxy part has not already shown', () => {
    const [r] = report({ refused: ['shown.example.com', 'only-dns.example.com'] }, ENFORCE, [
      'shown.example.com'
    ]).runnerSystem;
    expect(r.summary).toBe('DNS 2 names refused');
    expect(r.body).toContain('`only-dns.example.com`');
    expect(r.body).not.toContain('shown.example.com');
  });

  it('says so when every name is shown above; analyze words it as would-refuse', () => {
    const [r] = report({ refused: ['a.example.com'] }, ANALYZE, ['a.example.com']).runnerSystem;
    expect(r.summary).toBe('DNS 1 name enforce would refuse');
    expect(r.body).toContain('is listed above with its blocked connection');
  });

  it('never decides a verdict', () => {
    const s = report({ refused: ['a.example.com'] }, ENFORCE);
    expect([s.score, s.alerts, s.suggestions]).toEqual([[], [], []]);
  });
});
