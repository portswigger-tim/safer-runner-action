import type { ReportContext } from '../../report/section';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };

describe('DNS report (its Section)', () => {
  it('no blocked name: no row', () => {
    expect(report({ refused: [] }, ENFORCE).blocked).toEqual([]);
  });

  it('lists only the names the proxy part has not already shown, with the label dns.log writes', () => {
    const s = report({ refused: ['shown.example.com', 'only-dns.example.com'] }, ENFORCE, ['Shown.example.com']);
    expect(s.blocked).toEqual([{ reason: '`BLOCK`', layer: 'dns', what: '`only-dns.example.com`' }]);
  });

  it('analyze: WOULD_BLOCK, as the analyze resolver labels it', () => {
    expect(report({ refused: ['a.example.com'] }, ANALYZE).blocked[0].reason).toBe('`WOULD_BLOCK`');
  });

  it('a name that looks like data is redacted', () => {
    expect(report({ refused: ['5ec7e7c0ffee1234.example.com'] }, ENFORCE).blocked[0].what).toContain('‹redacted›');
  });
});
