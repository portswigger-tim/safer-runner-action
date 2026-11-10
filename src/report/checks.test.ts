import { setupChecks } from './checks';

const OK = [{ name: 'repoint', ok: true, detail: 'x' }];

describe('setup checks', () => {
  it('all passed: one row each, no alert', () => {
    const c = setupChecks(OK, { status: 'verified', body: '' });
    expect(c.summary).toBe('self-tests 1/1 · tamper check: no change seen');
    expect(c.rows).toEqual([
      { ok: true, check: '`repoint`', detail: 'x' },
      { ok: true, check: 'tamper check', detail: 'no change seen' }
    ]);
    expect(c.alerts).toEqual([]);
  });

  it('a tamper check that could not run is unknown, never a pass', () => {
    const c = setupChecks(OK, undefined);
    expect(c.summary).toBe('self-tests 1/1 · tamper check: not run');
    expect(c.rows[1]).toEqual({ ok: false, check: 'tamper check', detail: 'not run' });
  });

  it('a tampered config and a failed self-test are each a CAUTION', () => {
    const c = setupChecks([{ name: 'repoint', ok: false, detail: 'x' }], { status: 'tampered', body: '' });
    expect(c.alerts.map(a => a.kind)).toEqual(['CAUTION', 'CAUTION']);
    expect(c.rows.map(r => r.ok)).toEqual([false, false]);
  });

  it('says when no self-test ran', () => {
    const c = setupChecks([], { status: 'verified', body: '' });
    expect(c.summary).toBe('self-tests not run · tamper check: no change seen');
    expect(c.rows[0]).toEqual({ ok: false, check: 'self-tests', detail: 'not run' });
  });
});
