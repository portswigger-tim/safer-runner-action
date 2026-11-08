import { setupChecks } from './checks';

const OK = [{ name: 'repoint', ok: true, detail: 'x' }];

describe('setup checks', () => {
  it('all passed: an allowed row', () => {
    const c = setupChecks(OK, { status: 'verified', body: '' });
    expect(c.score).toEqual({
      verdict: 'allowed',
      area: 'Setup',
      text: 'self-tests 1/1 · no config change seen (advisory)'
    });
    expect(c.alerts).toEqual([]);
  });

  it('a tamper check that could not run is unknown, never a pass', () => {
    expect(setupChecks(OK, undefined).score).toMatchObject({
      verdict: 'advisory',
      text: 'self-tests 1/1 · config not verified'
    });
  });

  it('a tampered config and a failed self-test are each a CAUTION', () => {
    const c = setupChecks([{ name: 'repoint', ok: false, detail: 'x' }], { status: 'tampered', body: '' });
    expect(c.alerts.map(a => a.kind)).toEqual(['CAUTION', 'CAUTION']);
    expect(c.score.verdict).toBe('advisory');
  });

  it('says when no self-test ran', () => {
    expect(setupChecks([], { status: 'verified', body: '' }).score.text).toBe(
      'self-tests not run · no config change seen (advisory)'
    );
  });
});
