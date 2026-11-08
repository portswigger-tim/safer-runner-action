import { integrityCheck, selfTestCheck } from './checks';

describe('setup checks', () => {
  it('a tamper check that could not run is unknown, never a pass', () => {
    expect(integrityCheck(undefined)).toEqual({ chip: '❔ config unverified', alerts: [] });
    expect(integrityCheck({ status: 'unavailable', body: '' }).diagnostic?.summary).toBe('config: no baseline');
  });

  it('a tampered config is a CAUTION', () => {
    expect(integrityCheck({ status: 'tampered', body: '' }).alerts.map(a => a.kind)).toEqual(['CAUTION']);
  });

  it('a failed self-test is a CAUTION; none run is said so', () => {
    const s = selfTestCheck([{ name: 'repoint', ok: false, detail: 'x' }]);
    expect(s.chip).toBe('❌ self-tests 0/1');
    expect(s.alerts.map(a => a.kind)).toEqual(['CAUTION']);
    expect(selfTestCheck([]).diagnostic?.summary).toBe('self-tests not run');
  });
});
