import { resolveDisableSudo } from './inputs';

describe('resolveDisableSudo (review H2: enforce removes sudo by default)', () => {
  it('defaults ON in enforce mode when disable-sudo is unset', () => {
    expect(resolveDisableSudo('', 'enforce', '')).toEqual([true, true]);
    expect(resolveDisableSudo('  ', 'enforce', '')).toEqual([true, true]);
  });

  it('defaults off in analyze mode', () => {
    expect(resolveDisableSudo('', 'analyze', '')).toEqual([false, true]);
  });

  it('keeps sudo when sudo-config supplies an explicit sudo policy', () => {
    expect(resolveDisableSudo('', 'enforce', 'runner ALL=(root) NOPASSWD: /usr/bin/apt-get')).toEqual([false, true]);
  });

  it('honours an explicit false in enforce (the advisory opt-out) - unset and false differ', () => {
    expect(resolveDisableSudo('false', 'enforce', '')).toEqual([false, false]);
    expect(resolveDisableSudo('FALSE', 'enforce', '')).toEqual([false, false]);
  });

  it('honours an explicit true in any mode, including over sudo-config', () => {
    expect(resolveDisableSudo('true', 'analyze', '')).toEqual([true, false]);
    expect(resolveDisableSudo('True', 'enforce', 'runner ALL=(ALL) NOPASSWD: ALL')).toEqual([true, false]);
  });

  it('rejects anything that is not a YAML boolean', () => {
    expect(() => resolveDisableSudo('yes', 'enforce', '')).toThrow(/disable-sudo must be true or false/);
    expect(() => resolveDisableSudo('0', 'enforce', '')).toThrow();
  });
});
