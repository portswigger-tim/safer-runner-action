import { isActionDisabled } from './mode';

describe('mode.ts - isActionDisabled', () => {
  const originalMode = process.env['INPUT_MODE'];

  afterEach(() => {
    if (originalMode === undefined) {
      delete process.env['INPUT_MODE'];
    } else {
      process.env['INPUT_MODE'] = originalMode;
    }
  });

  it('returns true when mode is explicitly empty', () => {
    process.env['INPUT_MODE'] = '';
    expect(isActionDisabled()).toBe(true);
  });

  it('returns true when mode is whitespace only', () => {
    process.env['INPUT_MODE'] = '   ';
    expect(isActionDisabled()).toBe(true);
  });

  it('returns false when mode is unset (never silently disable)', () => {
    delete process.env['INPUT_MODE'];
    expect(isActionDisabled()).toBe(false);
  });

  it('returns false for analyze mode', () => {
    process.env['INPUT_MODE'] = 'analyze';
    expect(isActionDisabled()).toBe(false);
  });

  it('returns false for enforce mode', () => {
    process.env['INPUT_MODE'] = 'enforce';
    expect(isActionDisabled()).toBe(false);
  });

  it('returns false for unrecognised values (disabling is only ever explicit-empty)', () => {
    process.env['INPUT_MODE'] = 'observe';
    expect(isActionDisabled()).toBe(false);
  });
});
