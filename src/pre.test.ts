import * as core from '@actions/core';
import { runSetup } from './setup/run';

jest.mock('@actions/core');
jest.mock('./setup/run', () => ({ runSetup: jest.fn() }));

/** Load pre.ts (it runs on import) with these inputs and wait for it to finish. */
async function runPre(values: Record<string, string>): Promise<void> {
  (core.getInput as jest.Mock).mockImplementation((name: string) => values[name] ?? '');
  jest.isolateModules(() => {
    require('./pre');
  });
  await new Promise(r => setImmediate(r));
}

describe('pre step', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (runSetup as jest.Mock).mockResolvedValue(undefined);
  });

  it('runs setup', async () => {
    await runPre({ mode: 'enforce', 'http-filter': 'github.com: { "*": GET }' });
    expect(runSetup).toHaveBeenCalledTimes(1);
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it('fails closed in enforce when another input is invalid', async () => {
    await runPre({ mode: 'enforce', 'http-filter': 'github.com: { "*": [' });
    expect(runSetup).not.toHaveBeenCalled();
    expect(core.setFailed).toHaveBeenCalledWith(expect.stringContaining('enforce mode'));
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('fails closed in enforce when setup throws', async () => {
    (runSetup as jest.Mock).mockRejectedValue(new Error('boom'));
    await runPre({ mode: 'enforce' });
    expect(core.setFailed).toHaveBeenCalledWith(expect.stringContaining('boom'));
  });

  it('leaves analyze to the main step', async () => {
    await runPre({ mode: 'analyze', 'http-filter': 'github.com: { "*": [' });
    expect(core.setFailed).not.toHaveBeenCalled();
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('main step will retry'));
  });

  it('fails on an invalid mode rather than guessing', async () => {
    await runPre({ mode: 'enforcee' });
    expect(runSetup).not.toHaveBeenCalled();
    expect(core.setFailed).toHaveBeenCalledWith(expect.stringContaining('mode must be'));
  });
});
