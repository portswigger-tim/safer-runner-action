import * as core from '@actions/core';
import { JOB_CONTAINER_MESSAGE, applyDockerPolicy, inJobContainer } from './egress';

jest.mock('@actions/core');
jest.mock('@actions/exec');

describe('inJobContainer (F3)', () => {
  it('detects Docker and Podman container markers', () => {
    expect(inJobContainer(p => p === '/.dockerenv')).toBe(true);
    expect(inJobContainer(p => p === '/run/.containerenv')).toBe(true);
    expect(inJobContainer(() => false)).toBe(false);
  });

  it('tells the user what to do instead', () => {
    expect(JOB_CONTAINER_MESSAGE).toMatch(/services:/);
    expect(JOB_CONTAINER_MESSAGE).toMatch(/docker run/);
  });
});

describe('applyDockerPolicy (G4)', () => {
  const removed = { daemonActive: true, socketUnitActive: true, runnerInGroup: false, socketAccessible: false };
  const kept = { ...removed, runnerInGroup: true, socketAccessible: true };
  const stopped = { ...kept, daemonActive: false, socketUnitActive: false };
  const ops = (state: typeof removed, failures: string[] = []) => ({
    disableDockerForRunner: jest.fn(async () => failures),
    stopDockerService: jest.fn(async () => failures),
    readDockerState: jest.fn(async () => state)
  });

  beforeEach(() => jest.clearAllMocks());

  it('remove-group: records the verified state', async () => {
    const o = ops(removed);
    const r = await applyDockerPolicy({ mode: 'enforce', docker: 'remove-group' }, o);
    expect(o.disableDockerForRunner).toHaveBeenCalled();
    expect(o.stopDockerService).not.toHaveBeenCalled();
    expect(r).toEqual({ requested: 'remove-group', access: 'group-removed', state: removed });
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('stop: records the daemon as not running', async () => {
    const o = ops(stopped);
    const r = await applyDockerPolicy({ mode: 'enforce', docker: 'stop' }, o);
    expect(o.stopDockerService).toHaveBeenCalled();
    expect(r.access).toBe('not-running');
  });

  it.each(['remove-group', 'stop'] as const)('enforce: fails closed when %s did not take', async docker => {
    const o = ops(kept, ['sudo gpasswd -d runner docker exited 3']);
    await expect(applyDockerPolicy({ mode: 'enforce', docker }, o)).rejects.toThrow(
      new RegExp(`docker: ${docker} did not take effect.*gpasswd`)
    );
  });

  it('enforce: fails closed even when every command "succeeded" but access remains', async () => {
    await expect(applyDockerPolicy({ mode: 'enforce', docker: 'remove-group' }, ops(kept))).rejects.toThrow(
      /still use docker/
    );
  });

  it('analyze: a failed removal warns and never breaks the job', async () => {
    const r = await applyDockerPolicy({ mode: 'analyze', docker: 'remove-group' }, ops(kept, ['boom']));
    expect(r.access).toBe('retained');
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('did not take effect'));
  });

  it('a step failure with access verifiably gone is only a warning', async () => {
    const r = await applyDockerPolicy({ mode: 'enforce', docker: 'stop' }, ops(stopped, ['disable failed']));
    expect(r.access).toBe('not-running');
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('disable failed'));
  });

  it('enforce + keep is ADVISORY', async () => {
    const o = ops(kept);
    const r = await applyDockerPolicy({ mode: 'enforce', docker: 'keep' }, o);
    expect(o.disableDockerForRunner).not.toHaveBeenCalled();
    expect(r.access).toBe('retained');
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('ADVISORY'), {
      title: 'safer-runner: enforce (ADVISORY - docker retained)'
    });
  });

  it('analyze + keep says nothing', async () => {
    await applyDockerPolicy({ mode: 'analyze', docker: 'keep' }, ops(kept));
    expect(core.warning).not.toHaveBeenCalled();
  });
});
