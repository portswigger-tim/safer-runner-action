import { jest } from '@jest/globals';
import { automock } from '../testing/automock.js';

const realCore = await import('@actions/core');
const realExec = await import('@actions/exec');
jest.unstable_mockModule('@actions/core', () => automock(realCore));
jest.unstable_mockModule('@actions/exec', () => automock(realExec));
const { JOB_CONTAINER_MESSAGE, inJobContainer } = await import('./run.js');

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
