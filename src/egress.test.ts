import { JOB_CONTAINER_MESSAGE, inJobContainer } from './egress';

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
