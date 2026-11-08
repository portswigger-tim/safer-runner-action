/** The docker policy evaluation (analyze): pure, no runner. */

import type { DockerPolicy } from '../../config/inputs';
import { parseDockerEvents } from '../../report/logs/docker-events';
import { classifyDockerEvents, evaluateDocker, healthcheckCommands, planDocker, type DockerObserved } from './config';

/** one line as `docker events --format '{{json .}}'` writes it */
const ev = (Type: string, Action: string, ID: string, Attributes: Record<string, string> = {}) =>
  JSON.stringify({ status: Action, id: ID, Type, Action, Actor: { ID, Attributes }, scope: 'local', time: 1 });

describe('planDocker', () => {
  it('enforce applies a removal; keep and analyze change nothing', () => {
    expect(planDocker('enforce', 'remove-group')).toEqual({
      policy: 'remove-group',
      applied: 'remove-group',
      apply: { removal: 'remove-group' }
    });
    expect(planDocker('enforce', 'stop').apply).toEqual({ removal: 'stop' });
    expect(planDocker('enforce', 'keep')).toEqual({ policy: 'keep', applied: 'keep', apply: { removal: null } });
    for (const p of ['keep', 'remove-group', 'stop'] as const) {
      expect(planDocker('analyze', p)).toEqual({ policy: p, applied: 'keep', apply: { removal: null } });
    }
  });
});

describe('healthcheckCommands (as dockerd names them in its exec events)', () => {
  it('CMD-SHELL runs in the shell (the container shell, else /bin/sh -c); CMD as is; NONE nothing', () => {
    expect(healthcheckCommands(['CMD-SHELL', 'pg_isready -U postgres'], null)).toEqual([
      '/bin/sh -c pg_isready -U postgres'
    ]);
    expect(healthcheckCommands(['CMD-SHELL', 'x'], ['/bin/bash', '-lc'])).toEqual(['/bin/bash -lc x']);
    expect(healthcheckCommands(['CMD', 'redis-cli', 'ping'], null)).toEqual(['redis-cli ping']);
    expect(healthcheckCommands(['CMD', 'healthy'], null)).toEqual(['healthy']);
    expect(healthcheckCommands(['NONE'], null)).toEqual([]);
    expect(healthcheckCommands(undefined, null)).toEqual([]);
    expect(healthcheckCommands([1, 2], null)).toEqual([]);
  });
});

describe('parseDockerEvents', () => {
  it('keeps the type, action, exec command (separately), id and image; skips what is not an event', () => {
    const text = [
      ev('container', 'exec_create: /bin/sh -c pg_isready', 'c1', { image: 'postgres:16', name: 'svc' }),
      'not json',
      '{"Type": "container"}',
      ev('image', 'pull', 'alpine:3.20', { name: 'alpine' }),
      ev('image', 'tag', 'sha256:abc', { name: 'app:1' }),
      ev('network', 'connect', 'n1', { container: 'c1' }),
      ''
    ].join('\n');
    expect(parseDockerEvents(text)).toEqual([
      { type: 'container', action: 'exec_create', command: '/bin/sh -c pg_isready', id: 'c1', image: 'postgres:16' },
      { type: 'image', action: 'pull', id: 'alpine:3.20', image: 'alpine:3.20' },
      { type: 'image', action: 'tag', id: 'sha256:abc', image: 'app:1' },
      { type: 'network', action: 'connect', id: 'n1' }
    ]);
  });
});

describe('classifyDockerEvents', () => {
  const events = (lines: string[]) => parseDockerEvents(lines.join('\n'));
  const HEALTH = new Map([['svc', ['/bin/sh -c pg_isready']]]);

  it("dockerd's own events are not a use: exits, healthchecks, health status, its reload", () => {
    const e = events([
      ev('container', 'exec_create: /bin/sh -c pg_isready', 'svc'),
      ev('container', 'exec_start: /bin/sh -c pg_isready ', 'svc'),
      ev('container', 'exec_die', 'svc', { exitCode: '0' }),
      ev('container', 'health_status: healthy', 'svc'),
      ev('container', 'die', 'svc'),
      ev('container', 'oom', 'svc'),
      ev('daemon', 'reload', 'd1')
    ]);
    expect(classifyDockerEvents(e, HEALTH)).toEqual({ uses: {}, images: [] });
  });

  it("a step's docker exec into a service container is a use, even into one with a healthcheck", () => {
    const e = events([ev('container', 'exec_create: psql -c select 1', 'svc', { image: 'postgres:16' })]);
    expect(classifyDockerEvents(e, HEALTH)).toEqual({ uses: { exec: 1 }, images: ['postgres:16'] });
    // without the container's healthcheck (it could not be read), its exec counts too
    expect(classifyDockerEvents(events([ev('container', 'exec_create: /bin/sh -c pg_isready', 'svc')]))).toEqual({
      uses: { exec: 1 },
      images: []
    });
  });

  it('counts each kind of use, and the images', () => {
    const e = events([
      ev('image', 'pull', 'alpine:3.20'),
      ev('container', 'create', 'r1', { image: 'alpine:3.20' }),
      ev('container', 'start', 'r1', { image: 'alpine:3.20' }),
      ev('container', 'destroy', 'r1', { image: 'alpine:3.20' }),
      ev('builder', 'prune', 'b1'),
      ev('network', 'create', 'n1'),
      ev('volume', 'create', 'v1'),
      ev('plugin', 'install', 'p1')
    ]);
    expect(classifyDockerEvents(e)).toEqual({
      uses: { image: 1, container: 3, build: 1, network: 1, volume: 1, other: 1 },
      images: ['alpine:3.20']
    });
  });
});

describe('evaluateDocker: what the policy would break, and the setting to suggest', () => {
  const observed = (o: Partial<DockerObserved>): DockerObserved => ({
    uses: {},
    images: [],
    services: 0,
    partial: false,
    ...o
  });
  const USED = observed({ uses: { container: 2, image: 1 } });
  const SERVICES = observed({ services: 1 });
  const NOTHING = observed({});

  it.each<[string, DockerPolicy, DockerObserved, object]>([
    // the job used docker: anything but keep breaks it; keep is the only setting that fits
    [
      'used, remove-group',
      'remove-group',
      USED,
      {
        wouldBlock: { container: 2, image: 1 },
        wouldStop: 0,
        fits: 'keep',
        value: 'keep',
        advisory: true,
        change: true
      }
    ],
    [
      'used, stop (with services)',
      'stop',
      observed({ ...USED, services: 1 }),
      {
        wouldBlock: { container: 2, image: 1 },
        wouldStop: 1,
        fits: 'keep',
        value: 'keep',
        advisory: true,
        change: true
      }
    ],
    [
      'used, keep',
      'keep',
      USED,
      { wouldBlock: {}, wouldStop: 0, fits: 'keep', value: 'keep', advisory: true, change: false }
    ],
    // only service containers: remove-group keeps them running; stop would stop them
    [
      'services, remove-group',
      'remove-group',
      SERVICES,
      { wouldBlock: {}, wouldStop: 0, fits: 'remove-group', value: 'remove-group', advisory: false, change: false }
    ],
    [
      'services, stop',
      'stop',
      SERVICES,
      { wouldBlock: {}, wouldStop: 1, fits: 'remove-group', value: 'remove-group', advisory: false, change: true }
    ],
    [
      'services, keep',
      'keep',
      SERVICES,
      { wouldBlock: {}, wouldStop: 0, fits: 'remove-group', value: 'remove-group', advisory: false, change: true }
    ],
    // no docker at all: stop fits, but is never suggested over the policy
    [
      'nothing, remove-group',
      'remove-group',
      NOTHING,
      { wouldBlock: {}, wouldStop: 0, fits: 'stop', value: 'remove-group', advisory: false, change: false }
    ],
    [
      'nothing, stop',
      'stop',
      NOTHING,
      { wouldBlock: {}, wouldStop: 0, fits: 'stop', value: 'stop', advisory: false, change: false }
    ],
    [
      'nothing, keep',
      'keep',
      NOTHING,
      { wouldBlock: {}, wouldStop: 0, fits: 'stop', value: 'remove-group', advisory: false, change: true }
    ]
  ])('%s', (_name, policy, o, want) => {
    const e = evaluateDocker(policy, o);
    expect({ ...e, ...e.suggestion, suggestion: undefined, input: undefined }).toEqual({
      ...want,
      suggestion: undefined,
      input: undefined
    });
    expect(e.suggestion.input).toBe('docker');
  });

  it('suggests keep only with the advisory flag, and never stop', () => {
    for (const policy of ['keep', 'remove-group', 'stop'] as const) {
      for (const o of [USED, SERVICES, NOTHING]) {
        const s = evaluateDocker(policy, o).suggestion;
        expect(s.advisory).toBe(s.value === 'keep');
        if (s.change) expect(s.value).not.toBe('stop');
      }
    }
  });
});
