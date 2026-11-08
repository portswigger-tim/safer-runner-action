/**
 * Tests for the docker service, on a simulated runner (group membership, socket, units) driven
 * through a recording Host.
 */

import * as core from '@actions/core';
import * as fs from 'fs';
import { DOCKER_DAEMON_JSON, DOCKER_EVENTS_LOG, DOCKER_EVENTS_UNIT } from '../../constants';
import type { SelfTestsRun } from '../../setup/selftest';
import { recordingHost } from '../../system/testing';
import type { TrustInstalled } from '../mitmproxy/trust';
import {
  DOCKER_GROUP,
  DOCKER_SOCKET,
  RUNNER_USERNAME,
  applyAccessPolicy,
  containerAddresses,
  disableDockerForRunner,
  dockerAccess,
  isRunnerInDockerGroup,
  mergeLiveRestore,
  parseContainerAddresses,
  planDocker,
  prepare,
  readDockerState,
  observeDocker,
  startEventRecorder,
  stopDockerService,
  type DockerPrepared
} from '.';

jest.mock('@actions/core');
jest.mock('fs', () => {
  const actual = jest.requireActual('fs');
  return { ...actual, existsSync: jest.fn(actual.existsSync), accessSync: jest.fn(actual.accessSync) };
});
const mockExists = fs.existsSync as unknown as jest.Mock;
const mockAccess = fs.accessSync as unknown as jest.Mock;
const actualFs = jest.requireActual('fs');

/** tokens for tests that call a step directly */
const TRUST = Object.freeze({}) as TrustInstalled;
const SELF_TESTS = Object.freeze({}) as SelfTestsRun;
/** the access changes, as only planDocker() makes them (enforce) */
const REMOVE_GROUP = planDocker('enforce', 'remove-group').apply!;
const STOP = planDocker('enforce', 'stop').apply!;

interface World {
  inGroup: boolean;
  daemon: boolean;
  socketUnit: boolean;
  socket: boolean;
  locked: boolean;
  /** commands that fail (exit 3) */
  failing?: RegExp;
  /** commands "succeed" but change nothing */
  sticky?: boolean;
  /** `id -nG runner` fails */
  idFails?: boolean;
  containers?: string[];
  daemonJson?: string;
}

const RUNNING: World = { inGroup: true, daemon: true, socketUnit: true, socket: true, locked: false };

/** A runner with docker in the state `w`; commands change it the way the real ones would. */
function runner(world: Partial<World> = {}) {
  const w: World = { ...RUNNING, ...world };
  const effect = (line: string): number => {
    if (w.failing?.test(line)) return 3;
    if (line === 'id -nG runner') return w.idFails ? 1 : 0;
    if (line === 'systemctl is-active --quiet docker' || line === 'systemctl is-active --quiet docker.service') {
      return w.daemon ? 0 : 3;
    }
    if (line === 'systemctl is-active --quiet docker.socket') return w.socketUnit ? 0 : 3;
    if (line === `sudo cat ${DOCKER_DAEMON_JSON}`) return w.daemonJson === undefined ? 1 : 0;
    if (w.sticky) return 0;
    if (line === `sudo gpasswd -d ${RUNNER_USERNAME} ${DOCKER_GROUP}`) w.inGroup = false;
    if (line === `sudo chmod 600 ${DOCKER_SOCKET}`) w.locked = true;
    if (line === 'sudo systemctl stop docker.service') w.daemon = false;
    if (line === 'sudo systemctl stop docker.socket') w.socketUnit = false;
    return 0;
  };
  const output = (line: string): string => {
    if (line === 'id -nG runner') return w.inGroup ? 'runner adm cdrom docker\n' : 'runner adm cdrom\n';
    if (line === 'sudo docker ps -q --no-trunc') return (w.containers ?? []).join('\n');
    if (line === `sudo cat ${DOCKER_DAEMON_JSON}`) return w.daemonJson ?? '';
    return '';
  };
  mockExists.mockImplementation((p: string) => (p === DOCKER_SOCKET ? w.socket : actualFs.existsSync(p)));
  mockAccess.mockImplementation((p: string, mode?: number) => {
    if (p !== DOCKER_SOCKET) return actualFs.accessSync(p, mode);
    if (!w.socket || w.locked) throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
  });
  return { w, ...recordingHost(effect, output) };
}

const sudoCalls = (calls: string[]) => calls.filter(c => c.startsWith('sudo ')).map(c => c.slice(5));

beforeEach(() => jest.clearAllMocks());

describe('docker access (docker input)', () => {
  describe('disableDockerForRunner (docker: remove-group)', () => {
    it('removes the runner from the group and locks the socket to root', async () => {
      const { host, calls } = runner();
      expect(await disableDockerForRunner(host, REMOVE_GROUP)).toEqual([]);
      expect(sudoCalls(calls)).toEqual([
        `gpasswd -d ${RUNNER_USERNAME} ${DOCKER_GROUP} [ignore-rc]`,
        `chown root:root ${DOCKER_SOCKET} [ignore-rc]`,
        `chmod 600 ${DOCKER_SOCKET} [ignore-rc]`
      ]);
      expect(DOCKER_SOCKET).toBe('/var/run/docker.sock');
    });

    it('is idempotent: skips the group change and a missing socket', async () => {
      const { host, calls } = runner({ inGroup: false, socket: false });
      expect(await disableDockerForRunner(host, REMOVE_GROUP)).toEqual([]);
      expect(sudoCalls(calls)).toEqual([]);
    });

    it('reports failed steps instead of swallowing them (G4)', async () => {
      const { host } = runner({ failing: /gpasswd/ });
      expect(await disableDockerForRunner(host, REMOVE_GROUP)).toEqual([`sudo gpasswd -d runner docker exited 3`]);
    });
  });

  describe('stopDockerService (docker: stop)', () => {
    it('stops, then disables, the socket and the service', async () => {
      const { host, calls } = runner();
      expect(await stopDockerService(host, STOP)).toEqual([]);
      expect(sudoCalls(calls)).toEqual([
        'systemctl stop docker.socket [ignore-rc]',
        'systemctl stop docker.service [ignore-rc]',
        'systemctl disable docker.socket [ignore-rc]',
        'systemctl disable docker.service [ignore-rc]'
      ]);
    });

    it('reports failed steps instead of swallowing them (G4)', async () => {
      const { host } = runner({ failing: /systemctl (stop|disable)/ });
      expect(await stopDockerService(host, STOP)).toHaveLength(4);
    });
  });

  describe('isRunnerInDockerGroup', () => {
    it('reads the group database for the runner user', async () => {
      const { host, calls } = runner();
      expect(await isRunnerInDockerGroup(host)).toBe(true);
      expect(calls).toEqual([`id -nG ${RUNNER_USERNAME} [ignore-rc] [silent]`]);
    });

    it('does not match a group that merely contains the word', async () => {
      const { host } = recordingHost(
        () => 0,
        () => 'runner dockerroot'
      );
      expect(await isRunnerInDockerGroup(host)).toBe(false);
    });

    it('fails closed when membership cannot be read', async () => {
      const { host } = runner({ idFails: true, inGroup: false });
      expect(await isRunnerInDockerGroup(host)).toBe(true);
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('assuming docker membership'));
    });
  });

  describe('readDockerState / dockerAccess (verified, not the input value)', () => {
    const base = { daemonActive: true, socketUnitActive: true, runnerInGroup: false, socketAccessible: false };

    it('classifies the observed state', () => {
      expect(dockerAccess(base)).toBe('group-removed');
      expect(dockerAccess({ ...base, runnerInGroup: true })).toBe('retained');
      expect(dockerAccess({ ...base, socketAccessible: true })).toBe('retained');
      expect(dockerAccess({ ...base, daemonActive: false, socketUnitActive: false, runnerInGroup: true })).toBe(
        'not-running'
      );
      // socket activation alone can start dockerd on the next connection
      expect(dockerAccess({ ...base, daemonActive: false, runnerInGroup: true })).toBe('retained');
    });

    it('checks the socket with this process credentials and the units with systemctl', async () => {
      const { host } = runner({ socketUnit: false, inGroup: false });
      expect(await readDockerState(host)).toEqual({
        daemonActive: true,
        socketUnitActive: false,
        runnerInGroup: false,
        socketAccessible: true
      });
      expect((await readDockerState(runner({ socket: false }).host)).socketAccessible).toBe(false);
    });
  });
});

describe('applyAccessPolicy (G4: verified by observation)', () => {
  const enforce = (docker: 'keep' | 'remove-group' | 'stop') => planDocker('enforce', docker);

  it('remove-group: records the verified state', async () => {
    const { host } = runner();
    const r = await applyAccessPolicy(host, 'enforce', enforce('remove-group'), SELF_TESTS);
    expect(r).toEqual({
      requested: 'remove-group',
      access: 'group-removed',
      state: { daemonActive: true, socketUnitActive: true, runnerInGroup: false, socketAccessible: false }
    });
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('stop: records the daemon as not running', async () => {
    const { host, calls } = runner();
    const r = await applyAccessPolicy(host, 'enforce', enforce('stop'), SELF_TESTS);
    expect(r.access).toBe('not-running');
    expect(calls.some(c => c.includes('gpasswd'))).toBe(false);
  });

  it.each(['remove-group', 'stop'] as const)('enforce: fails closed when %s did not take', async docker => {
    const { host } = runner({ failing: /gpasswd|chmod|chown|systemctl (stop|disable)/ });
    await expect(applyAccessPolicy(host, 'enforce', enforce(docker), SELF_TESTS)).rejects.toThrow(
      new RegExp(`docker: ${docker} did not take effect.*exited 3`)
    );
  });

  it('enforce: fails closed even when every command "succeeded" but access remains', async () => {
    const { host } = runner({ sticky: true });
    await expect(applyAccessPolicy(host, 'enforce', enforce('remove-group'), SELF_TESTS)).rejects.toThrow(
      /still use docker/
    );
  });

  it.each(['keep', 'remove-group', 'stop'] as const)(
    'analyze never changes docker access (docker: %s): it only reads the state',
    async docker => {
      const plan = planDocker('analyze', docker);
      expect(plan).toEqual({ policy: docker, applied: 'keep', apply: null });
      const { host, calls, w } = runner();
      const r = await applyAccessPolicy(host, 'analyze', plan, SELF_TESTS);
      expect(r).toMatchObject({ requested: docker, access: 'retained' });
      expect(sudoCalls(calls)).toEqual([]);
      expect(w).toMatchObject({ inGroup: true, daemon: true, socketUnit: true, locked: false });
      expect(core.warning).not.toHaveBeenCalled();
    }
  );

  it('a step failure with access verifiably gone is only a warning', async () => {
    const { host } = runner({ failing: /systemctl disable/ });
    const r = await applyAccessPolicy(host, 'enforce', enforce('stop'), SELF_TESTS);
    expect(r.access).toBe('not-running');
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('systemctl disable docker.socket exited 3'));
  });

  it('enforce + keep is ADVISORY', async () => {
    const { host, calls } = runner();
    const r = await applyAccessPolicy(host, 'enforce', enforce('keep'), SELF_TESTS);
    expect(calls.some(c => c.includes('gpasswd'))).toBe(false);
    expect(r.access).toBe('retained');
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('ADVISORY'), {
      title: 'safer-runner: enforce (ADVISORY - docker retained)'
    });
  });

  it('needs the self-tests first (a compile-time order check)', () => {
    const { host } = runner();
    // @ts-expect-error - changing docker access before the self-tests ran does not compile
    const early = () => applyAccessPolicy(host, 'enforce', enforce('stop'), {});
    expect(early).toBeInstanceOf(Function);
  });

  it('only planDocker() can make an access change (a compile-time check)', () => {
    const { host } = runner();
    // @ts-expect-error - a plain object is not an access change (analyze never makes one)
    const forged = () => stopDockerService(host, { removal: 'stop' });
    // @ts-expect-error - nor is an analyze plan's
    const fromAnalyze = () => disableDockerForRunner(host, planDocker('analyze', 'remove-group').apply);
    expect([forged, fromAnalyze]).toHaveLength(2);
  });
});

describe('prepare (F1: dockerd trusts the CA before the firewall)', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());
  const settle = async <T>(p: Promise<T>): Promise<T> => {
    const done = p.then(v => v);
    await jest.advanceTimersByTimeAsync(5_000);
    return done;
  };

  it('docker not running: nothing to restart, no container rules', async () => {
    const { host, calls } = runner({ daemon: false });
    expect(await settle(prepare(host, 'remove-group', TRUST))).toMatchObject({ active: false, configWritten: false });
    expect(calls).toEqual(['systemctl is-active --quiet docker [ignore-rc] [silent]']);
  });

  it('docker: stop: not even asked', async () => {
    const { host, calls } = runner();
    expect(await settle(prepare(host, 'stop', TRUST))).toMatchObject({ active: false, configWritten: false });
    expect(calls).toEqual([]);
  });

  it('running, nothing pulled yet (no keep, no service containers): no restart', async () => {
    const { host, calls } = runner();
    expect(await settle(prepare(host, 'remove-group', TRUST))).toMatchObject({ active: true, configWritten: false });
    expect(calls.some(c => c.includes('restart'))).toBe(false);
  });

  it('keep: live-restore merged, SIGHUP reload, restart, wait, containers compared', async () => {
    const { host, calls, stdin } = runner({ containers: ['c1'], daemonJson: '{"registry-mirrors":["m"]}' });
    expect(await settle(prepare(host, 'keep', TRUST))).toMatchObject({ active: true, configWritten: true });
    expect(calls).toEqual([
      'systemctl is-active --quiet docker [ignore-rc] [silent]',
      'sudo docker ps -q --no-trunc [ignore-rc] [silent]',
      'sudo docker ps -q --no-trunc [ignore-rc] [silent]',
      `sudo cat ${DOCKER_DAEMON_JSON} [ignore-rc] [silent]`,
      'sudo install -d -m 0755 /etc/docker',
      `sudo tee ${DOCKER_DAEMON_JSON} [silent]`,
      'sudo systemctl reload docker',
      'sudo systemctl restart docker',
      'sudo docker info --format {{.ServerVersion}} [ignore-rc] [silent]',
      'sudo docker ps -q --no-trunc [ignore-rc] [silent]'
    ]);
    expect(JSON.parse(stdin[`sudo tee ${DOCKER_DAEMON_JSON}`])).toEqual({
      'registry-mirrors': ['m'],
      'live-restore': true
    });
  });

  it('a daemon.json it cannot parse is left alone and dockerd is not restarted', async () => {
    const { host, calls } = runner({ daemonJson: '{ not json' });
    expect(await settle(prepare(host, 'keep', TRUST))).toMatchObject({ active: true, configWritten: false });
    expect(calls.some(c => c.includes('restart') || c.includes('tee'))).toBe(false);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('is not a JSON object'));
  });

  it('needs the CA trusted first (a compile-time order check)', () => {
    const { host } = runner();
    // @ts-expect-error - restarting dockerd before the CA is in the system store does not compile
    const early = () => prepare(host, 'keep', {});
    expect(early).toBeInstanceOf(Function);
  });
});

describe('startEventRecorder (analyze: the use of docker after setup)', () => {
  const PREPARED = Object.freeze({}) as DockerPrepared;
  beforeEach(() => jest.useFakeTimers({ now: new Date('2026-11-08T12:00:00Z') }));
  afterEach(() => jest.useRealTimers());

  it('starts the recorder (never restarted, no network) and notes the containers already running', async () => {
    const { host, calls } = recordingHost(
      () => 0,
      l => (l === 'sudo docker ps -q --no-trunc' ? 'c1\nc2\n' : '')
    );
    expect(await startEventRecorder(host, PREPARED)).toEqual({
      since: '2026-11-08T12:00:00.000Z',
      containers: ['c1', 'c2']
    });
    const run = calls.find(c => c.startsWith(`sudo systemd-run --unit=${DOCKER_EVENTS_UNIT} `))!;
    expect(run).toContain(' -p Restart=no ');
    expect(run).not.toContain('Restart=always');
    expect(run).toContain(' -p PrivateNetwork=yes ');
    expect(run).toContain(` -p StandardOutput=append:${DOCKER_EVENTS_LOG} `);
    expect(run).toMatch(/ \/usr\/bin\/docker -H unix:\/\/\/var\/run\/docker\.sock events --format \{\{json \.\}\}$/);
    expect(calls.indexOf(`sudo touch ${DOCKER_EVENTS_LOG}`)).toBeLessThan(calls.indexOf(run));
  });

  it('dockerd not running: records nothing, and never connects (socket activation would start it)', async () => {
    const { host, calls } = runner({ daemon: false });
    expect(await startEventRecorder(host, PREPARED)).toBeNull();
    expect(calls).toEqual(['systemctl is-active --quiet docker.service [ignore-rc] [silent]']);
  });

  it('a recorder that does not start is a warning, never a setup failure', async () => {
    const { host } = recordingHost(l => (l === `systemctl is-active --quiet ${DOCKER_EVENTS_UNIT}` ? 3 : 0));
    const done = startEventRecorder(host, PREPARED);
    await jest.advanceTimersByTimeAsync(6_000);
    expect(await done).toBeNull();
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('docker events: not recorded'));
  });

  it('needs dockerd settled first (a compile-time order check)', () => {
    const { host } = runner();
    // @ts-expect-error - recording before dockerd restarted for the CA does not compile
    const early = () => startEventRecorder(host, {});
    expect(early).toBeInstanceOf(Function);
  });
});

describe('observeDocker (analyze, post step)', () => {
  const at = '2026-11-08T12:00:00.000Z';

  it('no recording, dockerd running: asks it for what it still holds since setup (partial)', async () => {
    const { host, calls } = recordingHost(
      () => 0,
      l =>
        l.startsWith('docker events ')
          ? JSON.stringify({ Type: 'image', Action: 'pull', Actor: { ID: 'alpine:3.20', Attributes: {} } }) + '\n'
          : ''
    );
    expect(await observeDocker(host, undefined, at, 'retained')).toEqual({
      uses: { image: 1 },
      images: ['alpine:3.20'],
      services: 0,
      partial: true
    });
    expect(calls).toContainEqual(
      expect.stringMatching(/^docker events --since 1794139200 --until \d+ --format \{\{json \.\}\}/)
    );
  });

  it('no recording, dockerd stopped: never asks (that would start it through socket activation)', async () => {
    const { host, calls } = runner({ daemon: false });
    expect(await observeDocker(host, undefined, at, 'retained')).toMatchObject({ uses: {}, partial: true });
    expect(calls.some(c => c.startsWith('docker '))).toBe(false);
  });

  it('docker not running at setup or now: nothing to miss, so not partial', async () => {
    const { host } = runner({ daemon: false, socketUnit: false });
    expect(await observeDocker(host, undefined, at, 'not-running')).toEqual({
      uses: {},
      images: [],
      services: 0,
      partial: false
    });
  });
});

describe('containerAddresses', () => {
  it('shows addresses only when the runner has lost docker access', async () => {
    const { host } = recordingHost(l => (l.startsWith('docker ') ? 1 : 0));
    expect(await containerAddresses(host)).toEqual(new Map());
  });
});

describe('mergeLiveRestore (F1)', () => {
  it('creates a config when there is none', () => {
    expect(mergeLiveRestore('')).toEqual({ json: '{\n  "live-restore": true\n}\n', changed: true });
  });

  it('keeps existing keys', () => {
    const r = mergeLiveRestore('{"registry-mirrors":["https://mirror.gcr.io"],"live-restore":false}');
    expect(r?.changed).toBe(true);
    expect(JSON.parse(r!.json)).toEqual({ 'registry-mirrors': ['https://mirror.gcr.io'], 'live-restore': true });
  });

  it('leaves an already live-restore config untouched', () => {
    const body = '{ "live-restore": true }\n';
    expect(mergeLiveRestore(body)).toEqual({ json: body, changed: false });
  });

  it('refuses to rewrite a config it cannot parse', () => {
    expect(mergeLiveRestore('{ not json')).toBeNull();
    expect(mergeLiveRestore('[]')).toBeNull();
    expect(mergeLiveRestore('null')).toBeNull();
  });
});

describe('parseContainerAddresses', () => {
  it('maps every network address of a container to its name', () => {
    const m = parseContainerAddresses('/svc_redis 172.18.0.2\n/builder 172.17.0.3 172.19.0.4\n/stopped \n\n');
    expect(Array.from(m.entries())).toEqual([
      ['172.18.0.2', 'svc_redis'],
      ['172.17.0.3', 'builder'],
      ['172.19.0.4', 'builder']
    ]);
  });
});
