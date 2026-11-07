/**
 * Tests for the docker service
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  disableDockerForRunner,
  dockerAccess,
  stopDockerService,
  isRunnerInDockerGroup,
  readDockerState,
  RUNNER_USERNAME,
  DOCKER_GROUP,
  DOCKER_SOCKET,
  mergeLiveRestore,
  parseContainerAddresses
} from '.';

jest.mock('@actions/core');
jest.mock('@actions/exec');

const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
const mockGetExecOutput = exec.getExecOutput as jest.MockedFunction<typeof exec.getExecOutput>;

function groups(out: string, exitCode = 0): void {
  mockGetExecOutput.mockResolvedValue({ stdout: out, stderr: '', exitCode });
}

function sudoCalls(): string[] {
  return mockExec.mock.calls.filter(c => c[0] === 'sudo').map(c => (c[1] as string[]).join(' '));
}

describe('docker access (docker input)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('disableDockerForRunner (docker: remove-group)', () => {
    it('removes the runner from the group and locks the socket to root', async () => {
      groups('runner adm docker');
      mockExec.mockResolvedValue(0);

      expect(await disableDockerForRunner(__filename)).toEqual([]);
      expect(sudoCalls()).toEqual([
        `gpasswd -d ${RUNNER_USERNAME} ${DOCKER_GROUP}`,
        `chown root:root ${__filename}`,
        `chmod 600 ${__filename}`
      ]);
      expect(DOCKER_SOCKET).toBe('/var/run/docker.sock');
    });

    it('is idempotent: skips the group change and a missing socket', async () => {
      groups('runner adm');

      expect(await disableDockerForRunner('/nonexistent/docker.sock')).toEqual([]);
      expect(sudoCalls()).toEqual([]);
    });

    it('reports failed steps instead of swallowing them (G4)', async () => {
      groups('runner docker');
      mockExec.mockImplementation(async (_cmd, args) => ((args as string[])[0] === 'gpasswd' ? 3 : 0));

      expect(await disableDockerForRunner(__filename)).toEqual([`sudo gpasswd -d runner docker exited 3`]);
    });
  });

  describe('stopDockerService (docker: stop)', () => {
    it('stops, then disables, the socket and the service', async () => {
      mockExec.mockResolvedValue(0);
      expect(await stopDockerService()).toEqual([]);
      expect(sudoCalls()).toEqual([
        'systemctl stop docker.socket',
        'systemctl stop docker.service',
        'systemctl disable docker.socket',
        'systemctl disable docker.service'
      ]);
    });

    it('reports failed steps instead of swallowing them (G4)', async () => {
      mockExec.mockResolvedValue(1);
      expect(await stopDockerService()).toHaveLength(4);
    });
  });

  describe('isRunnerInDockerGroup', () => {
    it('reads the group database for the runner user', async () => {
      groups('runner adm cdrom sudo dip plugdev lxd docker\n');
      expect(await isRunnerInDockerGroup()).toBe(true);
      expect(mockGetExecOutput).toHaveBeenCalledWith('id', ['-nG', RUNNER_USERNAME], expect.any(Object));
    });

    it('does not match a group that merely contains the word', async () => {
      groups('runner dockerroot');
      expect(await isRunnerInDockerGroup()).toBe(false);
    });

    it('fails closed when membership cannot be read', async () => {
      groups('', 1);
      expect(await isRunnerInDockerGroup()).toBe(true);
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
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safer-runner-docker-'));
      const sock = path.join(dir, 'docker.sock');
      fs.writeFileSync(sock, '');
      groups('runner');
      mockExec.mockImplementation(async (_cmd, args) => ((args as string[]).includes('docker.service') ? 0 : 3));
      try {
        expect(await readDockerState(sock)).toEqual({
          daemonActive: true,
          socketUnitActive: false,
          runnerInGroup: false,
          socketAccessible: true
        });
        expect((await readDockerState(path.join(dir, 'missing.sock'))).socketAccessible).toBe(false);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
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
