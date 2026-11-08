import * as fs from 'fs';
import { FLOW_LOG, MITMDUMP_BIN, POLICY_FILE, PROXY_CA_KEY_FILE, PROXY_CONF_DIR, PROXY_UNIT } from '../../constants';
import type { PolicyConfig } from '../../policy';
import { recordingHost } from '../../system/testing';
import { transientUnitArgs } from '../../system/unit';
import { PROXY_PORT_BAND, allocateProxyPorts, ensureUser, mitmdumpArgs, render, start, writeConfig } from '.';
import { generateCa, type CaReady } from './ca';
import type { ProxyConfigWritten } from '.';

jest.mock('@actions/core');
jest.mock('fs', () => {
  const actual = jest.requireActual('fs');
  return { ...actual, existsSync: jest.fn(actual.existsSync), readFileSync: jest.fn(actual.readFileSync) };
});
const mockExists = fs.existsSync as unknown as jest.Mock;
const mockRead = fs.readFileSync as unknown as jest.Mock;

const PORTS = { port: 26383, containerPort: 26384 };
const POLICY = { version: 1, mode: 'enforce' } as unknown as PolicyConfig;
/** tokens for tests that need to call a step directly */
const CONFIG = Object.freeze({}) as ProxyConfigWritten;
const CA = Object.freeze({}) as CaReady;

describe('mitmdumpArgs', () => {
  const args = mitmdumpArgs({ port: 8080, containerPort: 8081 });

  it('runs one transparent listener for the host and one for containers', () => {
    expect(args.filter(a => a.startsWith('transparent@'))).toEqual([
      'transparent@127.0.0.1:8080',
      'transparent@127.0.0.1:8081'
    ]);
    // listen-port would apply to every mode without its own port and collide
    expect(args).not.toContain('--listen-port');
  });

  it('keeps the settings repoint depends on', () => {
    expect(args).toContain('connection_strategy=lazy');
  });

  it('streams large bodies at the internal threshold', () => {
    expect(args).toContain('stream_large_bodies=1m');
  });
});

describe('allocateProxyPorts', () => {
  it('picks a free consecutive pair in the band, below the ephemeral range', async () => {
    const taken = new Set([20000, 20001 + 1]);
    const seq = [0, 0.0000001, 0.5];
    const r = await allocateProxyPorts(
      async p => !taken.has(p),
      () => seq.shift() ?? 0.5
    );
    expect(r.containerPort).toBe(r.port + 1);
    expect(r.port).toBeGreaterThanOrEqual(PROXY_PORT_BAND[0]);
    expect(r.containerPort).toBeLessThanOrEqual(PROXY_PORT_BAND[1] + 1);
    expect(r.containerPort).toBeLessThan(32768);
    expect(taken.has(r.port) || taken.has(r.containerPort)).toBe(false);
  });

  it('fails loudly when nothing is free', async () => {
    await expect(allocateProxyPorts(async () => false)).rejects.toThrow(/no free pair/);
  });

  it('really binds on this machine', async () => {
    const r = await allocateProxyPorts();
    expect(r.containerPort).toBe(r.port + 1);
  });
});

describe('mitmproxy render', () => {
  const r = render({ policy: POLICY, ports: PORTS });

  it('writes the config directory, policy.json and the flow log (proxy-owned)', () => {
    expect(r.inert.map(f => `${f.kind} ${f.path} ${f.mode} ${f.owner}`)).toEqual([
      'dir /etc/safer-runner 0755 root:root',
      `file ${POLICY_FILE} 0644 root:root`,
      `touch ${FLOW_LOG} 0644 safer-runner-proxy:safer-runner-proxy`
    ]);
    expect(r.inert[1]).toMatchObject({ content: JSON.stringify(POLICY, null, 2) + '\n' });
  });

  it('runs mitmdump as the proxy user, umask 0077, writable only where it must write', () => {
    expect(transientUnitArgs(r.unit)).toEqual([
      'systemd-run',
      `--unit=${PROXY_UNIT}`,
      '--description=safer-runner egress proxy',
      '--uid=safer-runner-proxy',
      '--gid=safer-runner-proxy',
      '-p',
      'Restart=always',
      '-p',
      'RestartSec=1',
      '-p',
      'UMask=0077',
      '-p',
      'NoNewPrivileges=yes',
      '-p',
      'PrivateTmp=yes',
      '-p',
      'ProtectHome=yes',
      '-p',
      'ProtectSystem=strict',
      '-p',
      `ReadWritePaths=${PROXY_CONF_DIR} ${FLOW_LOG}`,
      '-p',
      'LimitNOFILE=65536',
      `--setenv=HOME=${PROXY_CONF_DIR}`,
      `--setenv=SAFER_RUNNER_POLICY=${POLICY_FILE}`,
      ...mitmdumpArgs(PORTS)
    ]);
    expect(r.unit.argv[0]).toBe(MITMDUMP_BIN);
  });
});

describe('mitmproxy effects', () => {
  beforeEach(() => {
    mockExists.mockReset().mockImplementation(jest.requireActual('fs').existsSync);
    mockRead.mockReset().mockImplementation(jest.requireActual('fs').readFileSync);
  });

  it('ensureUser: creates the proxy user only when missing', async () => {
    const missing = recordingHost(
      l => (l === 'id -u safer-runner-proxy' && missing.calls.length === 1 ? 1 : 0),
      () => '998\n'
    );
    expect(await ensureUser(missing.host)).toBe(998);
    expect(missing.calls).toEqual([
      'id -u safer-runner-proxy [ignore-rc] [silent]',
      'sudo useradd --system --no-create-home --shell /usr/sbin/nologin safer-runner-proxy',
      'id -u safer-runner-proxy [silent]'
    ]);
    const present = recordingHost(
      () => 0,
      () => '998\n'
    );
    await ensureUser(present.host);
    expect(present.calls.some(c => c.includes('useradd'))).toBe(false);
  });

  it('writeConfig: the addon copied root-owned out of the checkout, then the rendered files', async () => {
    const { host, calls } = recordingHost();
    await writeConfig(host, render({ policy: POLICY, ports: PORTS }));
    expect(calls.map(c => c.split(' ').slice(0, 3).join(' '))).toEqual([
      'sudo install -d',
      'sudo install -m',
      'sudo install -m',
      'sudo install -d',
      `sudo tee ${POLICY_FILE}`,
      'sudo chown root:root',
      'sudo chmod 0644',
      `sudo touch ${FLOW_LOG}`,
      'sudo chown safer-runner-proxy:safer-runner-proxy',
      'sudo chmod 0644'
    ]);
    expect(calls[1]).toMatch(
      /^sudo install -m 0644 -o root -g root \S+\/proxy\/policy\.py \/opt\/safer-runner\/proxy\/policy\.py$/
    );
  });

  it('start: ready once the addon logged a good start and both listeners are up', async () => {
    let polls = 0;
    mockExists.mockImplementation(p => (p === FLOW_LOG ? true : jest.requireActual('fs').existsSync(p)));
    mockRead.mockImplementation((p, enc) =>
      p === FLOW_LOG
        ? ++polls < 2
          ? ''
          : '{"ev": "start", "ok": true, "pid": 42, "mode": "enforce"}\n'
        : jest.requireActual('fs').readFileSync(p, enc)
    );
    const { host, calls } = recordingHost(
      () => 0,
      l => (l.startsWith('ss -Hltn') ? `LISTEN 0 4096 127.0.0.1:${l.split(':')[1]} 0.0.0.0:*` : '')
    );
    await start(host, render({ policy: POLICY, ports: PORTS }), PORTS, CONFIG, CA);
    expect(calls.map(c => c.split(' ').slice(0, 3).join(' '))).toEqual([
      'sudo systemctl stop',
      'sudo systemctl reset-failed',
      `sudo systemd-run --unit=${PROXY_UNIT}`,
      'ss -Hltn sport',
      'ss -Hltn sport'
    ]);
  });

  it('start: fails with diagnostics when the addon never reports a good start', async () => {
    jest.useFakeTimers();
    try {
      mockExists.mockImplementation(p => (p === FLOW_LOG ? false : jest.requireActual('fs').existsSync(p)));
      const { host, calls } = recordingHost();
      const started = start(host, render({ policy: POLICY, ports: PORTS }), PORTS, CONFIG, CA);
      const failed = expect(started).rejects.toThrow('proxy did not become ready within 90s');
      await jest.advanceTimersByTimeAsync(91_000);
      await failed;
      expect(calls.slice(-2)).toEqual([
        `sudo systemctl status ${PROXY_UNIT} --no-pager -l [ignore-rc]`,
        `sudo journalctl -u ${PROXY_UNIT} --no-pager -n 50 [ignore-rc]`
      ]);
      // no listener probe without a start record
      expect(calls.some(c => c.startsWith('ss '))).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });

  it('start needs the config and the CA first (a compile-time order check)', () => {
    const { host } = recordingHost();
    const r = render({ policy: POLICY, ports: PORTS });
    // @ts-expect-error - starting the proxy before its CA exists does not compile
    const noCa = () => start(host, r, PORTS, CONFIG, {});
    // @ts-expect-error - nor before its config is written
    const noConfig = () => start(host, r, PORTS, {}, CA);
    expect([noCa, noConfig]).toHaveLength(2);
  });
});

describe('the CA (ca.ts)', () => {
  it('is generated as the proxy user, umask 077, the key only in its tmpfs confdir', async () => {
    const { host, calls } = recordingHost();
    await generateCa(host);
    expect(calls[0]).toBe('sudo install -d -m 0755 -o root -g root /run/safer-runner');
    expect(calls[1]).toBe(`sudo install -d -m 0700 -o safer-runner-proxy -g safer-runner-proxy ${PROXY_CONF_DIR}`);
    expect(calls[2]).toMatch(
      /^sudo -u safer-runner-proxy sh -c umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3 /
    );
    expect(calls[2]).toContain(
      '-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign'
    );
    expect(calls[2]).toContain(`&& rm -f "$1" sh ${PROXY_CONF_DIR}/ca-key.pem ${PROXY_CONF_DIR}/ca-cert.pem`);
    expect(calls[2].endsWith(` ${PROXY_CA_KEY_FILE}`)).toBe(true);
    // only the public cert leaves the confdir
    expect(calls[3]).toBe(
      `sudo install -m 0644 -o root -g root ${PROXY_CONF_DIR}/ca-cert.pem /etc/safer-runner/ca.pem`
    );
    expect(calls).toHaveLength(4);
  });
});
