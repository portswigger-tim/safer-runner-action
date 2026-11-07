import { COREDNS_BIN, COREFILE, DNS_LOG, DNS_UNIT, ETC_DIR } from '../../constants';
import { recordingHost } from '../../system/testing';
import { transientUnitArgs } from '../../system/unit';
import * as coredns from '.';

jest.mock('@actions/core');
jest.mock('dns', () => {
  const actual = jest.requireActual('dns');
  class Resolver {
    setServers(): void {}
    resolve4(): Promise<string[]> {
      return mockResolve();
    }
  }
  return { ...actual, promises: { ...actual.promises, Resolver } };
});
const mockResolve = jest.fn();

const FACTS = {
  mode: 'enforce' as const,
  allow: ['github.com', '*.github.com'],
  deny: ['gist.github.com'],
  upstreams: ['9.9.9.9'],
  hosts: { file: '/etc/hosts', names: ['localhost'], inline: [] },
  user: 'dns-0123456789abcdef'
};

describe('coredns render', () => {
  const r = coredns.render(FACTS);

  it('writes the config directory, the Corefile and the log, in that order', () => {
    expect(r.inert.map(f => `${f.kind} ${f.path} ${f.mode} ${f.owner}`)).toEqual([
      `dir ${ETC_DIR} 0755 root:root`,
      `file ${COREFILE} 0644 root:root`,
      `touch ${DNS_LOG} 0644 root:root`
    ]);
  });

  it('runs CoreDNS as its own user with only CAP_NET_BIND_SERVICE, logging to the DNS log', () => {
    expect(transientUnitArgs(r.unit)).toEqual([
      'systemd-run',
      `--unit=${DNS_UNIT}`,
      '--description=safer-runner DNS resolver (CoreDNS)',
      '--uid=dns-0123456789abcdef',
      '--gid=dns-0123456789abcdef',
      '-p',
      'Restart=always',
      '-p',
      'RestartSec=1',
      '-p',
      'AmbientCapabilities=CAP_NET_BIND_SERVICE',
      '-p',
      'CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
      '-p',
      'NoNewPrivileges=yes',
      '-p',
      'PrivateTmp=yes',
      '-p',
      'ProtectHome=yes',
      '-p',
      'ProtectSystem=strict',
      '-p',
      `StandardOutput=append:${DNS_LOG}`,
      '-p',
      `StandardError=append:${DNS_LOG}`,
      COREDNS_BIN,
      '-conf',
      COREFILE
    ]);
  });
});

describe('coredns effects', () => {
  beforeEach(() => mockResolve.mockReset());

  it('start: files, then the unit, ready once the resolver answers', async () => {
    mockResolve.mockRejectedValueOnce(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
    mockResolve.mockResolvedValue(['140.82.112.3']);
    const { host, calls } = recordingHost();
    await coredns.start(host, coredns.render(FACTS));
    expect(calls.map(c => c.split(' ').slice(0, 3).join(' '))).toEqual([
      'sudo install -d',
      `sudo tee ${COREFILE}`,
      'sudo chown root:root',
      'sudo chmod 0644',
      `sudo touch ${DNS_LOG}`,
      'sudo chown root:root',
      'sudo chmod 0644',
      `sudo systemctl stop`,
      `sudo systemctl reset-failed`,
      'sudo systemd-run --unit=safer-runner-dns'
    ]);
    expect(mockResolve).toHaveBeenCalledTimes(2);
  });

  it('start: fails with diagnostics when CoreDNS never answers', async () => {
    jest.useFakeTimers();
    try {
      mockResolve.mockRejectedValue(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
      const { host, calls } = recordingHost();
      const started = coredns.start(host, coredns.render(FACTS));
      const failed = expect(started).rejects.toThrow(
        'CoreDNS did not answer for github.com within 20s (last: ECONNREFUSED)'
      );
      await jest.advanceTimersByTimeAsync(21_000);
      await failed;
      expect(calls.slice(-4).map(c => c.split(' ').slice(0, 2).join(' '))).toEqual([
        'sudo systemctl',
        'sudo journalctl',
        'sudo tail',
        'sudo ss'
      ]);
    } finally {
      jest.useRealTimers();
    }
  });

  it('cutover: resolved drop-in, then resolv.conf, then restart resolved', async () => {
    const { host, calls } = recordingHost();
    mockResolve.mockResolvedValue(['140.82.112.3']);
    const dnsReady = await coredns.start(recordingHost().host, coredns.render(FACTS));
    await coredns.cutover(host, dnsReady);
    expect(calls).toEqual([
      'sudo mkdir -p /etc/systemd/resolved.conf.d',
      'sudo tee /etc/systemd/resolved.conf.d/no-stub.conf',
      'sudo unlink /etc/resolv.conf',
      'sudo tee /etc/resolv.conf',
      'sudo systemctl restart systemd-resolved'
    ]);
  });

  it('cutover needs the token that only start() returns (a compile-time order check)', () => {
    const { host } = recordingHost();
    // @ts-expect-error - switching the resolver over before CoreDNS answers does not compile
    const early = () => coredns.cutover(host, {});
    expect(early).toBeInstanceOf(Function);
  });

  it('createUser: a random system user with no login and no home', async () => {
    const { host, calls } = recordingHost();
    const u = await coredns.createUser(host);
    expect(u.username).toMatch(/^dns-[0-9a-f]{16}$/);
    expect(u.uid).toBeGreaterThanOrEqual(60000);
    expect(u.uid).toBeLessThan(65000);
    expect(calls).toEqual([
      `sudo useradd --system --no-create-home --shell /usr/sbin/nologin --uid ${u.uid} ${u.username}`
    ]);
  });
});
