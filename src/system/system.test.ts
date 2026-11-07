import { writeFiles } from './files';
import { recordingHost } from './testing';
import { HARDENING, startUnit, transientUnitArgs } from './unit';
import type { UnitSpec } from './types';

jest.mock('@actions/core');

const UNIT: UnitSpec = {
  unit: 'svc',
  description: 'a service',
  user: 'svc-user',
  props: ['UMask=0077', ...HARDENING, 'LimitNOFILE=65536'],
  env: { HOME: '/run/svc', CONFIG: '/etc/svc.json' },
  argv: ['/opt/bin/svc', '--flag']
};

describe('writeFiles', () => {
  it('refuses a restricted file: secrets are a named step, never an inert write', async () => {
    const { host, calls } = recordingHost();
    await expect(
      writeFiles(host, [
        { kind: 'file', path: '/etc/x/ok.json', content: '{}', mode: '0644', owner: 'root:root' },
        { kind: 'file', path: '/etc/x/secret.json', content: '{}', mode: '0600', owner: 'root:root' }
      ])
    ).rejects.toThrow(/secret\.json \(0600\) is restricted/);
    // checked before anything is written
    expect(calls).toEqual([]);
  });

  it('writes each kind in order, as root', async () => {
    const { host, calls } = recordingHost();
    await writeFiles(host, [
      { kind: 'dir', path: '/etc/x', mode: '0755', owner: 'root:root' },
      { kind: 'file', path: '/etc/x/a.json', content: '{}', mode: '0644', owner: 'root:root' },
      { kind: 'touch', path: '/var/log/x.log', mode: '0644', owner: 'svc:svc' }
    ]);
    expect(calls).toEqual([
      'sudo install -d -m 0755 -o root -g root /etc/x',
      'sudo tee /etc/x/a.json [silent]',
      'sudo chown root:root /etc/x/a.json',
      'sudo chmod 0644 /etc/x/a.json',
      'sudo touch /var/log/x.log',
      'sudo chown svc:svc /var/log/x.log',
      'sudo chmod 0644 /var/log/x.log'
    ]);
  });
});

describe('transient units', () => {
  it('builds systemd-run: restart policy, the unit props in order, env, then the command', () => {
    expect(transientUnitArgs(UNIT)).toEqual([
      'systemd-run',
      '--unit=svc',
      '--description=a service',
      '--uid=svc-user',
      '--gid=svc-user',
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
      'LimitNOFILE=65536',
      '--setenv=HOME=/run/svc',
      '--setenv=CONFIG=/etc/svc.json',
      '/opt/bin/svc',
      '--flag'
    ]);
  });

  it('stops and resets the unit before starting it, then polls until ready', async () => {
    const { host, calls } = recordingHost();
    let polls = 0;
    await startUnit(host, UNIT, {
      ready: async () => ++polls === 3,
      pollMs: 1,
      timeoutMs: 10_000,
      diagnostics: [['journalctl', '-u', 'svc']],
      timeoutError: () => new Error('never')
    });
    expect(calls.map(c => c.split(' ').slice(0, 4).join(' '))).toEqual([
      'sudo systemctl stop svc',
      'sudo systemctl reset-failed svc',
      'sudo systemd-run --unit=svc --description=a'
    ]);
    expect(polls).toBe(3);
  });

  it('prints the diagnostics and fails when the unit never becomes ready', async () => {
    const { host, calls } = recordingHost();
    await expect(
      startUnit(host, UNIT, {
        ready: async () => false,
        pollMs: 5,
        timeoutMs: 20,
        diagnostics: [
          ['journalctl', '-u', 'svc'],
          ['ss', '-lnt']
        ],
        timeoutError: () => new Error('svc did not start')
      })
    ).rejects.toThrow('svc did not start');
    expect(calls.slice(-2)).toEqual(['sudo journalctl -u svc [ignore-rc]', 'sudo ss -lnt [ignore-rc]']);
  });
});
