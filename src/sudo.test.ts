/**
 * Tests for sudo.ts - covers both classic sudo (Ubuntu 24.04) and sudo-rs (Ubuntu 25.10+ / 26.04)
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  parseSudoFlavour,
  detectSudoFlavour,
  getRequiredSudoCommands,
  getValidationSudoCommands,
  getSudoLoggingConfigFile,
  buildSudoRsyslogConfig,
  setupSudoLogging,
  removeSudoLogging,
  applyCustomSudoConfig,
  disableSudoForRunner,
  parseSudoLogs,
  readSudoUsage,
  INTERNAL_SUDO_COMMANDS,
  SUDO_LOGGING_SUDOERS_FILE,
  SUDO_LOGGING_RSYSLOG_FILE
} from './sudo';

jest.mock('@actions/core');
jest.mock('@actions/exec');
jest.mock('fs', () => {
  const actual = jest.requireActual('fs');
  return { ...actual, existsSync: jest.fn(actual.existsSync) };
});

const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
const mockGetExecOutput = exec.getExecOutput as jest.MockedFunction<typeof exec.getExecOutput>;
const mockExistsSync = fs.existsSync as jest.MockedFunction<typeof fs.existsSync>;
const realExistsSync = jest.requireActual('fs').existsSync;

/** Return the stdin passed to the `sudo tee <file>` call */
function teeInput(file: string): string {
  const call = mockExec.mock.calls.find(([cmd, args]) => cmd === 'sudo' && args?.[0] === 'tee' && args?.[1] === file);
  expect(call).toBeDefined();
  return (call![2]!.input as Buffer).toString();
}

/** All sudo invocations as "arg0 arg1 ..." strings, in order */
function sudoCalls(): string[] {
  return mockExec.mock.calls.filter(([cmd]) => cmd === 'sudo').map(([, args]) => (args || []).join(' '));
}

function visudoResult(exitCode: number, stderr = '') {
  mockGetExecOutput.mockImplementation(async (_cmd, args) => {
    if (args?.[0] === '--version') {
      return { exitCode: 0, stdout: 'sudo-rs 0.2.13-0ubuntu1.2\n', stderr: '' };
    }
    return { exitCode, stdout: '', stderr };
  });
}

describe('sudo module', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    mockExec.mockResolvedValue(0);
    mockExistsSync.mockImplementation(realExistsSync);
  });

  describe('parseSudoFlavour', () => {
    it('detects sudo-rs (Ubuntu 26.04)', () => {
      expect(parseSudoFlavour('sudo-rs 0.2.13-0ubuntu1.2\n')).toBe('sudo-rs');
    });

    it('detects classic sudo (Ubuntu 24.04)', () => {
      expect(
        parseSudoFlavour(
          'Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\nSudoers file grammar version 50\n'
        )
      ).toBe('sudo');
    });

    it('defaults to classic sudo for unknown output', () => {
      expect(parseSudoFlavour('')).toBe('sudo');
    });
  });

  describe('detectSudoFlavour', () => {
    it('runs sudo --version silently', async () => {
      mockGetExecOutput.mockResolvedValue({ exitCode: 0, stdout: 'sudo-rs 0.2.13\n', stderr: '' });
      await expect(detectSudoFlavour()).resolves.toBe('sudo-rs');
      expect(mockGetExecOutput).toHaveBeenCalledWith('sudo', ['--version'], expect.objectContaining({ silent: true }));
    });

    it('falls back to classic sudo if detection fails', async () => {
      mockGetExecOutput.mockRejectedValue(new Error('boom'));
      await expect(detectSudoFlavour()).resolves.toBe('sudo');
    });
  });

  describe('getRequiredSudoCommands (post-restriction allowlist)', () => {
    const config = getRequiredSudoCommands('runner');
    const ruleLines = config.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));

    it('contains no wildcards (rejected by sudo-rs, over-permissive in classic sudo)', () => {
      expect(config).not.toContain('*');
    });

    it('contains no Defaults overrides (log_allowed is unsupported by sudo-rs)', () => {
      expect(config).not.toMatch(/Defaults/);
      expect(config).not.toContain('log_allowed');
    });

    it('post-restriction sudoers contains only the validation allowlist', () => {
      // Every non-comment line is either the alias definition or the single rule granting it
      const commands = ruleLines
        .join('\n')
        .replace(/\\\n\s*/g, '')
        .replace(/^Cmnd_Alias SAFER_RUNNER_VALIDATION = /m, '')
        .split('\n');
      expect(commands).toEqual([
        getValidationSudoCommands().join(', '),
        'runner ALL=(ALL) NOPASSWD: SAFER_RUNNER_VALIDATION'
      ]);
      expect(getValidationSudoCommands()).toEqual([
        '/usr/bin/cat /etc/safer-runner/Corefile',
        '/usr/bin/cat /etc/resolv.conf',
        '/usr/bin/cat /etc/systemd/resolved.conf.d/no-stub.conf',
        '/usr/bin/cat /etc/safer-runner/policy.json',
        '/usr/bin/cat /opt/safer-runner/proxy/policy.py',
        '/usr/bin/cat /opt/safer-runner/proxy/policy_core.py',
        '/usr/bin/cat /etc/docker/daemon.json',
        `/usr/bin/cat ${SUDO_LOGGING_SUDOERS_FILE}`,
        `/usr/bin/cat ${SUDO_LOGGING_RSYSLOG_FILE}`,
        '/usr/bin/cat /etc/safer-runner/validation-state.json',
        '/usr/sbin/iptables -L INPUT -n --line-numbers',
        '/usr/sbin/iptables -L OUTPUT -n --line-numbers',
        '/usr/sbin/iptables -L FORWARD -n --line-numbers',
        '/usr/sbin/iptables -L SAFER_RUNNER_OUT -n --line-numbers',
        '/usr/sbin/iptables -t nat -L OUTPUT -n --line-numbers',
        '/usr/sbin/iptables -t nat -L SAFER_RUNNER_NAT -n --line-numbers',
        '/usr/sbin/iptables -L DOCKER-USER -n --line-numbers',
        '/usr/sbin/iptables -L SAFER_RUNNER_CFWD -n --line-numbers',
        '/usr/sbin/iptables -t nat -L SAFER_RUNNER_CNAT -n --line-numbers',
        '/opt/safer-runner/bin/teardown ""'
      ]);
    });

    it('allows every command post-action validation runs', () => {
      for (const file of [
        '/etc/safer-runner/Corefile',
        '/etc/resolv.conf',
        '/etc/systemd/resolved.conf.d/no-stub.conf',
        SUDO_LOGGING_SUDOERS_FILE,
        SUDO_LOGGING_RSYSLOG_FILE
      ]) {
        expect(config).toContain(`/usr/bin/cat ${file}`);
      }
      for (const chain of ['INPUT', 'OUTPUT', 'FORWARD']) {
        expect(config).toContain(`/usr/sbin/iptables -L ${chain} -n --line-numbers`);
      }
      expect(config).toContain('runner ALL=(ALL) NOPASSWD: SAFER_RUNNER_VALIDATION');
    });
  });

  describe('getSudoLoggingConfigFile', () => {
    it('returns the sudoers drop-in for classic sudo', () => {
      expect(getSudoLoggingConfigFile('sudo')).toBe(SUDO_LOGGING_SUDOERS_FILE);
    });

    it('returns the rsyslog rule for sudo-rs', () => {
      expect(getSudoLoggingConfigFile('sudo-rs')).toBe(SUDO_LOGGING_RSYSLOG_FILE);
    });
  });

  describe('setupSudoLogging', () => {
    it('classic sudo: installs a logfile drop-in, moved into place last', async () => {
      await setupSudoLogging('/var/log/safer-runner/main-sudo.log', 'sudo');

      const drop = teeInput('/tmp/safer-runner-sudo-logging.tmp');
      expect(drop).toContain('Defaults logfile=/var/log/safer-runner/main-sudo.log');
      expect(drop).toContain('Defaults loglinelen=0');

      const calls = sudoCalls();
      expect(calls[calls.length - 1]).toBe(`mv /tmp/safer-runner-sudo-logging.tmp ${SUDO_LOGGING_SUDOERS_FILE}`);
      expect(calls).toContain('chmod 0440 /tmp/safer-runner-sudo-logging.tmp');
      expect(calls).toContain('chown root:root /tmp/safer-runner-sudo-logging.tmp');
      expect(calls).not.toContain('systemctl restart rsyslog');
      expect(calls.some(c => c.includes(SUDO_LOGGING_RSYSLOG_FILE))).toBe(false);
    });

    it('sudo-rs: installs an rsyslog rule and restarts rsyslog', async () => {
      await setupSudoLogging('/var/log/safer-runner/pre-sudo.log', 'sudo-rs');

      expect(teeInput(SUDO_LOGGING_RSYSLOG_FILE)).toBe(buildSudoRsyslogConfig('/var/log/safer-runner/pre-sudo.log'));

      const calls = sudoCalls();
      expect(calls).toContain('chown syslog:adm /var/log/safer-runner/pre-sudo.log');
      expect(calls[calls.length - 1]).toBe('systemctl restart rsyslog');
      expect(calls.some(c => c.includes(SUDO_LOGGING_SUDOERS_FILE))).toBe(false);
    });

    it('detects the sudo implementation when not provided', async () => {
      mockGetExecOutput.mockResolvedValue({ exitCode: 0, stdout: 'sudo-rs 0.2.13\n', stderr: '' });
      await setupSudoLogging('/var/log/safer-runner/main-sudo.log');
      expect(sudoCalls()).toContain('systemctl restart rsyslog');
    });
  });

  describe('buildSudoRsyslogConfig', () => {
    it('filters sudo syslog messages into the given file using a classic-sudo compatible format', () => {
      const config = buildSudoRsyslogConfig('/var/log/safer-runner/main-sudo.log');
      expect(config).toContain(`$programname == 'sudo'`);
      expect(config).toContain(`$msg contains 'COMMAND='`);
      expect(config).toContain('file="/var/log/safer-runner/main-sudo.log"');
      expect(config).toContain('%timereported:::date-rfc3164% :%msg%\\n');
      // Must not stop processing - auth.log keeps its copy
      expect(config).not.toContain('stop');
    });
  });

  describe('removeSudoLogging', () => {
    it('removes the classic sudo drop-in', async () => {
      mockExistsSync.mockReturnValue(false);
      await removeSudoLogging();
      expect(sudoCalls()).toEqual([`rm -f ${SUDO_LOGGING_SUDOERS_FILE}`]);
    });

    it('removes the sudo-rs rsyslog rule and restarts rsyslog so pre-hook capture stops', async () => {
      mockExistsSync.mockImplementation(p => p === SUDO_LOGGING_RSYSLOG_FILE);
      await removeSudoLogging();
      expect(sudoCalls()).toEqual([
        `rm -f ${SUDO_LOGGING_SUDOERS_FILE}`,
        `rm -f ${SUDO_LOGGING_RSYSLOG_FILE}`,
        'systemctl restart rsyslog'
      ]);
    });
  });

  describe('disableSudoForRunner', () => {
    it.each(['sudo', 'sudo-rs'] as const)('%s: writes a validation-only sudoers file', async flavour => {
      visudoResult(0);
      await disableSudoForRunner(flavour);

      const written = teeInput('/tmp/runner-sudoers.tmp');
      expect(written).toContain(getRequiredSudoCommands('runner'));
      expect(written).not.toContain('NOPASSWD: ALL');
      expect(written).not.toContain('*');

      expect(mockGetExecOutput).toHaveBeenCalledWith(
        'sudo',
        ['visudo', '-c', '-f', '/tmp/runner-sudoers.tmp'],
        expect.anything()
      );
      const calls = sudoCalls();
      expect(calls[calls.length - 1]).toBe('mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner');
    });
  });

  describe('applyCustomSudoConfig', () => {
    it('appends the validation allowlist to the user config', async () => {
      visudoResult(0);
      await applyCustomSudoConfig('runner ALL=(root) NOPASSWD: /usr/bin/apt-get', 'sudo-rs');

      const written = teeInput('/tmp/runner-sudoers.tmp');
      expect(written.startsWith('runner ALL=(root) NOPASSWD: /usr/bin/apt-get\n')).toBe(true);
      expect(written).toContain('SAFER_RUNNER_VALIDATION');
    });

    it('sudo-rs: fails with guidance naming sudo-rs when visudo rejects the config', async () => {
      visudoResult(1, '/tmp/runner-sudoers.tmp:1:28: syntax error: wildcards are not allowed in command arguments');

      await expect(
        applyCustomSudoConfig('runner ALL=(root) NOPASSWD: /usr/bin/ls /home/*/x', 'sudo-rs')
      ).rejects.toThrow(/wildcards are not allowed/);

      expect(core.error).toHaveBeenCalledWith(expect.stringContaining('sudo-rs'));
      expect(core.error).toHaveBeenCalledWith(expect.stringContaining('whole argument list'));
      expect(sudoCalls()).toContain('rm -f /tmp/runner-sudoers.tmp');
      expect(sudoCalls()).not.toContain('mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner');
    });

    it('classic sudo: fails without sudo-rs guidance', async () => {
      visudoResult(1, 'syntax error');

      await expect(applyCustomSudoConfig('runner ALL=(root) NOPASSWD: bogus', 'sudo')).rejects.toThrow(
        'Invalid sudoers configuration'
      );
      expect(core.error).not.toHaveBeenCalledWith(expect.stringContaining('sudo-rs'));
    });
  });

  describe('parseSudoLogs', () => {
    let dir: string;

    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safer-runner-sudo-'));
    });

    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('sudo-rs (rsyslog) log: reports workflow commands and hides internal ones', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        `Nov  3 16:23:51 : runner :  PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/cat /etc/resolv.conf
Nov  3 16:23:51 : runner :  PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/tee /tmp/runner-sudoers.tmp
Nov  3 16:23:51 : runner :  PWD=/home/runner ; USER=root ; COMMAND=/usr/sbin/visudo -c -f /tmp/runner-sudoers.tmp
Nov  3 16:23:51 : runner :  PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner
Nov  3 16:23:51 : runner :  PWD=/home/runner ; USER=root ; COMMAND=/usr/sbin/iptables -L OUTPUT -n --line-numbers
Nov  3 16:23:52 : runner :  PWD=/home/runner/work ; USER=root ; COMMAND=/usr/bin/apt-get install -y jq
Nov  3 16:23:53 : runner :  PWD=/home/runner/work ; USER=nobody ; COMMAND=/usr/bin/true
`
      );

      const commands = parseSudoLogs(log);
      expect(commands.map(c => `${c.command} ${c.args}`.trim())).toEqual([
        '/usr/bin/apt-get install -y jq',
        '/usr/bin/true'
      ]);
      expect(commands[1].targetUser).toBe('nobody');
    });

    it('classic sudo log: handles wrapped entries and hides internal ones', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        `Nov  3 16:24:32 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/cat
    /etc/resolv.conf
Nov  3 16:24:32 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/chmod 0440
    /tmp/runner-sudoers.tmp
Nov  3 16:24:33 : runner : a password is required ; PWD=/ ; USER=root ;
    COMMAND=/usr/bin/id
`
      );

      const commands = parseSudoLogs(log);
      expect(commands).toHaveLength(1);
      expect(commands[0].command).toBe('/usr/bin/id');
      expect(commands[0].denied).toBe(true);
    });

    it('classic sudo log: reports refused attempts at internal commands', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        `Nov  3 16:24:32 : runner : a password is required ; PWD=/ ; USER=root ; COMMAND=/usr/bin/tee /tmp/runner-sudoers.tmp
`
      );
      expect(parseSudoLogs(log)).toHaveLength(1);
    });

    it('still reports same-named binaries outside system paths', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        'Nov  3 16:23:51 : runner :  PWD=/ ; USER=root ; COMMAND=/home/runner/cat /etc/resolv.conf\n'
      );
      expect(parseSudoLogs(log)).toHaveLength(1);
    });

    it('returns empty array for missing file', () => {
      expect(parseSudoLogs(path.join(dir, 'missing.log'))).toEqual([]);
    });
  });

  describe('readSudoUsage (report attribution)', () => {
    let dir: string;
    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safer-runner-sudo-'));
    });
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    // Real enforce job (v2.0.0-beta.2 suite, ubuntu-latest): the summary said "Workflow executed 4
    // sudo commands". Teardown is the action's own post step; the other three were the
    // workflow's attempts, all refused because enforce removed sudo.
    it('attributes the post-step teardown to the action and refused attempts to the workflow', () => {
      const log = path.join(dir, 'sudo.log');
      const pwd = 'PWD=/home/runner/work/x/x';
      fs.writeFileSync(
        log,
        [
          `Nov  4 19:17:12 : runner : ${pwd} ; USER=root ; COMMAND=/usr/bin/cat /etc/safer-runner/Corefile`,
          `Nov  4 19:17:13 : runner : ${pwd} ; USER=root ; COMMAND=/usr/bin/mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner`,
          `Nov  4 19:17:35 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/bin/true`,
          `Nov  4 19:20:01 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/bin/journalctl -u safer-runner-proxy --no-pager`,
          `Nov  4 19:20:01 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/sbin/iptables-save`,
          `Nov  4 19:20:30 : runner : ${pwd} ; USER=root ; COMMAND=/opt/safer-runner/bin/teardown`
        ].join('\n') + '\n'
      );
      const u = readSudoUsage(log);
      expect(u.ran).toEqual([]);
      expect(u.refused.map(c => c.command)).toEqual([
        '/usr/bin/true',
        '/usr/bin/journalctl',
        '/usr/sbin/iptables-save'
      ]);
      expect(u.internal.map(c => c.command)).toEqual(['/usr/bin/cat', '/usr/bin/mv', '/opt/safer-runner/bin/teardown']);
      // and the legacy filter no longer reports teardown as workflow usage
      expect(parseSudoLogs(log).map(c => c.command)).not.toContain('/opt/safer-runner/bin/teardown');
    });

    it('only matches the teardown helper by its exact root-owned path', () => {
      const log = path.join(dir, 'sudo.log');
      fs.writeFileSync(
        log,
        'Nov  4 19:20:30 : runner : PWD=/ ; USER=root ; COMMAND=/home/runner/opt/safer-runner/bin/teardown\n' +
          'Nov  4 19:20:31 : runner : PWD=/ ; USER=root ; COMMAND=/opt/safer-runner/bin/teardown --evil\n'
      );
      expect(readSudoUsage(log).ran).toHaveLength(2);
    });

    it('is empty for a missing file', () => {
      expect(readSudoUsage(path.join(dir, 'missing.log'))).toEqual({ ran: [], refused: [], internal: [] });
    });
  });

  describe('INTERNAL_SUDO_COMMANDS', () => {
    it('covers every validation command', () => {
      for (const cmd of getValidationSudoCommands()) {
        expect(INTERNAL_SUDO_COMMANDS).toContain(cmd.replace(/^\/usr\/s?bin\//, ''));
      }
    });
  });
});
