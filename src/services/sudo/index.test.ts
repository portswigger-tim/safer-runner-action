/**
 * Tests for the sudo service - covers both classic sudo (Ubuntu 24.04) and sudo-rs (Ubuntu 25.10+ / 26.04)
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { BaselineCaptured } from '../../integrity/baseline';
import { recordingHost } from '../../system/testing';
import {
  parseSudoFlavour,
  detectSudoFlavour,
  getRequiredSudoCommands,
  getValidationSudoCommands,
  getSudoLoggingConfigFile,
  buildSudoRsyslogConfig,
  render,
  setupSudoLogging,
  restrictSudo,
  readSudoUsage,
  INTERNAL_SUDO_COMMANDS,
  SUDO_LOGGING_SUDOERS_FILE,
  SUDO_LOGGING_RSYSLOG_FILE
} from '.';

jest.mock('@actions/core');

/** the baseline's token (a test stands in for captureBaseline) */
const BASELINE = Object.freeze({}) as BaselineCaptured;
const LOG = '/var/log/safer-runner/sudo.log';

describe('sudo module', () => {
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
      const { host, calls } = recordingHost(undefined, () => 'sudo-rs 0.2.13\n');
      await expect(detectSudoFlavour(host)).resolves.toBe('sudo-rs');
      expect(calls).toEqual(['sudo --version [ignore-rc] [silent]']);
    });

    it('falls back to classic sudo if detection fails', async () => {
      const { host } = recordingHost();
      host.output = async () => {
        throw new Error('boom');
      };
      await expect(detectSudoFlavour(host)).resolves.toBe('sudo');
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
        '/usr/sbin/iptables -t nat -L SAFER_RUNNER_CNAT -n --line-numbers'
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

  describe('render', () => {
    it.each([
      ['sudo', SUDO_LOGGING_SUDOERS_FILE, `Defaults logfile=${LOG}\nDefaults loglinelen=0\n`],
      ['sudo-rs', SUDO_LOGGING_RSYSLOG_FILE, buildSudoRsyslogConfig(LOG)]
    ] as const)('%s: the logging config and the restricted sudoers', (flavour, file, content) => {
      const r = render({ flavour, logFile: LOG });
      expect(r.logging).toEqual({ path: file, content });
      expect(r.sudoers).toBe(
        '# Safer Runner Action - Validation-only sudo access\n' +
          '# This configuration allows only the commands needed for post-action integrity validation.\n' +
          '# All other sudo commands will be denied.\n' +
          getRequiredSudoCommands('runner') +
          '\n'
      );
    });
  });

  describe('setupSudoLogging', () => {
    it('classic sudo: installs a logfile drop-in, moved into place last', async () => {
      const { host, calls, stdin } = recordingHost();
      await setupSudoLogging(host, render({ flavour: 'sudo', logFile: LOG }));
      expect(calls).toEqual([
        `sudo touch ${LOG}`,
        `sudo chmod 0644 ${LOG}`,
        'sudo tee /tmp/safer-runner-sudo-logging.tmp [silent]',
        'sudo chmod 0440 /tmp/safer-runner-sudo-logging.tmp',
        'sudo chown root:root /tmp/safer-runner-sudo-logging.tmp',
        `sudo mv /tmp/safer-runner-sudo-logging.tmp ${SUDO_LOGGING_SUDOERS_FILE}`
      ]);
      expect(stdin['sudo tee /tmp/safer-runner-sudo-logging.tmp']).toBe(
        `Defaults logfile=${LOG}\nDefaults loglinelen=0\n`
      );
    });

    it('sudo-rs: installs an rsyslog rule and restarts rsyslog', async () => {
      const { host, calls, stdin } = recordingHost();
      await setupSudoLogging(host, render({ flavour: 'sudo-rs', logFile: LOG }));
      expect(calls).toEqual([
        `sudo touch ${LOG}`,
        `sudo chmod 0644 ${LOG}`,
        `sudo chown syslog:adm ${LOG}`,
        `sudo tee ${SUDO_LOGGING_RSYSLOG_FILE} [silent]`,
        'sudo systemctl restart rsyslog'
      ]);
      expect(stdin[`sudo tee ${SUDO_LOGGING_RSYSLOG_FILE}`]).toBe(buildSudoRsyslogConfig(LOG));
    });

    it('fails when a logging step fails (no exit code is ignored)', async () => {
      const { host } = recordingHost(l => (l.startsWith('sudo mv ') ? 1 : 0));
      await expect(setupSudoLogging(host, render({ flavour: 'sudo', logFile: LOG }))).rejects.toThrow(/exit code 1/);
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

  describe('restrictSudo', () => {
    it.each(['sudo', 'sudo-rs'] as const)(
      '%s: validates, then installs a validation-only sudoers file',
      async flavour => {
        const { host, calls, stdin } = recordingHost();
        await restrictSudo(host, render({ flavour, logFile: LOG }), BASELINE);

        const written = stdin['sudo tee /tmp/runner-sudoers.tmp'];
        expect(written).toContain(getRequiredSudoCommands('runner'));
        expect(written).not.toContain('NOPASSWD: ALL');
        expect(written).not.toContain('*');
        // visudo's exit code is checked by restrictSudo itself (the next test), never just ignored
        expect(calls).toEqual([
          'sudo tee /tmp/runner-sudoers.tmp',
          'sudo visudo -c -f /tmp/runner-sudoers.tmp [ignore-rc]',
          'sudo chmod 0440 /tmp/runner-sudoers.tmp',
          'sudo chown root:root /tmp/runner-sudoers.tmp',
          'sudo mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner'
        ]);
      }
    );

    it('a sudoers file visudo rejects is removed and never installed', async () => {
      const { host, calls } = recordingHost(
        l => (l.startsWith('sudo visudo') ? 1 : 0),
        l => (l.startsWith('sudo visudo') ? 'syntax error' : '')
      );
      await expect(restrictSudo(host, render({ flavour: 'sudo-rs', logFile: LOG }), BASELINE)).rejects.toThrow(
        /rejected by visudo \(sudo-rs\): syntax error/
      );
      expect(calls.slice(-1)).toEqual(['sudo rm -f /tmp/runner-sudoers.tmp [ignore-rc]']);
      expect(calls.some(c => c.startsWith('sudo mv '))).toBe(false);
    });

    it.each(['tee', 'chmod 0440', 'chown root:root', 'mv'])('fails when `%s` of the sudoers file fails', async step => {
      const { host, calls } = recordingHost(l => (l.startsWith(`sudo ${step} /tmp/runner-sudoers.tmp`) ? 1 : 0));
      await expect(restrictSudo(host, render({ flavour: 'sudo', logFile: LOG }), BASELINE)).rejects.toThrow(
        /exit code 1/
      );
      expect(calls[calls.length - 1]).toMatch(new RegExp(`^sudo ${step} `));
    });

    it('needs the integrity baseline first (a compile-time order check)', () => {
      const { host } = recordingHost();
      const r = render({ flavour: 'sudo', logFile: LOG });
      // @ts-expect-error - restricting sudo before the baseline is stored does not compile
      const early = () => restrictSudo(host, r, {});
      expect(early).toBeInstanceOf(Function);
    });
  });

  describe('readSudoUsage: log formats', () => {
    let dir: string;

    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safer-runner-sudo-'));
    });

    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('sudo-rs (rsyslog) log: reports workflow commands and attributes internal ones', () => {
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

      const u = readSudoUsage(log);
      expect(u.ran.map(c => `${c.command} ${c.args}`.trim())).toEqual([
        '/usr/bin/apt-get install -y jq',
        '/usr/bin/true'
      ]);
      expect(u.ran[1].targetUser).toBe('nobody');
      expect(u.internal).toHaveLength(5);
      expect(u.refused).toEqual([]);
    });

    it('classic sudo log: handles wrapped entries and attributes internal ones', () => {
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

      const u = readSudoUsage(log);
      expect(u.ran).toEqual([]);
      expect(u.internal).toHaveLength(2);
      expect(u.refused).toHaveLength(1);
      expect(u.refused[0].command).toBe('/usr/bin/id');
      expect(u.refused[0].denied).toBe(true);
    });

    it('classic sudo log: reports refused attempts at internal commands', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        `Nov  3 16:24:32 : runner : a password is required ; PWD=/ ; USER=root ; COMMAND=/usr/bin/tee /tmp/runner-sudoers.tmp
`
      );
      const u = readSudoUsage(log);
      expect(u.refused).toHaveLength(1);
      expect(u.internal).toEqual([]);
    });

    it('still reports same-named binaries outside system paths', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        'Nov  3 16:23:51 : runner :  PWD=/ ; USER=root ; COMMAND=/home/runner/cat /etc/resolv.conf\n'
      );
      expect(readSudoUsage(log).ran).toHaveLength(1);
    });

    it('reports a workflow that removes the sudo logging config (the action never does)', () => {
      const log = path.join(dir, 'main-sudo.log');
      fs.writeFileSync(
        log,
        `Nov  3 16:23:51 : runner :  PWD=/ ; USER=root ; COMMAND=/usr/bin/rm -f ${SUDO_LOGGING_SUDOERS_FILE}
Nov  3 16:23:52 : runner :  PWD=/ ; USER=root ; COMMAND=/usr/bin/rm -f ${SUDO_LOGGING_RSYSLOG_FILE}
`
      );
      expect(readSudoUsage(log).ran).toHaveLength(2);
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

    // Real enforce job (v2.0.0-beta.2 suite, ubuntu-latest): the workflow's three attempts were
    // all refused because enforce removed sudo.
    it("attributes the action's own commands to the action and refused attempts to the workflow", () => {
      const log = path.join(dir, 'sudo.log');
      const pwd = 'PWD=/home/runner/work/x/x';
      fs.writeFileSync(
        log,
        [
          `Nov  4 19:17:12 : runner : ${pwd} ; USER=root ; COMMAND=/usr/bin/cat /etc/safer-runner/Corefile`,
          `Nov  4 19:17:13 : runner : ${pwd} ; USER=root ; COMMAND=/usr/bin/mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner`,
          `Nov  4 19:17:35 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/bin/true`,
          `Nov  4 19:20:01 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/bin/journalctl -u safer-runner-proxy --no-pager`,
          `Nov  4 19:20:01 : runner : a password is required ; ${pwd} ; USER=root ; COMMAND=/usr/sbin/iptables-save`
        ].join('\n') + '\n'
      );
      const u = readSudoUsage(log);
      expect(u.ran).toEqual([]);
      expect(u.refused.map(c => c.command)).toEqual([
        '/usr/bin/true',
        '/usr/bin/journalctl',
        '/usr/sbin/iptables-save'
      ]);
      expect(u.internal.map(c => c.command)).toEqual(['/usr/bin/cat', '/usr/bin/mv']);
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
