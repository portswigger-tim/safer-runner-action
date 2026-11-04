import {
  parseSudoLogLine,
  deduplicateSudoCommands,
  parseSudoLogsFromString,
  generateSudoersConfig,
  isDangerousSudoCommand,
  filterInternalSudoCommands,
  type SudoCommand
} from './sudo-parser';

describe('Sudo Parser', () => {
  describe('parseSudoLogLine', () => {
    it('should parse sudo log line with command and args', () => {
      const line = 'Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf';
      const result = parseSudoLogLine(line);

      expect(result).toEqual({
        timestamp: 'Oct  3 13:06:55',
        user: 'runner',
        targetUser: 'root',
        command: '/usr/bin/tee',
        args: '/etc/resolv.conf'
      });
    });

    it('should parse sudo log line with command only', () => {
      const line = 'Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/whoami';
      const result = parseSudoLogLine(line);

      expect(result).toEqual({
        timestamp: 'Oct  3 13:06:55',
        user: 'runner',
        targetUser: 'root',
        command: '/usr/bin/whoami',
        args: ''
      });
    });

    it('should parse sudo log line with multiple args', () => {
      const line =
        'Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/sbin/iptables -A OUTPUT -o eth0 -j ACCEPT';
      const result = parseSudoLogLine(line);

      expect(result).toEqual({
        timestamp: 'Oct  3 13:06:55',
        user: 'runner',
        targetUser: 'root',
        command: '/usr/sbin/iptables',
        args: '-A OUTPUT -o eth0 -j ACCEPT'
      });
    });

    it('should return null for invalid log lines', () => {
      expect(parseSudoLogLine('invalid log line')).toBeNull();
      expect(parseSudoLogLine('')).toBeNull();
      expect(parseSudoLogLine('Oct  3 13:06:55')).toBeNull();
    });

    it('should handle different date formats', () => {
      const line = 'Jan 15 09:30:45 : runner : *** ; USER=root ; COMMAND=/usr/bin/ls';
      const result = parseSudoLogLine(line);

      expect(result?.timestamp).toBe('Jan 15 09:30:45');
    });
  });

  describe('deduplicateSudoCommands', () => {
    it('should remove duplicate commands', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/tee',
          args: '/etc/resolv.conf'
        },
        {
          timestamp: 'Oct  3 13:06:56',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/tee',
          args: '/etc/resolv.conf'
        },
        {
          timestamp: 'Oct  3 13:06:57',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/chmod',
          args: '644 /tmp/test'
        }
      ];

      const result = deduplicateSudoCommands(commands);
      expect(result).toHaveLength(2);
      expect(result[0].command).toBe('/usr/bin/tee');
      expect(result[1].command).toBe('/usr/bin/chmod');
    });

    it('should keep commands with same executable but different args', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/chmod',
          args: '644 /tmp/test'
        },
        {
          timestamp: 'Oct  3 13:06:56',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/chmod',
          args: '755 /tmp/test'
        }
      ];

      const result = deduplicateSudoCommands(commands);
      expect(result).toHaveLength(2);
    });

    it('should handle empty array', () => {
      expect(deduplicateSudoCommands([])).toEqual([]);
    });
  });

  describe('parseSudoLogsFromString - single-line format', () => {
    it('should parse multiple sudo log entries', () => {
      const logs = `Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf
Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/chmod 600 /etc/dnsmasq.conf
Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/chown root:root /etc/dnsmasq.conf`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(3);
      expect(result[0].command).toBe('/usr/bin/tee');
      expect(result[1].command).toBe('/usr/bin/chmod');
      expect(result[2].command).toBe('/usr/bin/chown');
    });

    it('should deduplicate commands automatically', () => {
      const logs = `Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf
Oct  3 13:06:56 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf
Oct  3 13:06:57 : runner : *** ; USER=root ; COMMAND=/usr/bin/chmod 600 /etc/dnsmasq.conf`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(2);
    });

    it('should handle empty content', () => {
      expect(parseSudoLogsFromString('')).toEqual([]);
    });

    it('should handle malformed content gracefully', () => {
      const logs = `invalid line
Oct  3 13:06:55 : runner : *** ; USER=root ; COMMAND=/usr/bin/tee /etc/resolv.conf
another invalid line`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(1);
      expect(result[0].command).toBe('/usr/bin/tee');
    });
  });

  describe('parseSudoLogsFromString - sudo-rs format (via rsyslog)', () => {
    it('should parse sudo-rs entries (no TTY field, double space after user)', () => {
      const logs = `Nov  3 16:23:51 : runner :  PWD=/ ; USER=root ; COMMAND=/usr/bin/echo hello world
Nov  3 16:23:51 : runner :  PWD=/ ; USER=nobody ; COMMAND=/usr/bin/true `;

      const result = parseSudoLogsFromString(logs);
      expect(result).toEqual([
        {
          timestamp: 'Nov  3 16:23:51',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/echo',
          args: 'hello world'
        },
        { timestamp: 'Nov  3 16:23:51', user: 'runner', targetUser: 'nobody', command: '/usr/bin/true', args: '' }
      ]);
    });
  });

  describe('parseSudoLogsFromString - wrapped classic sudo entries', () => {
    it('should join continuation lines so arguments are not lost', () => {
      const logs = `Nov  3 16:24:32 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/cat
    /etc/resolv.conf
Nov  3 16:24:32 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/apt-get install
    -y jq`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({ command: '/usr/bin/cat', args: '/etc/resolv.conf' });
      expect(result[1]).toMatchObject({ command: '/usr/bin/apt-get', args: 'install -y jq' });
    });
  });

  describe('filterInternalSudoCommands', () => {
    const cmd = (command: string, args: string): SudoCommand => ({
      timestamp: 'Nov  3 16:23:51',
      user: 'runner',
      targetUser: 'root',
      command,
      args
    });
    const internal = ['cat /etc/resolv.conf', 'systemctl restart rsyslog'];

    it('removes internal commands regardless of bin/sbin location', () => {
      const result = filterInternalSudoCommands(
        [
          cmd('/usr/bin/cat', '/etc/resolv.conf'),
          cmd('/bin/cat', '/etc/resolv.conf'),
          cmd('/usr/bin/systemctl', 'restart rsyslog'),
          cmd('/usr/sbin/systemctl', 'restart rsyslog')
        ],
        internal
      );
      expect(result).toEqual([]);
    });

    it('keeps commands with different arguments', () => {
      const result = filterInternalSudoCommands(
        [cmd('/usr/bin/cat', '/etc/shadow'), cmd('/usr/bin/cat', '/etc/resolv.conf /etc/shadow')],
        internal
      );
      expect(result).toHaveLength(2);
    });

    it('keeps refused attempts that mimic internal commands', () => {
      const result = filterInternalSudoCommands(
        [{ ...cmd('/usr/bin/cat', '/etc/resolv.conf'), denied: true }],
        internal
      );
      expect(result).toHaveLength(1);
    });

    it('marks classic sudo refusals as denied', () => {
      const result = parseSudoLogsFromString(`Nov  3 16:24:32 : runner : a password is required ; PWD=/ ; USER=root ;
    COMMAND=/usr/bin/tee /tmp/runner-sudoers.tmp
Nov  3 16:24:33 : runner : command not allowed ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id
Nov  3 16:24:34 : runner : PWD=/ ; USER=root ; COMMAND=/usr/bin/whoami`);
      expect(result.map(c => c.denied)).toEqual([true, true, undefined]);
    });

    it('keeps same-named binaries outside system directories', () => {
      const result = filterInternalSudoCommands([cmd('/tmp/cat', '/etc/resolv.conf')], internal);
      expect(result).toHaveLength(1);
    });
  });

  describe('parseSudoLogsFromString - multi-line format', () => {
    it('should parse multi-line sudo log entries', () => {
      const logs = `Oct  3 14:36:19 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/docker --version
Oct  3 14:36:19 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/whoami
Oct  3 14:36:19 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/cat /etc/os-release`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(3);
      expect(result[0].command).toBe('/usr/bin/docker');
      expect(result[0].args).toBe('--version');
      expect(result[1].command).toBe('/usr/bin/whoami');
      expect(result[1].args).toBe('');
      expect(result[2].command).toBe('/usr/bin/cat');
      expect(result[2].args).toBe('/etc/os-release');
    });

    it('should deduplicate multi-line entries automatically', () => {
      const logs = `Oct  3 14:36:19 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/docker --version
Oct  3 14:36:20 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/docker --version`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(1);
      expect(result[0].command).toBe('/usr/bin/docker');
    });

    it('should handle empty multi-line content', () => {
      expect(parseSudoLogsFromString('')).toEqual([]);
    });

    it('should handle malformed multi-line content gracefully', () => {
      const logs = `invalid line
Oct  3 14:36:19 : runner :
    *** ; USER=root ;
    COMMAND=/usr/bin/docker --version
another invalid line`;

      const result = parseSudoLogsFromString(logs);
      expect(result).toHaveLength(1);
      expect(result[0].command).toBe('/usr/bin/docker');
    });
  });

  describe('generateSudoersConfig', () => {
    const mk = (command: string, args: string, targetUser = 'root'): SudoCommand => ({
      timestamp: 'Oct  3 13:06:55',
      user: 'runner',
      targetUser,
      command,
      args
    });

    it('runs as the observed target user, not (ALL), and pins exact args', () => {
      const result = generateSudoersConfig([mk('/usr/sbin/iptables', '-L OUTPUT -n')]);
      expect(result).toBe('runner ALL=(root) NOPASSWD: /usr/sbin/iptables -L OUTPUT -n');
      expect(result).not.toContain('(ALL)');
    });

    it('emits `cmd ""` for a no-argument command (a bare command would allow any args)', () => {
      const result = generateSudoersConfig([mk('/usr/bin/id', '')]);
      expect(result).toBe('runner ALL=(root) NOPASSWD: /usr/bin/id ""');
    });

    it('comments out escalation-prone commands with a warning', () => {
      const result = generateSudoersConfig([mk('/usr/bin/docker', 'run -it image')]);
      expect(result).toContain('# WARNING:');
      expect(result).toContain('# runner ALL=(root) NOPASSWD: /usr/bin/docker run -it image');
      // the active (uncommented) rule must NOT be present
      expect(result).not.toMatch(/^runner ALL=\(root\) NOPASSWD: \/usr\/bin\/docker/m);
    });

    it('comments out package managers and file-writers (apt-get, tee)', () => {
      const result = generateSudoersConfig([mk('/usr/bin/apt-get', 'update'), mk('/usr/bin/tee', '/etc/hosts')]);
      expect(result).toContain('# runner ALL=(root) NOPASSWD: /usr/bin/apt-get update');
      expect(result).toContain('# runner ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts');
    });

    it('emits a separate exact rule per distinct invocation (no "any args" fallback)', () => {
      const result = generateSudoersConfig([
        mk('/usr/bin/systemctl', 'restart nginx'),
        mk('/usr/bin/systemctl', 'status nginx')
      ]);
      // systemctl is escalation-prone, so both are commented, but each exact invocation appears
      expect(result).toContain('# runner ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx');
      expect(result).toContain('# runner ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx');
      // never the unrestricted bare form
      expect(result).not.toMatch(/NOPASSWD: \/usr\/bin\/systemctl\s*$/m);
    });

    it('de-duplicates identical invocations', () => {
      const result = generateSudoersConfig([mk('/usr/bin/id', ''), mk('/usr/bin/id', '')]);
      expect(result).toBe('runner ALL=(root) NOPASSWD: /usr/bin/id ""');
    });

    it('uses a custom username', () => {
      const result = generateSudoersConfig([mk('/usr/bin/id', '')], 'testuser');
      expect(result).toContain('testuser ALL=(root) NOPASSWD:');
    });

    it('handles the empty array', () => {
      expect(generateSudoersConfig([])).toBe('');
    });
  });

  describe('isDangerousSudoCommand', () => {
    it('flags shells, interpreters, file-writers, package/service managers and docker', () => {
      for (const c of [
        '/bin/bash',
        '/usr/bin/python3',
        '/usr/bin/tee',
        '/usr/bin/dd',
        '/usr/bin/apt-get',
        '/usr/bin/systemctl',
        '/usr/bin/docker',
        '/usr/bin/vim',
        '/usr/bin/env'
      ]) {
        expect(isDangerousSudoCommand(c)).toBe(true);
      }
    });

    it('does not flag narrow read-only tools', () => {
      for (const c of ['/usr/bin/id', '/usr/bin/whoami', '/usr/sbin/iptables', '/usr/bin/cat']) {
        expect(isDangerousSudoCommand(c)).toBe(false);
      }
    });
  });
});
