import {
  parseSudoLogLine,
  deduplicateSudoCommands,
  parseSudoLogsFromString,
  generateSudoersConfig,
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

  describe('parseSudoLogsFromString', () => {
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

  describe('generateSudoersConfig', () => {
    it('should generate config for single command with args', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'build .'
        }
      ];

      const result = generateSudoersConfig(commands);
      expect(result).toBe('runner ALL=(ALL) NOPASSWD: /usr/bin/docker build .');
    });

    it('should generate config for command without args', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/whoami',
          args: ''
        }
      ];

      const result = generateSudoersConfig(commands);
      expect(result).toBe('runner ALL=(ALL) NOPASSWD: /usr/bin/whoami');
    });

    it('should generate config for multiple commands', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'build .'
        },
        {
          timestamp: 'Oct  3 13:06:56',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/npm',
          args: 'install'
        }
      ];

      const result = generateSudoersConfig(commands);
      expect(result).toContain('runner ALL=(ALL) NOPASSWD: /usr/bin/docker build .');
      expect(result).toContain('runner ALL=(ALL) NOPASSWD: /usr/bin/npm install');
    });

    it('should handle command with multiple different args', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'build .'
        },
        {
          timestamp: 'Oct  3 13:06:56',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'push image'
        },
        {
          timestamp: 'Oct  3 13:06:57',
          user: 'runner',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'run -it image'
        }
      ];

      const result = generateSudoersConfig(commands);
      expect(result).toContain('runner ALL=(ALL) NOPASSWD: /usr/bin/docker');
      expect(result).toContain('# Used with:');
    });

    it('should use custom username', () => {
      const commands: SudoCommand[] = [
        {
          timestamp: 'Oct  3 13:06:55',
          user: 'testuser',
          targetUser: 'root',
          command: '/usr/bin/docker',
          args: 'build .'
        }
      ];

      const result = generateSudoersConfig(commands, 'testuser');
      expect(result).toContain('testuser ALL=(ALL) NOPASSWD:');
    });

    it('should handle empty array', () => {
      expect(generateSudoersConfig([])).toBe('');
    });
  });
});
