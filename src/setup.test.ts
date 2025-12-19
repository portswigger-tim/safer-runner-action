import * as exec from '@actions/exec';
import { setupFirewallRules, finalizeFirewallRules, setupIptablesLogging } from './setup';
import { DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER } from './config/dns-config-builder';

// Mock @actions/exec
jest.mock('@actions/exec');

describe('setup.ts - iptables configuration', () => {
  let execSpy: jest.SpyInstance;
  let capturedCommands: Array<{ program: string; args: string[] }>;

  beforeEach(() => {
    capturedCommands = [];

    // Mock exec.exec to capture all commands
    execSpy = jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
      capturedCommands.push({ program, args: args || [] });
      return 0;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('setupFirewallRules', () => {
    it('should flush OUTPUT chain first', async () => {
      await setupFirewallRules(1001, 'Test-');

      const flushCommand = capturedCommands.find(
        cmd => cmd.args.includes('iptables') && cmd.args.includes('-F') && cmd.args.includes('OUTPUT')
      );

      expect(flushCommand).toBeDefined();
      expect(capturedCommands[0]).toEqual({
        program: 'sudo',
        args: ['iptables', '-F', 'OUTPUT']
      });
    });

    it('should allow established connections', async () => {
      await setupFirewallRules(1001, 'Test-');

      const establishedCommand = capturedCommands.find(
        cmd =>
          cmd.args.includes('ESTABLISHED') &&
          cmd.args.includes('-m') &&
          cmd.args.includes('conntrack') &&
          cmd.args.includes('ACCEPT')
      );

      expect(establishedCommand).toBeDefined();
      expect(establishedCommand?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-m',
        'conntrack',
        '--ctstate',
        'ESTABLISHED',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should allow Azure metadata services', async () => {
      await setupFirewallRules(1001, 'Test-');

      const azureCommands = capturedCommands.filter(
        cmd =>
          cmd.args.includes('iptables') && (cmd.args.includes('168.63.129.16') || cmd.args.includes('169.254.169.254'))
      );

      expect(azureCommands).toHaveLength(2);
      expect(azureCommands[0].args).toContain('168.63.129.16');
      expect(azureCommands[1].args).toContain('169.254.169.254');
    });

    it('should add LOG rule for GitHub ipset matches with correct prefix', async () => {
      await setupFirewallRules(1001, 'Test-');

      const githubLogRule = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('LOG') &&
          cmd.args.includes('--match-set') &&
          cmd.args.includes('github') &&
          cmd.args.includes('--log-prefix=Test-GitHub-Allow: ')
      );

      expect(githubLogRule).toBeDefined();
      expect(githubLogRule?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-m',
        'set',
        '--match-set',
        'github',
        'dst',
        '-j',
        'LOG',
        '--log-prefix=Test-GitHub-Allow: '
      ]);
    });

    it('should add ACCEPT rule for GitHub ipset matches', async () => {
      await setupFirewallRules(1001, 'Test-');

      const githubAcceptRule = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('ACCEPT') &&
          cmd.args.includes('--match-set') &&
          cmd.args.includes('github')
      );

      expect(githubAcceptRule).toBeDefined();
      expect(githubAcceptRule?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-m',
        'set',
        '--match-set',
        'github',
        'dst',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should add LOG rule for user ipset matches with correct prefix', async () => {
      await setupFirewallRules(1001, 'Test-');

      const userLogRule = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('LOG') &&
          cmd.args.includes('--match-set') &&
          cmd.args.includes('user') &&
          cmd.args.includes('--log-prefix=Test-User-Allow: ')
      );

      expect(userLogRule).toBeDefined();
      expect(userLogRule?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-m',
        'set',
        '--match-set',
        'user',
        'dst',
        '-j',
        'LOG',
        '--log-prefix=Test-User-Allow: '
      ]);
    });

    it('should add ACCEPT rule for user ipset matches', async () => {
      await setupFirewallRules(1001, 'Test-');

      const userAcceptRule = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('ACCEPT') &&
          cmd.args.includes('--match-set') &&
          cmd.args.includes('user')
      );

      expect(userAcceptRule).toBeDefined();
      expect(userAcceptRule?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-m',
        'set',
        '--match-set',
        'user',
        'dst',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should allow DNS traffic to primary DNS server on UDP port 53 from DNS user', async () => {
      await setupFirewallRules(1001, 'Test-', DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER);

      const primaryDnsCommand = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('-d') &&
          cmd.args.includes(DEFAULT_DNS_SERVER) &&
          cmd.args.includes('--dport') &&
          cmd.args.includes('53') &&
          cmd.args.includes('udp')
      );

      expect(primaryDnsCommand).toBeDefined();
      expect(primaryDnsCommand?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-d',
        DEFAULT_DNS_SERVER,
        '-p',
        'udp',
        '--dport',
        '53',
        '-m',
        'owner',
        '--uid-owner',
        '1001',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should allow DNS traffic to secondary DNS server on UDP port 53 from DNS user', async () => {
      await setupFirewallRules(1001, 'Test-', DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER);

      const secondaryDnsCommand = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('-d') &&
          cmd.args.includes(SECONDARY_DNS_SERVER) &&
          cmd.args.includes('--dport') &&
          cmd.args.includes('53') &&
          cmd.args.includes('udp')
      );

      expect(secondaryDnsCommand).toBeDefined();
      expect(secondaryDnsCommand?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-d',
        SECONDARY_DNS_SERVER,
        '-p',
        'udp',
        '--dport',
        '53',
        '-m',
        'owner',
        '--uid-owner',
        '1001',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should support custom DNS servers', async () => {
      const customPrimary = '8.8.8.8';
      const customSecondary = '8.8.4.4';

      await setupFirewallRules(1001, 'Test-', customPrimary, customSecondary);

      const primaryCommand = capturedCommands.find(cmd => cmd.args.includes(customPrimary));
      const secondaryCommand = capturedCommands.find(cmd => cmd.args.includes(customSecondary));

      expect(primaryCommand).toBeDefined();
      expect(secondaryCommand).toBeDefined();
    });

    it('should allow ICMP traffic to primary DNS server from DNS user', async () => {
      await setupFirewallRules(1001, 'Test-', DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER);

      const primaryIcmpCommand = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('-d') &&
          cmd.args.includes(DEFAULT_DNS_SERVER) &&
          cmd.args.includes('-p') &&
          cmd.args.includes('icmp') &&
          cmd.args.includes('--uid-owner')
      );

      expect(primaryIcmpCommand).toBeDefined();
      expect(primaryIcmpCommand?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-d',
        DEFAULT_DNS_SERVER,
        '-p',
        'icmp',
        '-m',
        'owner',
        '--uid-owner',
        '1001',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should allow ICMP traffic to secondary DNS server from DNS user', async () => {
      await setupFirewallRules(1001, 'Test-', DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER);

      const secondaryIcmpCommand = capturedCommands.find(
        cmd =>
          cmd.args.includes('iptables') &&
          cmd.args.includes('-d') &&
          cmd.args.includes(SECONDARY_DNS_SERVER) &&
          cmd.args.includes('-p') &&
          cmd.args.includes('icmp') &&
          cmd.args.includes('--uid-owner')
      );

      expect(secondaryIcmpCommand).toBeDefined();
      expect(secondaryIcmpCommand?.args).toEqual([
        'iptables',
        '-A',
        'OUTPUT',
        '-o',
        'eth0',
        '-d',
        SECONDARY_DNS_SERVER,
        '-p',
        'icmp',
        '-m',
        'owner',
        '--uid-owner',
        '1001',
        '-j',
        'ACCEPT'
      ]);
    });

    it('should not add ICMP rule for secondary DNS when secondary DNS is disabled', async () => {
      await setupFirewallRules(1001, 'Test-', DEFAULT_DNS_SERVER, '');

      const secondaryIcmpCommands = capturedCommands.filter(
        cmd => cmd.args.includes('icmp') && cmd.args.includes(SECONDARY_DNS_SERVER)
      );

      // Should only have ICMP rule for primary DNS server
      const icmpCommands = capturedCommands.filter(cmd => cmd.args.includes('icmp'));
      expect(icmpCommands).toHaveLength(1);
      expect(icmpCommands[0].args).toContain(DEFAULT_DNS_SERVER);
      expect(secondaryIcmpCommands).toHaveLength(0);
    });

    it('should allow ICMP with custom DNS servers', async () => {
      const customPrimary = '8.8.8.8';
      const customSecondary = '8.8.4.4';

      await setupFirewallRules(1001, 'Test-', customPrimary, customSecondary);

      const primaryIcmpCommand = capturedCommands.find(
        cmd => cmd.args.includes('icmp') && cmd.args.includes(customPrimary)
      );
      const secondaryIcmpCommand = capturedCommands.find(
        cmd => cmd.args.includes('icmp') && cmd.args.includes(customSecondary)
      );

      expect(primaryIcmpCommand).toBeDefined();
      expect(secondaryIcmpCommand).toBeDefined();
      expect(primaryIcmpCommand?.args).toContain('ACCEPT');
      expect(secondaryIcmpCommand?.args).toContain('ACCEPT');
    });

    it('should execute commands in correct order', async () => {
      await setupFirewallRules(1001, 'Test-');

      // Verify flush comes first
      expect(capturedCommands[0].args).toContain('-F');

      // Verify established connections rule comes early
      const establishedIndex = capturedCommands.findIndex(cmd => cmd.args.includes('ESTABLISHED'));

      // Verify ipset matching rules come after basic setup
      const useGithubIndex = capturedCommands.findIndex(
        cmd => cmd.args.includes('iptables') && cmd.args.includes('--match-set') && cmd.args.includes('github')
      );

      expect(establishedIndex).toBeGreaterThan(0);
      expect(useGithubIndex).toBeGreaterThan(establishedIndex);
    });
  });

  describe('finalizeFirewallRules', () => {
    describe('enforce mode', () => {
      it('should add LOG rule for dropped traffic with correct prefix', async () => {
        await finalizeFirewallRules('enforce', 'Main-');

        const logCommand = capturedCommands.find(
          cmd => cmd.args.includes('LOG') && cmd.args.includes('--log-prefix=Main-Drop-Enforce: ')
        );

        expect(logCommand).toBeDefined();
        expect(logCommand?.args).toEqual([
          'iptables',
          '-A',
          'OUTPUT',
          '-o',
          'eth0',
          '-j',
          'LOG',
          '--log-prefix=Main-Drop-Enforce: '
        ]);
      });

      it('should add DROP rule as final rule', async () => {
        await finalizeFirewallRules('enforce', 'Main-');

        const dropCommand = capturedCommands.find(
          cmd => cmd.args.includes('iptables') && cmd.args.includes('DROP') && cmd.args.includes('eth0')
        );

        expect(dropCommand).toBeDefined();
        expect(dropCommand?.args).toEqual(['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'DROP']);
      });

      it('should execute LOG before DROP', async () => {
        await finalizeFirewallRules('enforce', 'Main-');

        const logIndex = capturedCommands.findIndex(cmd => cmd.args.includes('LOG'));
        const dropIndex = capturedCommands.findIndex(cmd => cmd.args.includes('DROP'));

        expect(logIndex).toBeLessThan(dropIndex);
      });

      it('should scope rules to eth0 interface', async () => {
        await finalizeFirewallRules('enforce', 'Main-');

        const eth0Commands = capturedCommands.filter(cmd => cmd.args.includes('eth0'));

        expect(eth0Commands).toHaveLength(2); // LOG and DROP
        eth0Commands.forEach(cmd => {
          expect(cmd.args).toContain('-o');
          expect(cmd.args).toContain('eth0');
        });
      });
    });

    describe('analyze mode', () => {
      it('should add LOG rule for analyzed traffic with correct prefix', async () => {
        await finalizeFirewallRules('analyze', 'Pre-');

        const logCommand = capturedCommands.find(
          cmd => cmd.args.includes('LOG') && cmd.args.includes('--log-prefix=Pre-Allow-Analyze: ')
        );

        expect(logCommand).toBeDefined();
        expect(logCommand?.args).toEqual([
          'iptables',
          '-A',
          'OUTPUT',
          '-o',
          'eth0',
          '-j',
          'LOG',
          '--log-prefix=Pre-Allow-Analyze: '
        ]);
      });

      it('should add ACCEPT rule as final rule', async () => {
        await finalizeFirewallRules('analyze', 'Pre-');

        const acceptCommand = capturedCommands.find(
          cmd => cmd.args.includes('iptables') && cmd.args.includes('ACCEPT') && cmd.args.includes('eth0')
        );

        expect(acceptCommand).toBeDefined();
        expect(acceptCommand?.args).toEqual(['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'ACCEPT']);
      });

      it('should execute LOG before ACCEPT', async () => {
        await finalizeFirewallRules('analyze', 'Pre-');

        const logIndex = capturedCommands.findIndex(cmd => cmd.args.includes('LOG'));
        const acceptIndex = capturedCommands.findIndex(cmd => cmd.args.includes('ACCEPT'));

        expect(logIndex).toBeLessThan(acceptIndex);
      });

      it('should NOT add DROP rule in analyze mode', async () => {
        await finalizeFirewallRules('analyze', 'Pre-');

        const dropCommand = capturedCommands.find(cmd => cmd.args.includes('DROP'));

        expect(dropCommand).toBeUndefined();
      });
    });

    describe('log prefix handling', () => {
      it('should use provided log prefix', async () => {
        await finalizeFirewallRules('enforce', 'Custom-');

        const logCommand = capturedCommands.find(cmd => cmd.args.includes('--log-prefix=Custom-Drop-Enforce: '));

        expect(logCommand).toBeDefined();
      });

      it('should handle empty log prefix', async () => {
        await finalizeFirewallRules('enforce', '');

        const logCommand = capturedCommands.find(cmd => cmd.args.includes('--log-prefix=Drop-Enforce: '));

        expect(logCommand).toBeDefined();
      });
    });
  });

  describe('setupIptablesLogging', () => {
    it('should create rsyslog configuration file with correct filters', async () => {
      await setupIptablesLogging('/var/log/test.log', ['Test-GitHub', 'Test-User'], 'main');

      const teeCommand = capturedCommands.find(cmd => cmd.args.includes('tee') && cmd.args[1].includes('rsyslog'));

      expect(teeCommand).toBeDefined();
      expect(teeCommand?.args[1]).toBe('/etc/rsyslog.d/10-iptables-safer-runner-main.conf');
    });

    it('should filter by programname=kernel', async () => {
      const mockExec = execSpy.mockImplementation(async (program, args, options) => {
        if (args && args[0] === 'tee' && options?.input) {
          const config = options.input.toString();
          expect(config).toContain("$programname == 'kernel'");
        }
        return 0;
      });

      await setupIptablesLogging('/var/log/test.log', ['Test-Prefix'], 'main');

      expect(mockExec).toHaveBeenCalled();
    });

    it('should include all log prefixes in filter', async () => {
      const mockExec = execSpy.mockImplementation(async (program, args, options) => {
        if (args && args[0] === 'tee' && options?.input) {
          const config = options.input.toString();
          expect(config).toContain("['Prefix1', 'Prefix2', 'Prefix3']");
        }
        return 0;
      });

      await setupIptablesLogging('/var/log/test.log', ['Prefix1', 'Prefix2', 'Prefix3'], 'test');

      expect(mockExec).toHaveBeenCalled();
    });

    it('should create log file with correct permissions', async () => {
      await setupIptablesLogging('/var/log/test.log', ['Test-Prefix'], 'main');

      const touchCommand = capturedCommands.find(cmd => cmd.args.includes('touch'));
      const chownCommand = capturedCommands.find(cmd => cmd.args.includes('chown'));
      const chmodCommand = capturedCommands.find(cmd => cmd.args.includes('chmod'));

      expect(touchCommand?.args).toEqual(['touch', '/var/log/test.log']);
      expect(chownCommand?.args).toEqual(['chown', 'syslog:adm', '/var/log/test.log']);
      expect(chmodCommand?.args).toEqual(['chmod', '644', '/var/log/test.log']);
    });

    it('should restart rsyslog service', async () => {
      await setupIptablesLogging('/var/log/test.log', ['Test-Prefix'], 'main');

      const restartCommand = capturedCommands.find(
        cmd => cmd.args.includes('systemctl') && cmd.args.includes('restart')
      );

      expect(restartCommand).toBeDefined();
      expect(restartCommand?.args).toEqual(['systemctl', 'restart', 'rsyslog']);
    });

    it('should use different config file names for different suffixes', async () => {
      await setupIptablesLogging('/var/log/pre.log', ['Pre-'], 'pre');
      const preConfig = capturedCommands.find(cmd => cmd.args[1]?.includes('pre.conf'));

      capturedCommands = [];

      await setupIptablesLogging('/var/log/main.log', ['Main-'], 'main');
      const mainConfig = capturedCommands.find(cmd => cmd.args[1]?.includes('main.conf'));

      expect(preConfig?.args[1]).toContain('pre.conf');
      expect(mainConfig?.args[1]).toContain('main.conf');
      expect(preConfig?.args[1]).not.toBe(mainConfig?.args[1]);
    });

    it('should use default config name when no suffix provided', async () => {
      await setupIptablesLogging('/var/log/test.log', ['Test-'], '');

      const configCommand = capturedCommands.find(cmd => cmd.args[1]?.includes('rsyslog'));

      expect(configCommand?.args[1]).toBe('/etc/rsyslog.d/10-iptables-safer-runner.conf');
    });
  });

  describe('Integration scenarios', () => {
    it('should set up complete firewall in enforce mode', async () => {
      await setupFirewallRules(1001, 'Main-');
      await finalizeFirewallRules('enforce', 'Main-');

      // Verify key components exist
      expect(capturedCommands.find(cmd => cmd.args.includes('-F'))).toBeDefined(); // Flush
      expect(capturedCommands.find(cmd => cmd.args.includes('--match-set'))).toBeDefined(); // ipset matching
      expect(capturedCommands.find(cmd => cmd.args.includes('DROP'))).toBeDefined(); // Final DROP
      expect(capturedCommands.find(cmd => cmd.args.includes('--log-prefix=Main-Drop-Enforce: '))).toBeDefined(); // Enforce logging
    });

    it('should set up complete firewall in analyze mode', async () => {
      await setupFirewallRules(1001, 'Pre-');
      await finalizeFirewallRules('analyze', 'Pre-');

      // Verify key components exist
      expect(capturedCommands.find(cmd => cmd.args.includes('-F'))).toBeDefined(); // Flush
      expect(capturedCommands.find(cmd => cmd.args.includes('--match-set'))).toBeDefined(); // ipset matching
      expect(capturedCommands.find(cmd => cmd.args.includes('ACCEPT') && cmd.args.includes('eth0'))).toBeDefined(); // Final ACCEPT
      expect(capturedCommands.find(cmd => cmd.args.includes('--log-prefix=Pre-Allow-Analyze: '))).toBeDefined(); // Analyze logging

      // Should NOT have DROP
      expect(capturedCommands.find(cmd => cmd.args.includes('DROP'))).toBeUndefined();
    });
  });
});
