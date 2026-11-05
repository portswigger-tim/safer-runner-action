import * as exec from '@actions/exec';
import { setupIptablesLogging } from './setup';

// Mock @actions/exec
jest.mock('@actions/exec');
jest.mock('@actions/core');

describe('setup.ts', () => {
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
});
