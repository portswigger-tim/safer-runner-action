import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { checkDnsHealth, ensureDnsHealthy, DEFAULT_HEALTH_CHECK_CONFIG, DnsHealthCheckConfig } from './dns-health';

jest.mock('@actions/core');
jest.mock('@actions/exec');

describe('DNS Health Check', () => {
  let mockExec: jest.MockedFunction<typeof exec.exec>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
  });

  describe('Happy Path Tests', () => {
    it('should pass when all services healthy on first attempt', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      const result = await checkDnsHealth();

      expect(result.healthy).toBe(true);
      expect(result.checks.systemdResolved).toBe(true);
      expect(result.checks.dnsmasq).toBe(true);
      expect(result.checks.dnsResolution).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('should test multiple domains and succeed if any passes', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async () => {
          return 1; // First domain fails
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('185.199.108.153\n'));
          return 0;
        });

      const result = await checkDnsHealth();

      expect(result.healthy).toBe(true);
      expect(result.checks.dnsResolution).toBe(true);
    });

    it('should accept 0.0.0.0:53 as valid port binding', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      const result = await checkDnsHealth();

      expect(result.healthy).toBe(true);
    });
  });

  describe('Failure Tests', () => {
    it('should fail if systemd-resolved never becomes active', async () => {
      mockExec.mockImplementation(async (_cmd, args, options) => {
        if (args?.[0] === 'is-active' && args?.[1] === 'systemd-resolved') {
          options?.listeners?.stdout?.(Buffer.from('inactive\n'));
          return 3;
        }
        return 0;
      });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(false);
      expect(result.checks.systemdResolved).toBe(false);
    });

    it('should fail if all test domains fail resolution', async () => {
      mockExec.mockImplementation(async (cmd, args, options) => {
        if (args?.[0] === 'is-active') {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        }
        if (cmd === 'ss') {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        }
        if (cmd === 'dig') {
          return 1; // DNS fails
        }
        return 0;
      });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(false);
      expect(result.checks.dnsResolution).toBe(false);
    });
  });

  describe('Edge Case Tests', () => {
    it('should handle dig returning empty output', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from(''));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(true);
    });

    it('should handle dig returning non-IP output', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('SERVFAIL\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(true);
    });

    it('should handle dig throwing exception', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (cmd) => {
          if (cmd === 'dig') {
            throw new Error('dig: command not found');
          }
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(true);
    });

    it('should handle systemctl throwing exception', async () => {
      mockExec.mockImplementation(async (_cmd, args) => {
        if (args?.[0] === 'is-active') {
          throw new Error('systemctl: command not found');
        }
        return 0;
      });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const result = await checkDnsHealth(config);

      expect(result.healthy).toBe(false);
      expect(result.checks.systemdResolved).toBe(false);
    });
  });

  describe('ensureDnsHealthy Tests', () => {
    it('should not throw when DNS is healthy', async () => {
      mockExec
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('active\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n'));
          return 0;
        })
        .mockImplementationOnce(async (_cmd, _args, options) => {
          options?.listeners?.stdout?.(Buffer.from('140.82.121.4\n'));
          return 0;
        });

      await expect(ensureDnsHealthy()).resolves.not.toThrow();
    });

    it('should throw with detailed error message when DNS is unhealthy', async () => {
      mockExec.mockImplementation(async (_cmd, args, options) => {
        if (args?.[0] === 'is-active') {
          options?.listeners?.stdout?.(Buffer.from('inactive\n'));
          return 3;
        }
        return 0;
      });

      const config: DnsHealthCheckConfig = {
        ...DEFAULT_HEALTH_CHECK_CONFIG,
        maxWaitMs: 500,
        initialDelayMs: 1,
        maxDelayMs: 5
      };

      const ensurePromise = ensureDnsHealthy(config);

      await expect(ensurePromise).rejects.toThrow(/DNS health check failed/);
      await expect(ensurePromise).rejects.toThrow(/Check Results:/);
      await expect(ensurePromise).rejects.toThrow(/Error History:/);
      await expect(ensurePromise).rejects.toThrow(/Debugging Steps:/);
    });
  });
});
