/**
 * DNS health check module
 *
 * Verifies DNS services (systemd-resolved, dnsmasq) are responsive
 * after restart. Uses multi-layer verification with retry logic.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

export interface DnsHealthCheckConfig {
  maxWaitMs: number;
  initialDelayMs: number;
  maxDelayMs: number;
  testDomains: string[];
  verbose?: boolean;
}

export const DEFAULT_HEALTH_CHECK_CONFIG: DnsHealthCheckConfig = {
  maxWaitMs: 30000,
  initialDelayMs: 100,
  maxDelayMs: 2000,
  testDomains: ['github.com', 'actions.githubusercontent.com'],
  verbose: false
};

export interface DnsHealthCheckResult {
  healthy: boolean;
  durationMs: number;
  checks: {
    systemdResolved: boolean;
    dnsmasq: boolean;
    dnsResolution: boolean;
  };
  errors: string[];
}

/**
 * Check if systemd-resolved is active
 */
async function checkSystemdResolvedStatus(): Promise<boolean> {
  try {
    let output = '';
    await exec.exec('sudo', ['systemctl', 'is-active', 'systemd-resolved'], {
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        }
      }
    });
    return output.trim() === 'active';
  } catch {
    core.debug('systemd-resolved is not active');
    return false;
  }
}

/**
 * Check if dnsmasq is active
 */
async function checkDnsmasqStatus(): Promise<boolean> {
  try {
    let output = '';
    await exec.exec('sudo', ['systemctl', 'is-active', 'dnsmasq'], {
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        }
      }
    });
    return output.trim() === 'active';
  } catch {
    core.debug('dnsmasq is not active');
    return false;
  }
}

/**
 * Check if dnsmasq is listening on port 53
 */
async function checkDnsmasqPort(): Promise<boolean> {
  try {
    let output = '';
    await exec.exec('ss', ['-lun'], {
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        }
      }
    });
    // Check if 127.0.0.1:53 or 0.0.0.0:53 is in the output
    return output.includes('127.0.0.1:53') || output.includes('0.0.0.0:53');
  } catch {
    core.debug('Failed to check dnsmasq port binding');
    return false;
  }
}

/**
 * Test DNS resolution for a specific domain
 */
async function testDnsResolution(domain: string, server: string = '127.0.0.1'): Promise<boolean> {
  try {
    let output = '';
    const exitCode = await exec.exec('dig', ['+short', '+time=2', '+tries=1', `@${server}`, domain, 'A'], {
      silent: true,
      ignoreReturnCode: true,
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        }
      }
    });

    // dig returns 0 on success, non-zero on failure
    // Output should be non-empty and contain an IP address
    if (exitCode !== 0) {
      return false;
    }

    const trimmed = output.trim();
    // Check if output looks like an IP address (simple validation)
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    return trimmed.length > 0 && trimmed.split('\n').some(line => ipPattern.test(line.trim()));
  } catch {
    core.debug(`DNS resolution test failed for ${domain}`);
    return false;
  }
}

/**
 * Sleep with exponential backoff and jitter
 */
async function sleepWithBackoff(attempt: number, config: DnsHealthCheckConfig): Promise<void> {
  // Calculate exponential backoff: initialDelay * 2^attempt, capped at maxDelay
  const exponentialDelay = Math.min(config.initialDelayMs * Math.pow(2, attempt), config.maxDelayMs);

  // Add ±20% jitter to prevent thundering herd
  const jitter = exponentialDelay * 0.2 * (Math.random() * 2 - 1);
  const delayMs = Math.max(0, exponentialDelay + jitter);

  if (config.verbose) {
    core.debug(`Waiting ${delayMs.toFixed(0)}ms before retry (attempt ${attempt + 1})`);
  }

  await new Promise(resolve => setTimeout(resolve, delayMs));
}

/**
 * Check if we've exceeded the maximum wait time
 */
function hasExceededMaxWait(startTime: number, config: DnsHealthCheckConfig): boolean {
  return Date.now() - startTime > config.maxWaitMs;
}

/**
 * Performs comprehensive DNS health check with retry logic
 *
 * Verifies three layers:
 * 1. Service status - systemd-resolved and dnsmasq are active
 * 2. Port availability - dnsmasq listening on 127.0.0.1:53
 * 3. DNS resolution - Actual queries succeed for test domains
 *
 * Uses exponential backoff with jitter for retries. Will continue
 * retrying until maxWaitMs is exceeded.
 *
 * @param config - Optional configuration (uses defaults if not provided)
 * @returns Detailed health check result with status and errors
 *
 * @example
 * ```typescript
 * const result = await checkDnsHealth();
 * if (!result.healthy) {
 *   console.error(`DNS check failed after ${result.durationMs}ms`);
 *   result.errors.forEach(err => console.error(err));
 * }
 * ```
 */
export async function checkDnsHealth(
  config: DnsHealthCheckConfig = DEFAULT_HEALTH_CHECK_CONFIG
): Promise<DnsHealthCheckResult> {
  const startTime = Date.now();
  const result: DnsHealthCheckResult = {
    healthy: false,
    durationMs: 0,
    checks: {
      systemdResolved: false,
      dnsmasq: false,
      dnsResolution: false
    },
    errors: []
  };

  let attempt = 0;

  while (!hasExceededMaxWait(startTime, config)) {
    const attemptStartTime = Date.now();

    // Layer 1: Check systemd-resolved status
    result.checks.systemdResolved = await checkSystemdResolvedStatus();
    if (!result.checks.systemdResolved) {
      const error = `Attempt ${attempt + 1} (${Date.now() - startTime}ms): systemd-resolved not active`;
      result.errors.push(error);
      if (config.verbose) {
        core.debug(error);
      }
      await sleepWithBackoff(attempt, config);
      attempt++;
      continue;
    }

    // Layer 2: Check dnsmasq status
    result.checks.dnsmasq = await checkDnsmasqStatus();
    if (!result.checks.dnsmasq) {
      const error = `Attempt ${attempt + 1} (${Date.now() - startTime}ms): dnsmasq not active`;
      result.errors.push(error);
      if (config.verbose) {
        core.debug(error);
      }
      await sleepWithBackoff(attempt, config);
      attempt++;
      continue;
    }

    // Layer 3: Check dnsmasq port binding
    const portBound = await checkDnsmasqPort();
    if (!portBound) {
      const error = `Attempt ${attempt + 1} (${Date.now() - startTime}ms): dnsmasq not listening on port 53`;
      result.errors.push(error);
      if (config.verbose) {
        core.debug(error);
      }
      await sleepWithBackoff(attempt, config);
      attempt++;
      continue;
    }

    // Layer 4: Test DNS resolution (at least one domain must succeed)
    let resolvedAny = false;
    for (const domain of config.testDomains) {
      if (await testDnsResolution(domain)) {
        resolvedAny = true;
        break;
      }
    }

    if (!resolvedAny) {
      const error = `Attempt ${attempt + 1} (${Date.now() - startTime}ms): DNS resolution failed for all test domains`;
      result.errors.push(error);
      if (config.verbose) {
        core.debug(error);
      }
      await sleepWithBackoff(attempt, config);
      attempt++;
      continue;
    }

    // All checks passed!
    result.checks.dnsResolution = true;
    result.healthy = true;
    result.durationMs = Date.now() - startTime;
    return result;
  }

  // Timeout exceeded
  result.durationMs = Date.now() - startTime;
  result.errors.push(`DNS health check timed out after ${result.durationMs}ms (${attempt} attempts)`);

  return result;
}

/**
 * Performs DNS health check and throws on failure
 *
 * This is a convenience wrapper around checkDnsHealth() that throws
 * an error with a detailed message if the health check fails.
 *
 * @param config - Optional configuration (uses defaults if not provided)
 * @throws Error with detailed failure information if health check fails
 *
 * @example
 * ```typescript
 * try {
 *   await ensureDnsHealthy();
 *   console.log('DNS is healthy!');
 * } catch (error) {
 *   console.error('DNS health check failed:', error.message);
 * }
 * ```
 */
export async function ensureDnsHealthy(config: DnsHealthCheckConfig = DEFAULT_HEALTH_CHECK_CONFIG): Promise<void> {
  const result = await checkDnsHealth(config);

  if (!result.healthy) {
    // Build detailed error message
    const checkResults = [
      `  ${result.checks.systemdResolved ? '✅' : '❌'} systemd-resolved: ${result.checks.systemdResolved ? 'ACTIVE' : 'INACTIVE'}`,
      `  ${result.checks.dnsmasq ? '✅' : '❌'} dnsmasq: ${result.checks.dnsmasq ? 'ACTIVE' : 'INACTIVE'}`,
      `  ${result.checks.dnsResolution ? '✅' : '❌'} DNS resolution: ${result.checks.dnsResolution ? 'WORKING' : 'FAILED'}`
    ].join('\n');

    const errorHistory = result.errors
      .slice(0, 10)
      .map(err => `  ${err}`)
      .join('\n');
    const moreErrors = result.errors.length > 10 ? `  ... and ${result.errors.length - 10} more errors\n` : '';

    const debuggingSteps = `
Debugging Steps:
  1. Check dnsmasq status:
     sudo systemctl status dnsmasq

  2. Test DNS manually:
     dig @127.0.0.1 github.com

  3. Check logs:
     sudo journalctl -u dnsmasq -n 50
     cat /var/log/safer-runner/main-dns.log

  4. Verify network connectivity:
     ping 9.9.9.9
`;

    const errorMessage = `
DNS health check failed after ${result.durationMs}ms (${result.errors.length} attempts):

Check Results:
${checkResults}

Error History:
${errorHistory}
${moreErrors}
${debuggingSteps}`.trim();

    throw new Error(errorMessage);
  }
}
