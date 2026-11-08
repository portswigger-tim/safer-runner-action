/**
 * System Integrity Validation for Safer Runner Action
 *
 * This module provides SHA256 checksum-based validation to ensure that critical
 * security configurations (Corefile, resolv.conf, iptables rules) are not
 * tampered with between setup completion and action end.
 *
 * Validation Flow:
 * 1. Setup completes (main.ts) → Capture post-setup baseline checksums
 * 2. User workflow runs (potentially malicious code could run here)
 * 3. Post-action (post.ts) → Verify current state matches baseline
 *
 * This detects tampering by external processes during the action run, ensuring
 * that DNS filtering and firewall rules maintain their integrity.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import { VALIDATION_STATE_FILE } from '../constants';
import type { SudoLogging } from '../services/sudo';

interface FileChecksum {
  path: string;
  checksum: string;
  timestamp: string;
}

interface IptablesRuleChecksum {
  chain: string;
  rules: string;
  checksum: string;
  timestamp: string;
}

interface ValidationState {
  files: FileChecksum[];
  iptablesRules: IptablesRuleChecksum[];
  timestamp: string;
}

/**
 * iptables chains to monitor for tampering: the built-in hooks plus the chains the v2
 * action owns. `table:CHAIN` selects a non-filter table.
 */
export const IPTABLES_CHAINS = [
  'INPUT',
  'OUTPUT',
  'FORWARD',
  'SAFER_RUNNER_OUT',
  'nat:OUTPUT',
  'nat:SAFER_RUNNER_NAT',
  // container egress (P2); absent when Docker isn't running (capture skips missing chains)
  'DOCKER-USER',
  'SAFER_RUNNER_CFWD',
  'nat:SAFER_RUNNER_CNAT'
] as const;

/** `iptables` arguments that list one chain spec (`CHAIN` or `table:CHAIN`). */
export function iptablesListArgs(spec: string): string[] {
  const [table, chain] = spec.includes(':') ? spec.split(':') : ['filter', spec];
  return [...(table === 'filter' ? [] : ['-t', table]), '-L', chain, '-n', '--line-numbers'];
}

/**
 * Security configuration files monitored for tampering
 * The sudo logging config file is appended at runtime (it depends on the sudo implementation)
 */
export const CRITICAL_FILES = [
  '/etc/safer-runner/Corefile',
  '/etc/resolv.conf',
  '/etc/systemd/resolved.conf.d/no-stub.conf',
  '/etc/safer-runner/policy.json',
  '/opt/safer-runner/proxy/policy.py',
  '/opt/safer-runner/proxy/policy_core.py'
] as const;

/** sudo commands that store the baseline (exact; also filtered from the sudo report). */
export const BASELINE_WRITE_COMMANDS: string[][] = [
  ['touch', VALIDATION_STATE_FILE],
  ['chown', 'root:root', VALIDATION_STATE_FILE],
  ['chmod', '0600', VALIDATION_STATE_FILE],
  ['tee', VALIDATION_STATE_FILE]
];

declare const baselineCaptured: unique symbol;
/**
 * The baseline is stored (root-owned 0600), with sudo logging already on. Minted only by
 * capturePostSetupBaseline(); restricting sudo takes it, so it comes after.
 */
export type BaselineCaptured = { readonly [baselineCaptured]: true };

export class SystemValidator {
  private criticalFiles: string[];

  constructor(criticalFiles?: string[]) {
    // Allow injection of critical files for testing
    this.criticalFiles = criticalFiles || [...CRITICAL_FILES];
  }

  /**
   * Capture post-setup baseline checksums after all configuration is complete
   * This baseline will be verified in the post-action to detect tampering
   */
  async capturePostSetupBaseline(_logging: SudoLogging): Promise<BaselineCaptured> {
    core.info('📋 Capturing post-setup security baseline...');

    const state: ValidationState = {
      files: [],
      iptablesRules: [],
      timestamp: new Date().toISOString()
    };

    // Capture file checksums
    for (const filePath of this.criticalFiles) {
      try {
        const checksum = await this.calculateFileChecksum(filePath);
        if (checksum) {
          state.files.push({
            path: filePath,
            checksum,
            timestamp: new Date().toISOString()
          });
          core.info(`✅ Captured baseline checksum for ${filePath}: ${checksum.substring(0, 16)}...`);
        } else {
          core.error(`❌ Expected file ${filePath} not found after setup - this indicates a setup failure`);
          throw new Error(`Critical file ${filePath} missing after setup completion`);
        }
      } catch (error) {
        core.error(`❌ Failed to capture baseline for ${filePath}: ${error}`);
        throw error;
      }
    }

    // Capture iptables state
    await this.captureIptablesState(state);

    // Save validation state
    await this.writeBaseline(JSON.stringify(state, null, 2));
    core.info(`💾 Security baseline saved to ${VALIDATION_STATE_FILE}`);
    return Object.freeze({}) as BaselineCaptured;
  }

  /**
   * Store the baseline root-owned (0600) under /etc/safer-runner, never in a runner-writable
   * location: the runner could otherwise rewrite it to match a tampered state (review M1).
   * Runs during setup, before sudo is restricted.
   */
  protected async writeBaseline(json: string): Promise<void> {
    // Each command is listed in INTERNAL_SUDO_COMMANDS (sudo logging is already on here).
    // Mode and owner are set before the content goes in. ETC_DIR is root-owned (writePolicy).
    for (const args of BASELINE_WRITE_COMMANDS) {
      await exec.exec('sudo', args, args[0] === 'tee' ? { input: Buffer.from(json), silent: true } : {});
    }
  }

  /**
   * Read the baseline back with the same privilege path as the checked files (an exact
   * `sudo cat` allowlist entry, see getValidationSudoCommands). Null if it is missing.
   */
  protected async readBaseline(): Promise<string | null> {
    let out = '';
    const rc = await exec.exec('sudo', ['-n', 'cat', VALIDATION_STATE_FILE], {
      silent: true,
      ignoreReturnCode: true,
      listeners: { stdout: data => (out += data.toString()) }
    });
    return rc === 0 ? out : null;
  }

  /**
   * Verify current state against post-setup baseline to detect tampering
   */
  async verifyAgainstBaseline(): Promise<boolean> {
    core.info('🔍 Verifying system integrity against baseline...');

    const baseline = await this.readBaseline();
    if (baseline === null) {
      core.warning('⚠️  No baseline state file found - cannot verify integrity');
      return false;
    }

    let baselineState: ValidationState;
    try {
      baselineState = JSON.parse(baseline);
    } catch (error) {
      core.error(`❌ Failed to read baseline state: ${error}`);
      return false;
    }

    let allValid = true;

    // Verify file checksums against baseline
    for (const fileState of baselineState.files) {
      try {
        const currentChecksum = await this.calculateFileChecksum(fileState.path);

        if (!currentChecksum) {
          core.error(`❌ Critical file ${fileState.path} was deleted after setup!`);
          allValid = false;
          continue;
        }

        if (currentChecksum === fileState.checksum) {
          core.info(`✅ File ${fileState.path} integrity verified`);
        } else {
          core.error(`❌ File ${fileState.path} has been tampered with after setup!`);
          allValid = false;
        }
      } catch (error) {
        core.error(`❌ Failed to verify ${fileState.path}: ${error}`);
        allValid = false;
      }
    }

    // Verify iptables rules against baseline
    const currentIptablesState = await this.getCurrentIptablesState();
    for (const ruleState of baselineState.iptablesRules) {
      const currentRule = currentIptablesState.find(r => r.chain === ruleState.chain);

      if (!currentRule) {
        core.error(`❌ iptables chain ${ruleState.chain} is missing!`);
        allValid = false;
        continue;
      }

      if (currentRule.checksum === ruleState.checksum) {
        core.info(`✅ iptables chain ${ruleState.chain} integrity verified`);
      } else {
        core.error(`❌ iptables chain ${ruleState.chain} has been tampered with after setup!`);
        allValid = false;
      }
    }

    if (allValid) {
      core.info('✅ All validation checks passed - no tampering detected');
    }

    return allValid;
  }

  /**
   * Calculate SHA256 checksum of a file
   * Uses sudo to read files with restricted permissions (e.g. 0600 root-owned config)
   */
  protected async calculateFileChecksum(filePath: string): Promise<string | null> {
    try {
      let fileContent = '';
      const exitCode = await exec.exec('sudo', ['cat', filePath], {
        silent: true,
        listeners: {
          stdout: data => {
            fileContent += data.toString();
          }
        },
        ignoreReturnCode: true
      });

      // Exit code 1 typically means file not found
      if (exitCode !== 0) {
        return null;
      }

      return crypto.createHash('sha256').update(fileContent).digest('hex');
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return null; // File doesn't exist
      }
      throw error;
    }
  }

  /**
   * Calculate checksum of iptables rules content
   */
  private calculateRulesChecksum(rules: string): string {
    return crypto.createHash('sha256').update(rules).digest('hex');
  }

  /**
   * Get iptables rules output for a specific chain
   * Extracted for testability - can be overridden in tests
   */
  protected async getIptablesChainOutput(chain: string): Promise<string> {
    let rulesOutput = '';
    await exec.exec('sudo', ['iptables', ...iptablesListArgs(chain)], {
      silent: true,
      listeners: {
        stdout: data => {
          rulesOutput += data.toString();
        }
      },
      ignoreReturnCode: true
    });
    return rulesOutput;
  }

  /**
   * Capture current iptables state
   */
  private async captureIptablesState(state: ValidationState): Promise<void> {
    for (const chain of IPTABLES_CHAINS) {
      try {
        const rulesOutput = await this.getIptablesChainOutput(chain);

        const checksum = this.calculateRulesChecksum(rulesOutput);
        state.iptablesRules.push({
          chain,
          rules: rulesOutput,
          checksum,
          timestamp: new Date().toISOString()
        });

        core.info(`✅ Captured iptables ${chain} chain: ${checksum.substring(0, 16)}...`);
      } catch (error) {
        core.warning(`⚠️  Failed to capture iptables ${chain} chain: ${error}`);
      }
    }
  }

  /**
   * Get current iptables state for comparison
   */
  private async getCurrentIptablesState(): Promise<IptablesRuleChecksum[]> {
    const currentState: IptablesRuleChecksum[] = [];

    for (const chain of IPTABLES_CHAINS) {
      try {
        const rulesOutput = await this.getIptablesChainOutput(chain);

        const checksum = this.calculateRulesChecksum(rulesOutput);
        currentState.push({
          chain,
          rules: rulesOutput,
          checksum,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        core.warning(`⚠️  Failed to get current iptables ${chain} chain: ${error}`);
      }
    }

    return currentState;
  }

  /**
   * Generate detailed validation report
   */
  async generateValidationReport(): Promise<string> {
    const { status, body } = await this.generateValidationDetails();
    // Wrap in collapsible section with warning emoji if tampering detected
    const titleEmoji = status === 'tampered' ? '⚠️ ' : '';
    return `<details>\n<summary><h2>${titleEmoji}Config File Tamper Detection</h2></summary>\n\n${body}</details>\n\n`;
  }

  /** The checksum tables and an overall result, for embedding in the job summary. */
  async generateValidationDetails(): Promise<{ status: 'verified' | 'tampered' | 'unavailable'; body: string }> {
    const baseline = await this.readBaseline();
    if (baseline === null) {
      return { status: 'unavailable', body: 'No validation data available.\n\n' };
    }

    // Check if tampering occurred to add warning emoji
    let tamperingDetected = false;
    let reportContent = '';

    try {
      const state: ValidationState = JSON.parse(baseline);

      reportContent += `**Baseline:** ${state.timestamp}\n`;
      reportContent += `**Verified:** ${new Date().toISOString()}\n\n`;

      // File integrity report
      reportContent += '**Configuration Files**\n\n';
      reportContent += '| File | Status | Checksum Comparison |\n';
      reportContent += '|------|--------|--------------------|\n';

      for (const file of state.files) {
        const currentChecksum = await this.calculateFileChecksum(file.path);
        let status = 'Unknown';
        let displayChecksum = file.checksum.substring(0, 16);

        if (!currentChecksum) {
          status = '🚨 DELETED';
          displayChecksum = `${displayChecksum} -> MISSING`;
          tamperingDetected = true;
        } else if (currentChecksum === file.checksum) {
          status = 'VERIFIED';
          displayChecksum = `${displayChecksum} (unchanged)`;
        } else {
          status = '⚠️ TAMPERED';
          displayChecksum = `${displayChecksum} -> ${currentChecksum.substring(0, 16)}`;
          tamperingDetected = true;
        }

        reportContent += `| ${file.path} | ${status} | ${displayChecksum} |\n`;
      }

      // iptables integrity report
      reportContent += '\n**Firewall Rules**\n\n';
      reportContent += '| Chain | Status | Checksum Comparison |\n';
      reportContent += '|-------|--------|--------------|\n';

      const currentIptablesState = await this.getCurrentIptablesState();
      for (const rule of state.iptablesRules) {
        const currentRule = currentIptablesState.find(r => r.chain === rule.chain);
        let status = 'Unknown';
        let displayChecksum = rule.checksum.substring(0, 16);

        if (!currentRule) {
          status = '🚨 MISSING';
          displayChecksum = `${displayChecksum} -> MISSING`;
          tamperingDetected = true;
        } else if (currentRule.checksum === rule.checksum) {
          status = 'VERIFIED';
          displayChecksum = `${displayChecksum} (unchanged)`;
        } else {
          status = '⚠️ TAMPERED';
          displayChecksum = `${displayChecksum} -> ${currentRule.checksum.substring(0, 16)}`;
          tamperingDetected = true;
        }

        reportContent += `| ${rule.chain} | ${status} | ${displayChecksum} |\n`;
      }

      reportContent += '\n';
    } catch (error) {
      reportContent += `Failed to generate report: ${error}\n`;
      tamperingDetected = true;
    }

    return { status: tamperingDetected ? 'tampered' : 'verified', body: reportContent };
  }
}
