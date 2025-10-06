/**
 * System Integrity Validation for Safer Runner Action
 *
 * This module provides SHA256 checksum-based validation to ensure that critical
 * security configurations (dnsmasq.conf, resolv.conf, iptables rules) are not
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
import { readFileSync, writeFileSync, existsSync } from 'fs';

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
 * Standard iptables chains to monitor for tampering
 */
const IPTABLES_CHAINS = ['INPUT', 'OUTPUT', 'FORWARD'] as const;

export class SystemValidator {
  private validationStateFile = '/tmp/safer-runner-validation-state.json';
  private criticalFiles: string[];

  constructor(criticalFiles?: string[]) {
    // Allow injection of critical files for testing
    this.criticalFiles = criticalFiles || [
      '/etc/dnsmasq.conf',
      '/etc/resolv.conf',
      '/etc/systemd/resolved.conf.d/no-stub.conf'
    ];
  }

  /**
   * Capture post-setup baseline checksums after all configuration is complete
   * This baseline will be verified in the post-action to detect tampering
   */
  async capturePostSetupBaseline(): Promise<void> {
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
    writeFileSync(this.validationStateFile, JSON.stringify(state, null, 2));
    core.info(`💾 Security baseline saved to ${this.validationStateFile}`);
  }

  /**
   * Verify current state against post-setup baseline to detect tampering
   */
  async verifyAgainstBaseline(): Promise<boolean> {
    core.info('🔍 Verifying system integrity against baseline...');

    if (!existsSync(this.validationStateFile)) {
      core.warning('⚠️  No baseline state file found - cannot verify integrity');
      return false;
    }

    let baselineState: ValidationState;
    try {
      baselineState = JSON.parse(readFileSync(this.validationStateFile, 'utf8'));
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
   * Uses sudo to read files with restricted permissions (e.g., dnsmasq.conf with mode 600)
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
    await exec.exec('sudo', ['iptables', '-L', chain, '-n', '--line-numbers'], {
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
    if (!existsSync(this.validationStateFile)) {
      return '<details>\n<summary><h2>Config File Tamper Detection</h2></summary>\n\nNo validation data available.\n\n</details>\n\n';
    }

    // Check if tampering occurred to add warning emoji
    let tamperingDetected = false;
    let reportContent = '';

    try {
      const state: ValidationState = JSON.parse(readFileSync(this.validationStateFile, 'utf8'));

      reportContent += `**Baseline:** ${state.timestamp}\n`;
      reportContent += `**Verified:** ${new Date().toISOString()}\n\n`;

      // File integrity report
      reportContent += '### Configuration Files\n\n';
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
      reportContent += '\n### Firewall Rules\n\n';
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

    // Wrap in collapsible section with warning emoji if tampering detected
    const titleEmoji = tamperingDetected ? '⚠️ ' : '';
    return `<details>\n<summary><h2>${titleEmoji}Config File Tamper Detection</h2></summary>\n\n${reportContent}</details>\n\n`;
  }
}
