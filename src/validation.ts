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

export class SystemValidator {
  private validationStateFile = '/tmp/safer-runner-validation-state.json';

  constructor() {}

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

    // Critical files to monitor (these should all exist after setup)
    const criticalFiles = [
      '/etc/dnsmasq.conf',
      '/etc/resolv.conf',
      '/etc/systemd/resolved.conf.d/no-stub.conf'
    ];

    // Capture file checksums
    for (const filePath of criticalFiles) {
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
   */
  private async calculateFileChecksum(filePath: string): Promise<string | null> {
    try {
      const fileContent = readFileSync(filePath);
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
   * Capture current iptables state
   */
  private async captureIptablesState(state: ValidationState): Promise<void> {
    const chains = ['INPUT', 'OUTPUT', 'FORWARD'];

    for (const chain of chains) {
      try {
        let rulesOutput = '';
        await exec.exec('sudo', ['iptables', '-L', chain, '-n', '--line-numbers'], {
          listeners: {
            stdout: (data) => { rulesOutput += data.toString(); }
          },
          ignoreReturnCode: true
        });

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
    const chains = ['INPUT', 'OUTPUT', 'FORWARD'];
    const currentState: IptablesRuleChecksum[] = [];

    for (const chain of chains) {
      try {
        let rulesOutput = '';
        await exec.exec('sudo', ['iptables', '-L', chain, '-n', '--line-numbers'], {
          listeners: {
            stdout: (data) => { rulesOutput += data.toString(); }
          },
          ignoreReturnCode: true
        });

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
      return '## Config File Tamper Detection\n\nNo validation data available.\n\n';
    }

    let report = '## Config File Tamper Detection\n\n';

    try {
      const state: ValidationState = JSON.parse(readFileSync(this.validationStateFile, 'utf8'));

      report += `**Baseline:** ${state.timestamp}\n`;
      report += `**Verified:** ${new Date().toISOString()}\n\n`;

      // File integrity report
      report += '### Configuration Files\n\n';
      report += '| File | Status | Checksum Comparison |\n';
      report += '|------|--------|--------------------|\n';

      for (const file of state.files) {
        const currentChecksum = await this.calculateFileChecksum(file.path);
        let status = 'Unknown';
        let displayChecksum = file.checksum.substring(0, 16);

        if (!currentChecksum) {
          status = '🚨 DELETED';
          displayChecksum = `${displayChecksum} -> MISSING`;
        } else if (currentChecksum === file.checksum) {
          status = 'VERIFIED';
          displayChecksum = `${displayChecksum} (unchanged)`;
        } else {
          status = '⚠️ TAMPERED';
          displayChecksum = `${displayChecksum} -> ${currentChecksum.substring(0, 16)}`;
        }

        report += `| ${file.path} | ${status} | ${displayChecksum} |\n`;
      }

      // iptables integrity report
      report += '\n### Firewall Rules\n\n';
      report += '| Chain | Status | Checksum Comparison |\n';
      report += '|-------|--------|--------------|\n';

      const currentIptablesState = await this.getCurrentIptablesState();
      for (const rule of state.iptablesRules) {
        const currentRule = currentIptablesState.find(r => r.chain === rule.chain);
        let status = 'Unknown';
        let displayChecksum = rule.checksum.substring(0, 16);

        if (!currentRule) {
          status = '🚨 MISSING';
          displayChecksum = `${displayChecksum} -> MISSING`;
        } else if (currentRule.checksum === rule.checksum) {
          status = 'VERIFIED';
          displayChecksum = `${displayChecksum} (unchanged)`;
        } else {
          status = '⚠️ TAMPERED';
          displayChecksum = `${displayChecksum} -> ${currentRule.checksum.substring(0, 16)}`;
        }

        report += `| ${rule.chain} | ${status} | ${displayChecksum} |\n`;
      }

      report += '\n';

    } catch (error) {
      report += `Failed to generate report: ${error}\n`;
    }

    return report;
  }
}