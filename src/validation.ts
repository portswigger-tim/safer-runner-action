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
   * Capture pre-run checksums of critical system files and iptables rules
   */
  async capturePreRunState(): Promise<void> {
    core.info('📋 Capturing pre-run validation state...');

    const state: ValidationState = {
      files: [],
      iptablesRules: [],
      timestamp: new Date().toISOString()
    };

    // Critical files to monitor
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
          core.info(`✅ Captured checksum for ${filePath}: ${checksum.substring(0, 16)}...`);
        }
      } catch (error) {
        // File may not exist yet, that's expected for some files
        core.info(`ℹ️  File ${filePath} not found (expected for pre-run): ${error}`);
        state.files.push({
          path: filePath,
          checksum: 'FILE_NOT_EXISTS',
          timestamp: new Date().toISOString()
        });
      }
    }

    // Capture iptables state
    await this.captureIptablesState(state);

    // Save validation state
    writeFileSync(this.validationStateFile, JSON.stringify(state, null, 2));
    core.info(`💾 Validation state saved to ${this.validationStateFile}`);
  }

  /**
   * Verify post-run checksums against pre-run state
   */
  async verifyPostRunState(): Promise<boolean> {
    core.info('🔍 Verifying post-run validation state...');

    if (!existsSync(this.validationStateFile)) {
      core.warning('⚠️  No validation state file found - cannot verify integrity');
      return false;
    }

    let preRunState: ValidationState;
    try {
      preRunState = JSON.parse(readFileSync(this.validationStateFile, 'utf8'));
    } catch (error) {
      core.error(`❌ Failed to read validation state: ${error}`);
      return false;
    }

    let allValid = true;

    // Verify file checksums
    for (const fileState of preRunState.files) {
      try {
        const currentChecksum = await this.calculateFileChecksum(fileState.path);

        if (fileState.checksum === 'FILE_NOT_EXISTS') {
          if (currentChecksum) {
            core.info(`✅ File ${fileState.path} was created as expected`);
          } else {
            core.warning(`⚠️  File ${fileState.path} was expected to be created but still doesn't exist`);
          }
          continue;
        }

        if (!currentChecksum) {
          core.error(`❌ File ${fileState.path} was deleted unexpectedly!`);
          allValid = false;
          continue;
        }

        if (currentChecksum === fileState.checksum) {
          core.info(`✅ File ${fileState.path} integrity verified`);
        } else {
          core.error(`❌ File ${fileState.path} has been tampered with!`);
          core.error(`   Expected: ${fileState.checksum}`);
          core.error(`   Actual:   ${currentChecksum}`);
          allValid = false;
        }
      } catch (error) {
        core.error(`❌ Failed to verify ${fileState.path}: ${error}`);
        allValid = false;
      }
    }

    // Verify iptables rules
    const currentIptablesState = await this.getCurrentIptablesState();
    for (const ruleState of preRunState.iptablesRules) {
      const currentRule = currentIptablesState.find(r => r.chain === ruleState.chain);

      if (!currentRule) {
        core.error(`❌ iptables chain ${ruleState.chain} is missing!`);
        allValid = false;
        continue;
      }

      if (currentRule.checksum === ruleState.checksum) {
        core.info(`✅ iptables chain ${ruleState.chain} integrity verified`);
      } else {
        core.error(`❌ iptables chain ${ruleState.chain} has been tampered with!`);
        core.error(`   Expected: ${ruleState.checksum}`);
        core.error(`   Actual:   ${currentRule.checksum}`);
        allValid = false;
      }
    }

    if (allValid) {
      core.info('✅ All validation checks passed - no tampering detected');
    } else {
      core.error('❌ Validation failed - potential tampering detected!');
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
      return '⚠️  No validation data available';
    }

    let report = '## 🔒 System Integrity Validation Report\n\n';

    try {
      const state: ValidationState = JSON.parse(readFileSync(this.validationStateFile, 'utf8'));

      report += `**Validation Timestamp:** ${state.timestamp}\n\n`;

      // File integrity report
      report += '### 📁 File Integrity\n\n';
      report += '| File | Status | Checksum (first 16 chars) |\n';
      report += '|------|--------|---------------------------|\n';

      for (const file of state.files) {
        const currentChecksum = await this.calculateFileChecksum(file.path);
        let status = '❓ Unknown';
        let displayChecksum = file.checksum === 'FILE_NOT_EXISTS' ? 'N/A' : file.checksum.substring(0, 16);

        if (file.checksum === 'FILE_NOT_EXISTS') {
          status = currentChecksum ? '✅ Created' : '⚠️  Not Created';
        } else if (!currentChecksum) {
          status = '❌ Deleted';
        } else if (currentChecksum === file.checksum) {
          status = '✅ Verified';
        } else {
          status = '❌ Tampered';
          displayChecksum = `${displayChecksum} → ${currentChecksum.substring(0, 16)}`;
        }

        report += `| ${file.path} | ${status} | ${displayChecksum} |\n`;
      }

      // iptables integrity report
      report += '\n### 🛡️ iptables Rules Integrity\n\n';
      report += '| Chain | Status | Checksum (first 16 chars) |\n';
      report += '|-------|--------|---------------------------|\n';

      const currentIptablesState = await this.getCurrentIptablesState();
      for (const rule of state.iptablesRules) {
        const currentRule = currentIptablesState.find(r => r.chain === rule.chain);
        let status = '❓ Unknown';
        let displayChecksum = rule.checksum.substring(0, 16);

        if (!currentRule) {
          status = '❌ Missing';
        } else if (currentRule.checksum === rule.checksum) {
          status = '✅ Verified';
        } else {
          status = '❌ Tampered';
          displayChecksum = `${displayChecksum} → ${currentRule.checksum.substring(0, 16)}`;
        }

        report += `| ${rule.chain} | ${status} | ${displayChecksum} |\n`;
      }

      report += '\n---\n*🔒 Generated by System Integrity Validator*\n';

    } catch (error) {
      report += `❌ Failed to generate report: ${error}\n`;
    }

    return report;
  }
}