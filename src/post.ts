import * as core from '@actions/core';
import { SystemValidator } from './validation';
import { parseNetworkLogs, parsePreHookNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';
import { parseSudoLogs, generateSudoSummarySection, type SudoCommand } from './sudo';
import {
  generateNetworkConnectionDetails,
  generateDnsTable,
  generateDnsDetails,
  generateConfigurationAdvice
} from './formatters/report-formatter';

async function run(): Promise<void> {
  try {
    core.info('🔍 Analyzing network access logs...');

    // Wait for logs to be written
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Parse main action logs
    const connections = await parseNetworkLogs();
    const dnsResolutions = await parseDnsLogs('/var/log/safer-runner/main-dns.log');

    // Parse main sudo logs (workflow commands only)
    const sudoCommands = parseSudoLogs('/var/log/safer-runner/main-sudo.log');
    if (sudoCommands.length > 0) {
      core.info(`✅ Found ${sudoCommands.length} workflow sudo command(s)`);
    }

    // Parse pre-hook logs if pre-action ran
    let preHookConnections: NetworkConnection[] = [];
    let preHookDnsResolutions: DnsResolution[] = [];
    let preHookSudoCommands: SudoCommand[] = [];

    // Check if pre-action ran by looking for DNS user state
    const preUsername = core.getState('dns-user');
    if (preUsername) {
      core.info('📋 Parsing pre-hook logs...');

      // Parse pre-hook network connections
      preHookConnections = await parsePreHookNetworkLogs();
      core.info(`✅ Found ${preHookConnections.length} pre-hook network connection(s)`);

      // Parse pre-hook DNS logs from dedicated log file
      try {
        const fs = await import('fs');
        if (fs.existsSync('/var/log/safer-runner/pre-dns.log')) {
          preHookDnsResolutions = await parseDnsLogs('/var/log/safer-runner/pre-dns.log');
          core.info(`✅ Found ${preHookDnsResolutions.length} pre-hook DNS resolution(s)`);
        }

        // Parse pre-hook sudo logs (other actions' pre-hooks only)
        // Sudo logging is removed at start of main.ts, so this captures pre-hook activity only
        preHookSudoCommands = parseSudoLogs('/var/log/safer-runner/pre-sudo.log');
        if (preHookSudoCommands.length > 0) {
          core.info(`✅ Found ${preHookSudoCommands.length} pre-hook sudo command(s)`);
        }
      } catch (error) {
        core.warning(`Could not parse pre-hook logs: ${error}`);
      }
    }

    // Verify system integrity against post-setup baseline
    const validator = new SystemValidator();
    const integrityValid = await validator.verifyAgainstBaseline();
    const validationReport = await validator.generateValidationReport();

    // Check if we should fail on tampering (GitHub Actions converts boolean inputs to strings)
    const failOnTampering = core.getBooleanInput('fail-on-tampering');

    if (!integrityValid && failOnTampering) {
      core.setFailed('🚨 Workflow failed due to security configuration tampering detection!');
      return; // Exit early - the validation report will still be in the logs above
    }

    await generateJobSummary(
      connections,
      dnsResolutions,
      sudoCommands,
      preHookConnections,
      preHookDnsResolutions,
      preHookSudoCommands,
      validationReport
    );

    core.info('✅ Network access summary generated');
  } catch (error) {
    core.warning(`Failed to generate network summary: ${error}`);
    // Don't fail the entire action if log analysis fails
  }
}

/**
 * Generate simplified pre-hook analysis section with network connections, DNS, and sudo info
 */
function generatePreHookAnalysis(
  preHookConnections: NetworkConnection[],
  preHookDnsResolutions: DnsResolution[],
  preHookSudoCommands: SudoCommand[]
): string {
  // If no pre-hook activity, don't show the section
  if (preHookConnections.length === 0 && preHookDnsResolutions.length === 0 && preHookSudoCommands.length === 0) {
    return '';
  }

  let report = `<details>\n<summary><h2>Pre-Hook Security Analysis</h2></summary>\n\n`;

  report += `This section shows activity captured during pre-hook monitoring (other actions' pre-hooks), before your workflow steps executed.\n\n`;

  // Network Connection Details
  report += generateNetworkConnectionDetails(preHookConnections);

  // DNS Information
  report += generateDnsDetails(preHookDnsResolutions);

  // Sudo Commands
  report += generateSudoSummarySection(preHookSudoCommands, 'Sudo Commands');

  report += `</details>\n\n`;
  return report;
}

async function generateJobSummary(
  connections: NetworkConnection[],
  dnsResolutions: DnsResolution[],
  sudoCommands: SudoCommand[],
  preHookConnections: NetworkConnection[],
  preHookDnsResolutions: DnsResolution[],
  preHookSudoCommands: SudoCommand[],
  validationReport: string
): Promise<void> {
  const mode = core.getInput('mode') || 'analyze';
  const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');
  const jobName = process.env.GITHUB_JOB || 'unknown';

  let summary = `# Safer Runner Security Report\n\n`;

  const modeIcon = mode === 'enforce' ? '🔒' : '📊';
  summary += `**Job:** ${jobName}\n`;
  summary += `**Mode:** ${modeIcon} ${mode.toUpperCase()}\n`;

  // Show blocked subdomains if in enforce mode
  if (mode === 'enforce') {
    const riskySubdomains = ['gist.github.com', 'gist.githubusercontent.com', 'raw.githubusercontent.com'];
    if (blockRiskySubdomains) {
      summary += `**Blocked Subdomains:** 🚫 ${riskySubdomains.join(', ')}\n`;
    } else {
      summary += `**Blocked Subdomains:** ⚠️ DISABLED (risky subdomains are allowed)\n`;
    }
  }

  summary += `**Generated:** ${new Date().toISOString()}\n\n`;
  summary += `---\n\n`;

  // 1. Network Connection Details
  summary += generateNetworkConnectionDetails(connections);
  summary += `---\n\n`;

  // 2. DNS Information
  summary += generateDnsDetails(dnsResolutions);
  summary += `---\n\n`;

  // 3. Pre-Hook Security Analysis (collapsible)
  summary += generatePreHookAnalysis(preHookConnections, preHookDnsResolutions, preHookSudoCommands);
  if (preHookConnections.length > 0 || preHookDnsResolutions.length > 0 || preHookSudoCommands.length > 0) {
    summary += `---\n\n`;
  }

  // 4. Config File Tamper Detection
  summary += `${validationReport}`;
  summary += `---\n\n`;

  // 5. Configuration Advice (for analyze mode only)
  if (mode === 'analyze') {
    summary += generateConfigurationAdvice(dnsResolutions, sudoCommands);
    summary += `---\n\n`;
  }

  summary += `*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
}

run();
