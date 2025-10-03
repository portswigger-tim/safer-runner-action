import * as core from '@actions/core';
import { SystemValidator } from './validation';
import { parseNetworkLogs, parsePreHookNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';
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
    const dnsResolutions = await parseDnsLogs('/tmp/main-dns.log');

    // Parse pre-hook logs if pre-action ran
    let preHookConnections: NetworkConnection[] = [];
    let preHookDnsResolutions: DnsResolution[] = [];

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
        if (fs.existsSync('/tmp/pre-dns.log')) {
          preHookDnsResolutions = await parseDnsLogs('/tmp/pre-dns.log');
          core.info(`✅ Found ${preHookDnsResolutions.length} pre-hook DNS resolution(s)`);
        }
      } catch (error) {
        core.warning(`Could not parse pre-hook DNS logs: ${error}`);
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

    await generateJobSummary(connections, dnsResolutions, preHookConnections, preHookDnsResolutions, validationReport);

    core.info('✅ Network access summary generated');
  } catch (error) {
    core.warning(`Failed to generate network summary: ${error}`);
    // Don't fail the entire action if log analysis fails
  }
}

/**
 * Generate simplified pre-hook analysis section with network connections and DNS info
 */
function generatePreHookAnalysis(
  preHookConnections: NetworkConnection[],
  preHookDnsResolutions: DnsResolution[]
): string {
  // If no pre-hook activity, don't show the section
  if (preHookConnections.length === 0 && preHookDnsResolutions.length === 0) {
    return '';
  }

  let report = `<details>\n<summary><h2>Pre-Hook Security Analysis</h2></summary>\n\n`;

  report += `This section shows network activity captured during pre-hook monitoring, before your workflow steps executed.\n\n`;

  // Network Connection Details
  report += generateNetworkConnectionDetails(preHookConnections);

  // DNS Information
  report += generateDnsDetails(preHookDnsResolutions);

  report += `</details>\n\n`;
  return report;
}

async function generateJobSummary(
  connections: NetworkConnection[],
  dnsResolutions: DnsResolution[],
  preHookConnections: NetworkConnection[],
  preHookDnsResolutions: DnsResolution[],
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

  // 1. Network Connection Details
  summary += generateNetworkConnectionDetails(connections);

  // 2. DNS Information
  summary += generateDnsDetails(dnsResolutions);

  // 3. Pre-Hook Security Analysis (collapsible)
  summary += generatePreHookAnalysis(preHookConnections, preHookDnsResolutions);

  // 4. Config File Tamper Detection
  summary += `${validationReport}\n`;

  // 5. Configuration Advice (for analyze mode only)
  if (mode === 'analyze') {
    summary += generateConfigurationAdvice(dnsResolutions);
  }

  summary += `---\n*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
}

run();
