import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';
import { SystemValidator } from './validation';
import { parseNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';
import { isGitHubRelated } from './parsers/github-parser';
import {
  generateNetworkConnectionDetails,
  generateDnsDetails,
  generateConfigurationAdvice
} from './formatters/report-formatter';

async function run(): Promise<void> {
  try {
    core.info('🔍 Analyzing network access logs...');

    // Wait for logs to be written
    await new Promise(resolve => setTimeout(resolve, 2000));

    const connections = await parseNetworkLogs();
    const dnsResolutions = await parseDnsLogs();

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

    await generateJobSummary(connections, dnsResolutions, validationReport);

    core.info('✅ Network access summary generated');

  } catch (error) {
    core.warning(`Failed to generate network summary: ${error}`);
    // Don't fail the entire action if log analysis fails
  }
}

function generateAllowedDomainsConfig(dnsResolutions: DnsResolution[]): string[] {
  const allowedDomains = new Set<string>();

  for (const dns of dnsResolutions) {
    // Include resolved domains (both IPv4 and CNAME) that are not GitHub-related
    if (dns.status === 'RESOLVED' && !isGitHubRelated(dns.domain)) {
      allowedDomains.add(dns.domain);
    }
  }

  return Array.from(allowedDomains).sort();
}

async function generateJobSummary(connections: NetworkConnection[], dnsResolutions: DnsResolution[], validationReport: string): Promise<void> {
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

  // 3. Config File Tamper Detection
  summary += `${validationReport}\n`;

  // 4. Configuration Advice (for analyze mode)
  if (mode === 'analyze') {
    const suggestedDomains = generateAllowedDomainsConfig(dnsResolutions);
    summary += generateConfigurationAdvice(suggestedDomains);
  }

  summary += `---\n*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
}

run();