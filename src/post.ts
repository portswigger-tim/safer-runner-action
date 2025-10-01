import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';
import { SystemValidator } from './validation';
import { parseNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';
import { getGitHubRequiredDomains, isGitHubDomain, isGitHubInfrastructure, isGitHubRelated } from './parsers/github-parser';

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
    summary += generateConfigurationAdvice(dnsResolutions);
  }

  summary += `---\n*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
}

function generateNetworkConnectionDetails(connections: NetworkConnection[]): string {
  let details = `## Network Connection Details\n\n`;

  if (connections.length === 0) {
    details += `No network connections recorded.\n\n`;
    return details;
  }

  // Separate GitHub and non-GitHub connections
  const githubConnections = connections.filter(c => c.source === 'GitHub Required');
  const userConnections = connections.filter(c => c.source === 'User Defined');
  const deniedConnections = connections.filter(c => c.status === 'DENIED');
  const analyzedConnections = connections.filter(c => c.status === 'ANALYZED');

  // Show user-defined and denied connections first (most important)
  if (userConnections.length > 0 || deniedConnections.length > 0 || analyzedConnections.length > 0) {
    const importantConnections = [...userConnections, ...deniedConnections, ...analyzedConnections];
    // Remove duplicates
    const uniqueImportant = Array.from(new Map(importantConnections.map(c => [`${c.ip}:${c.port}`, c])).values());

    details += `| IP Address | Port | Status | Source |\n`;
    details += `|------------|------|--------|--------|\n`;

    for (const conn of uniqueImportant) {
      let statusDisplay = conn.status;
      if (conn.status === 'DENIED') {
        statusDisplay = `🚫 ${conn.status}`;
      }
      details += `| ${conn.ip} | ${conn.port} | ${statusDisplay} | ${conn.source} |\n`;
    }
    details += `\n`;
  }

  // Show GitHub connections in collapsed section
  if (githubConnections.length > 0) {
    details += `<details>\n<summary>📋 GitHub Infrastructure Connections (${githubConnections.length}) - Click to expand</summary>\n\n`;
    details += `| IP Address | Port | Status | Source |\n`;
    details += `|------------|------|--------|--------|\n`;

    for (const conn of githubConnections) {
      let statusDisplay = conn.status;
      if (conn.status === 'DENIED') {
        statusDisplay = `🚫 ${conn.status}`;
      }
      details += `| ${conn.ip} | ${conn.port} | ${statusDisplay} | ${conn.source} |\n`;
    }
    details += `\n</details>\n\n`;
  }

  const deniedCount = connections.filter(c => c.status === 'DENIED').length;
  details += `**Total connections:** ${connections.length}`;
  if (deniedCount > 0) {
    details += ` (🛡️ ${deniedCount} blocked)`;
  }
  details += `\n\n`;

  return details;
}

function generateDnsDetails(dnsResolutions: DnsResolution[]): string {
  let details = `## DNS Information\n\n`;

  if (dnsResolutions.length === 0) {
    details += `No DNS resolutions recorded.\n\n`;
    return details;
  }

  const githubDomains = new Set(getGitHubRequiredDomains());

  // Separate GitHub and non-GitHub DNS resolutions
  const githubDns = dnsResolutions.filter(d =>
    githubDomains.has(d.domain) || isGitHubInfrastructure(d.domain)
  );
  const userDns = dnsResolutions.filter(d =>
    !githubDomains.has(d.domain) && !isGitHubInfrastructure(d.domain)
  );
  const blockedDns = dnsResolutions.filter(d => d.status === 'BLOCKED');

  // Show user-defined and blocked DNS first (most important)
  if (userDns.length > 0 || blockedDns.length > 0) {
    const importantDns = [...userDns, ...blockedDns];
    // Remove duplicates
    const uniqueImportant = Array.from(new Map(importantDns.map(d => [d.domain, d])).values());

    details += `| Domain | IP Address(es) | Status |\n`;
    details += `|--------|----------------|--------|\n`;

    for (const dns of uniqueImportant) {
      let status = dns.status;
      if (dns.status === 'BLOCKED') {
        status = `🚫 BLOCKED`;
      }

      // Format IP addresses with <br/> separation for readability
      let formattedIps = dns.ip;
      if (dns.ip.includes(', ')) {
        formattedIps = dns.ip.split(', ').join('<br/>');
      }

      details += `| ${dns.domain} | ${formattedIps} | ${status} |\n`;
    }
    details += `\n`;
  }

  // Show GitHub DNS in collapsed section
  if (githubDns.length > 0) {
    details += `<details>\n<summary>📋 GitHub Infrastructure DNS (${githubDns.length} domains) - Click to expand</summary>\n\n`;
    details += `| Domain | IP Address(es) | Status |\n`;
    details += `|--------|----------------|--------|\n`;

    for (const dns of githubDns) {
      let status = dns.status;
      if (dns.status === 'BLOCKED') {
        status = `🚫 BLOCKED`;
      }

      // Format IP addresses with <br/> separation for readability
      let formattedIps = dns.ip;
      if (dns.ip.includes(', ')) {
        formattedIps = dns.ip.split(', ').join('<br/>');
      }

      details += `| ${dns.domain} | ${formattedIps} | ${status} |\n`;
    }
    details += `\n</details>\n\n`;
  }

  const blockedCount = dnsResolutions.filter(d => d.status === 'BLOCKED').length;
  details += `**Total domains:** ${dnsResolutions.length}`;
  if (blockedCount > 0) {
    details += ` (🛡️ ${blockedCount} filtered)`;
  }
  details += `\n\n`;

  return details;
}

function generateConfigurationAdvice(dnsResolutions: DnsResolution[]): string {
  const suggestedDomains = generateAllowedDomainsConfig(dnsResolutions);

  if (suggestedDomains.length === 0) {
    return `## Configuration Advice\n\nNo additional domains detected for allowlist configuration.\n\n`;
  }

  let advice = `## Configuration Advice\n\n`;
  advice += `To run in enforce mode with the domains accessed in this workflow, add these domains to your configuration:\n\n`;
  advice += `\`\`\`yaml\n`;
  advice += `- uses: portswigger-tim/safer-runner-action@v1\n`;
  advice += `  with:\n`;
  advice += `    mode: 'enforce'\n`;
  advice += `    allowed-domains: |\n`;

  for (const domain of suggestedDomains) {
    advice += `      ${domain}\n`;
  }

  advice += `\`\`\`\n\n`;
  return advice;
}

function getStatusIcon(status: string): string {
  switch (status) {
    case 'ALLOWED': return '✅';
    case 'DENIED': return '❌';
    case 'ANALYZED': return '📊';
    default: return '❓';
  }
}

function getDnsStatusIcon(status: string): string {
  switch (status) {
    case 'RESOLVED': return '✅';
    case 'BLOCKED': return '🚫';
    case 'QUERIED': return '❓';
    default: return '❓';
  }
}

run();