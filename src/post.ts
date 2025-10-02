import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';
import { SystemValidator } from './validation';
import { parseNetworkLogs, parsePreHookNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';
import {
  generateNetworkConnectionDetails,
  generateDnsTable,
  generateConfigurationAdvice
} from './formatters/report-formatter';

async function run(): Promise<void> {
  try {
    core.info('🔍 Analyzing network access logs...');

    // Wait for logs to be written
    await new Promise(resolve => setTimeout(resolve, 2000));

    const connections = await parseNetworkLogs();
    const dnsResolutions = await parseDnsLogs();

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

      // Parse pre-hook DNS logs if they exist
      try {
        const fs = await import('fs');
        if (fs.existsSync('/tmp/pre-hook-dns-logs.txt')) {
          preHookDnsResolutions = await parseDnsLogs('/tmp/pre-hook-dns-logs.txt');
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
 * Analyze pre-hook traffic to identify connections that were:
 * 1. Seen in pre-hook but blocked later (good - action working)
 * 2. Only seen in pre-hook (early workflow setup traffic)
 */
function generatePreHookAnalysis(connections: NetworkConnection[], dnsResolutions: DnsResolution[], preHookConnections: NetworkConnection[], preHookDnsResolutions: DnsResolution[]): string {
  // connections are already separated (main vs pre-hook)

  // Find connections only in pre-hook
  const preHookOnlyConnections = preHookConnections.filter(preConn =>
    !connections.some(mainConn =>
      mainConn.ip === preConn.ip && mainConn.port === preConn.port
    )
  );

  // Find connections that were pre-hook ANALYZED but later DENIED
  const blockedAfterPreHook = preHookConnections.filter(preConn =>
    connections.some(mainConn =>
      mainConn.ip === preConn.ip &&
      mainConn.port === preConn.port &&
      mainConn.status === 'DENIED'
    )
  );

  // Find DNS resolutions only in pre-hook
  const preHookOnlyDns = preHookDnsResolutions.filter(preDns =>
    !dnsResolutions.some(mainDns => mainDns.domain === preDns.domain)
  );

  // Find DNS resolutions that were pre-hook RESOLVED but later BLOCKED
  const blockedDnsAfterPreHook = preHookDnsResolutions.filter(preDns =>
    preDns.status === 'RESOLVED' &&
    dnsResolutions.some(mainDns =>
      mainDns.domain === preDns.domain && mainDns.status === 'BLOCKED'
    )
  );

  // If no pre-hook activity, don't show the section
  if (preHookConnections.length === 0 && preHookDnsResolutions.length === 0) {
    return '';
  }

  let report = `<details>\n<summary><h2>Pre-Hook Security Analysis</h2></summary>\n\n`;

  if (preHookConnections.length > 0) {
    report += `Pre-hook monitoring captured **${preHookConnections.length}** network connection(s) before user workflow execution.\n\n`;
  }

  if (preHookDnsResolutions.length > 0) {
    report += `Pre-hook DNS monitoring captured **${preHookDnsResolutions.length}** DNS resolution(s).\n\n`;
  }

  // Show all pre-hook DNS resolutions using the standard DNS table formatter
  if (preHookDnsResolutions.length > 0) {
    report += `### 📋 Pre-Hook DNS Resolutions\n\n`;
    report += `All DNS queries captured during pre-hook monitoring:\n\n`;
    report += generateDnsTable(preHookDnsResolutions);
  }

  // Show blocked connections (security working as intended)
  if (blockedAfterPreHook.length > 0) {
    report += `### ✅ Connections Blocked After Pre-Hook\n\n`;
    report += `These connections were monitored during pre-hook but blocked when enforce mode activated:\n\n`;
    report += `| IP Address | Port | Status Transition |\n`;
    report += `|------------|------|-------------------|\n`;
    for (const conn of blockedAfterPreHook) {
      report += `| ${conn.ip} | ${conn.port} | Pre-hook: ANALYZED → Main: DENIED |\n`;
    }
    report += `\n`;
  }

  // Show blocked DNS domains (security working as intended)
  if (blockedDnsAfterPreHook.length > 0) {
    report += `### ✅ DNS Domains Blocked After Pre-Hook\n\n`;
    report += `These DNS queries were resolved during pre-hook but blocked when enforce mode activated:\n\n`;
    report += `| Domain | IP | Status Transition |\n`;
    report += `|--------|----|-----------------|\n`;
    for (const dns of blockedDnsAfterPreHook) {
      report += `| ${dns.domain} | ${dns.ip} | Pre-hook: RESOLVED → Main: BLOCKED |\n`;
    }
    report += `\n`;
  }

  // Show pre-hook only connections
  if (preHookOnlyConnections.length > 0) {
    report += `### 🕐 Pre-Hook Only Connections\n\n`;
    report += `These connections only appeared during pre-hook monitoring (before user workflow):\n\n`;
    report += `| IP Address | Port | Source |\n`;
    report += `|------------|------|--------|\n`;
    for (const conn of preHookOnlyConnections) {
      report += `| ${conn.ip} | ${conn.port} | ${conn.source} |\n`;
    }
    report += `\n`;
  }

  // Show pre-hook only DNS resolutions
  if (preHookOnlyDns.length > 0) {
    report += `### 🕐 Pre-Hook Only DNS Resolutions\n\n`;
    report += `These DNS queries only appeared during pre-hook monitoring:\n\n`;
    report += `| Domain | IP | Status |\n`;
    report += `|--------|----|---------|\n`;
    for (const dns of preHookOnlyDns) {
      report += `| ${dns.domain} | ${dns.ip} | ${dns.status} |\n`;
    }
    report += `\n`;
  }

  if (preHookOnlyConnections.length > 0 || preHookOnlyDns.length > 0) {
    report += `*Note: Pre-hook only activity typically represents GitHub Actions setup connections that occur before workflow steps run.*\n\n`;
  }

  report += `</details>\n\n`;
  return report;
}

async function generateJobSummary(connections: NetworkConnection[], dnsResolutions: DnsResolution[], preHookConnections: NetworkConnection[], preHookDnsResolutions: DnsResolution[], validationReport: string): Promise<void> {
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
  summary += `## DNS Information\n\n`;
  summary += generateDnsTable(dnsResolutions);

  // 3. Pre-Hook Security Analysis (collapsible)
  summary += generatePreHookAnalysis(connections, dnsResolutions, preHookConnections, preHookDnsResolutions);

  // 4. Config File Tamper Detection
  summary += `${validationReport}\n`;

  // 5. Configuration Advice (for analyze mode)
  if (mode === 'analyze') {
    summary += generateConfigurationAdvice(dnsResolutions);
  }

  summary += `---\n*Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
}

run();