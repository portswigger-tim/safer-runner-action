import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';
import { SystemValidator } from './validation';
import { parseNetworkLogs, NetworkConnection } from './parsers/network-parser';
import { parseDnsLogs, DnsResolution } from './parsers/dns-parser';

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

function getGitHubRequiredDomains(): string[] {
  // GitHub required domains (must match main.ts)
  return [
    'github.com', 'actions.githubusercontent.com', 'api.github.com',
    'codeload.github.com', 'pkg.actions.githubusercontent.com', 'ghcr.io',
    'results-receiver.actions.githubusercontent.com',
    // Add all the productionresultssa domains...
    ...Array.from({length: 20}, (_, i) => `productionresultssa${i}.blob.core.windows.net`),
    'objects.githubusercontent.com', 'objects-origin.githubusercontent.com',
    'github-releases.githubusercontent.com', 'github-registry-files.githubusercontent.com',
    'pkg.github.com', 'pkg-containers.githubusercontent.com',
    'github-cloud.githubusercontent.com', 'github-cloud.s3.amazonaws.com',
    'dependabot-actions.githubapp.com', 'release-assets.githubusercontent.com',
    'api.snapcraft.io'
  ];
}

function generateAllowedDomainsConfig(dnsResolutions: DnsResolution[]): string[] {
  const githubDomains = new Set(getGitHubRequiredDomains());
  const excludePatterns = ['github.com', 'store.core.windows.net', 'trafficmanager.net'];
  const allowedDomains = new Set<string>();

  for (const dns of dnsResolutions) {
    // Include resolved domains (both IPv4 and CNAME) that are not GitHub/Azure domains
    if (dns.status === 'RESOLVED' &&
        !githubDomains.has(dns.domain) &&
        !excludePatterns.some(pattern => dns.domain.includes(pattern))) {
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

function calculateStats(connections: NetworkConnection[]) {
  return {
    total: connections.length,
    allowed: connections.filter(c => c.status === 'ALLOWED').length,
    denied: connections.filter(c => c.status === 'DENIED').length,
    analyzed: connections.filter(c => c.status === 'ANALYZED').length
  };
}

function calculateDnsStats(resolutions: DnsResolution[]) {
  return {
    total: resolutions.length,
    resolved: resolutions.filter(r => r.status === 'RESOLVED').length,
    blocked: resolutions.filter(r => r.status === 'BLOCKED').length,
    queried: resolutions.filter(r => r.status === 'QUERIED').length
  };
}

function categorizeDomains(dnsResolutions: DnsResolution[]) {
  const githubDomains = new Set(getGitHubRequiredDomains());
  const categories = {
    github: [] as DnsResolution[],
    user: [] as DnsResolution[],
    blocked: [] as DnsResolution[]
  };

  for (const dns of dnsResolutions) {
    if (dns.status === 'BLOCKED') {
      categories.blocked.push(dns);
    } else if (githubDomains.has(dns.domain) || isGitHubInfrastructure(dns.domain)) {
      categories.github.push(dns);
    } else {
      categories.user.push(dns);
    }
  }

  return categories;
}

function isGitHubInfrastructure(domain: string): boolean {
  const patterns = [
    'github.com',
    'githubusercontent.com',
    'github.io',
    'blob.core.windows.net',
    'trafficmanager.net'
  ];
  return patterns.some(pattern => domain.includes(pattern));
}

function generateExecutiveSummary(mode: string, stats: any, dnsStats: any): string {
  const modeIcon = mode === 'enforce' ? '🔒' : '📊';
  const securityLevel = mode === 'enforce' ? 'ENFORCED' : 'MONITORED';

  let summary = `## ${modeIcon} Security Status: ${securityLevel}\n\n`;

  if (mode === 'enforce') {
    const blocked = stats.denied;
    if (blocked > 0) {
      summary += `🚨 **${blocked} potential threats blocked** - Your workflow is protected!\n\n`;
    } else {
      summary += `✅ **All network access authorized** - No threats detected\n\n`;
    }
  } else {
    summary += `📈 **${dnsStats.total} domains accessed** - Review suggested configuration below\n\n`;
  }

  return summary;
}

function generateSecurityStatus(mode: string, stats: any, dnsStats: any): string {
  let status = `### 📊 Network Activity Summary\n\n`;

  // Create a more concise stats table
  status += `| Metric | Count | Status |\n`;
  status += `|--------|-------|--------|\n`;
  status += `| **Domains Resolved** | ${dnsStats.resolved} | ${dnsStats.resolved > 0 ? '✅' : '➖'} |\n`;
  status += `| **Connections Made** | ${stats.total} | ${stats.total > 0 ? '✅' : '➖'} |\n`;

  if (mode === 'enforce') {
    status += `| **Threats Blocked** | ${stats.denied + dnsStats.blocked} | ${(stats.denied + dnsStats.blocked) > 0 ? '🛡️' : '✅'} |\n`;
  }

  status += `| **DNS Provider** | Quad9 (9.9.9.9) | 🛡️ 98% malware blocking |\n\n`;

  return status;
}

function generateDomainAccessDetails(domainGroups: any, mode: string, connections: NetworkConnection[], dnsResolutions: DnsResolution[]): string {
  let details = '';

  // Create comprehensive domain-to-connection correlation
  const domainConnections = correlateDomainConnections(dnsResolutions, connections);

  // Only show user domains if they exist (most important)
  if (domainGroups.user.length > 0) {
    details += `### 🌐 External Domains Accessed\n\n`;
    details += `| Domain | DNS Status | Connection Status | Purpose |\n`;
    details += `|--------|------------|-------------------|--------|\n`;

    for (const dns of domainGroups.user) {
      const correlation = domainConnections.get(dns.domain);
      const dnsIcon = getDnsStatusIcon(dns.status);
      const purpose = inferDomainPurpose(dns.domain);

      let connectionStatus = '➖ No Connection';
      if (correlation) {
        const connIcon = getStatusIcon(correlation.status);
        connectionStatus = `${connIcon} ${correlation.status}`;
        if (correlation.ips.length > 1) {
          connectionStatus += ` (${correlation.ips.length} IPs)`;
        }
      }

      details += `| ${dns.domain} | ${dnsIcon} ${dns.status} | ${connectionStatus} | ${purpose} |\n`;
    }
    details += `\n`;
  }

  // Show GitHub infrastructure in collapsed detail (less important)
  if (domainGroups.github.length > 0) {
    const githubCount = domainGroups.github.length;
    details += `<details>\n<summary>📋 GitHub Infrastructure (${githubCount} domains) - Click to expand</summary>\n\n`;
    details += `| Domain | Status |\n`;
    details += `|--------|---------|\n`;

    for (const dns of domainGroups.github) {
      const statusIcon = getDnsStatusIcon(dns.status);
      details += `| ${dns.domain} | ${statusIcon} ${dns.status} |\n`;
    }
    details += `\n</details>\n\n`;
  }

  return details;
}

function generateThreatDetails(connections: NetworkConnection[], dnsResolutions: DnsResolution[]): string {
  let threats = `### 🚨 Security Events\n\n`;

  const deniedConnections = connections.filter(c => c.status === 'DENIED');
  const blockedDomains = dnsResolutions.filter(d => d.status === 'BLOCKED');

  // Create IP-to-domain mapping for context
  const ipToDomainMap = new Map<string, string>();
  for (const dns of dnsResolutions) {
    if (dns.status === 'RESOLVED' && dns.ip !== 'CNAME' && dns.ip !== 'NXDOMAIN') {
      const ips = dns.ip.includes(',') ? dns.ip.split(',').map(ip => ip.trim()) : [dns.ip];
      for (const ip of ips) {
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
          ipToDomainMap.set(ip, dns.domain);
        }
      }
    }
  }

  if (blockedDomains.length > 0) {
    threats += `**🛡️ DNS Filtering (DNSmasq):**\n`;
    threats += `| Domain | Action | Reason |\n`;
    threats += `|--------|--------|--------|\n`;

    for (const dns of blockedDomains) {
      threats += `| ${dns.domain} | ❌ NXDOMAIN | Not in allowed domains list |\n`;
    }
    threats += `\n`;
  }

  if (deniedConnections.length > 0) {
    threats += `**🔥 Firewall Blocking (iptables):**\n`;
    threats += `| Domain/IP | Port | Action | Reason |\n`;
    threats += `|-----------|------|--------|--------|\n`;

    for (const conn of deniedConnections) {
      const domain = ipToDomainMap.get(conn.ip);
      const target = domain ? `${domain} (${conn.ip})` : conn.ip;
      threats += `| ${target} | ${conn.port} | ❌ DROP | Connection to unauthorized destination |\n`;
    }
    threats += `\n`;
  }

  // Show the two-layer protection model
  if (deniedConnections.length > 0 || blockedDomains.length > 0) {
    threats += `**🛡️ Two-Layer Protection:**\n`;
    threats += `1. **DNS Layer (DNSmasq)**: Blocks domain resolution for unauthorized domains\n`;
    threats += `2. **Network Layer (iptables)**: Blocks connections to unauthorized IP addresses\n\n`;
  }

  return threats;
}

function inferDomainPurpose(domain: string): string {
  // Infer the likely purpose of external domains
  if (domain.includes('api.')) return '🔗 API Service';
  if (domain.includes('cdn.') || domain.includes('static.')) return '📦 Content Delivery';
  if (domain.includes('registry.') || domain.includes('npm') || domain.includes('pypi')) return '📚 Package Registry';
  if (domain.includes('auth.') || domain.includes('oauth.')) return '🔐 Authentication';
  if (domain.includes('analytics.') || domain.includes('tracking.')) return '📊 Analytics';
  if (domain.includes('storage.') || domain.includes('bucket.')) return '💾 File Storage';
  return '🌐 External Service';
}

function correlateDomainConnections(dnsResolutions: DnsResolution[], connections: NetworkConnection[]): Map<string, any> {
  const correlationMap = new Map<string, any>();

  // Create IP to domain mapping from DNS resolutions
  const ipToDomainMap = new Map<string, string>();
  for (const dns of dnsResolutions) {
    if (dns.status === 'RESOLVED' && dns.ip !== 'CNAME' && dns.ip !== 'NXDOMAIN') {
      // Handle multiple IPs (comma-separated or single)
      const ips = dns.ip.includes(',') ? dns.ip.split(',').map(ip => ip.trim()) : [dns.ip];
      for (const ip of ips) {
        // Validate IP format (basic IPv4 check)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
          ipToDomainMap.set(ip, dns.domain);
        }
      }
    }
  }

  // Group connections by domain
  for (const conn of connections) {
    const domain = ipToDomainMap.get(conn.ip);
    if (domain) {
      if (!correlationMap.has(domain)) {
        correlationMap.set(domain, {
          status: conn.status,
          ips: [conn.ip],
          connections: [conn]
        });
      } else {
        const existing = correlationMap.get(domain);
        // Update status priority: DENIED > ALLOWED > ANALYZED
        if (conn.status === 'DENIED' ||
           (conn.status === 'ALLOWED' && existing.status !== 'DENIED')) {
          existing.status = conn.status;
        }
        if (!existing.ips.includes(conn.ip)) {
          existing.ips.push(conn.ip);
        }
        existing.connections.push(conn);
      }
    }
  }

  return correlationMap;
}

run();