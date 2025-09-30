import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';
import { SystemValidator } from './validation';

interface NetworkConnection {
  ip: string;
  port: string;
  status: string;
  source: string;
}

interface DnsResolution {
  domain: string;
  ip: string;
  status: string;
}

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

    if (!integrityValid) {
      core.error('🚨 System integrity validation failed - potential tampering detected!');
      // Note: We don't fail the action here as this is post-cleanup
      // The validation report will show the tampering details
    }

    await generateJobSummary(connections, dnsResolutions, validationReport);

    core.info('✅ Network access summary generated');

  } catch (error) {
    core.warning(`Failed to generate network summary: ${error}`);
    // Don't fail the entire action if log analysis fails
  }
}

async function parseNetworkLogs(): Promise<NetworkConnection[]> {
  const connections: NetworkConnection[] = [];

  try {
    // Get syslog content
    let syslogOutput = '';
    await exec.exec('sudo', ['grep', '-E', 'GitHub-Allow: |User-Allow: |Drop-Enforce: |Allow-Analyze: ', '/var/log/syslog'], {
      listeners: {
        stdout: (data) => { syslogOutput += data.toString(); }
      },
      ignoreReturnCode: true
    });

    const lines = syslogOutput.split('\n').filter(line => line.trim());

    for (const line of lines) {
      const connection = parseLogLine(line);
      if (connection) {
        connections.push(connection);
      }
    }

    // Remove duplicates and limit results
    return deduplicateConnections(connections).slice(0, 20);

  } catch (error) {
    core.warning(`Failed to parse logs: ${error}`);
    return [];
  }
}

function parseLogLine(line: string): NetworkConnection | null {
  // Parse iptables log format
  const ipMatch = line.match(/DST=([0-9.]+)/);
  const portMatch = line.match(/DPT=([0-9]+)/);

  if (!ipMatch) return null;

  const ip = ipMatch[1];
  const port = portMatch ? portMatch[1] : '443';

  let status = 'UNKNOWN';
  let source = 'Unknown';

  if (line.includes('GitHub-Allow: ')) {
    status = 'ALLOWED';
    source = 'GitHub Required';
  } else if (line.includes('User-Allow: ')) {
    status = 'ALLOWED';
    source = 'User Defined';
  } else if (line.includes('Drop-Enforce: ')) {
    status = 'DENIED';
    source = 'Firewall Drop';
  } else if (line.includes('Allow-Analyze: ')) {
    status = 'ANALYZED';
    source = 'Monitor Only';
  }

  return { ip, port, status, source };
}

function deduplicateConnections(connections: NetworkConnection[]): NetworkConnection[] {
  const seen = new Map<string, NetworkConnection>();

  for (const conn of connections) {
    const key = `${conn.ip}:${conn.port}`;
    if (!seen.has(key)) {
      seen.set(key, conn);
    }
  }

  return Array.from(seen.values());
}

async function parseDnsLogs(): Promise<DnsResolution[]> {
  const resolutions: DnsResolution[] = [];

  try {
    // Get DNS-related logs from syslog
    let syslogOutput = '';
    await exec.exec('sudo', ['grep', '-E', 'reply|NXDOMAIN|dnsmasq', '/var/log/syslog'], {
      listeners: {
        stdout: (data) => { syslogOutput += data.toString(); }
      },
      ignoreReturnCode: true
    });

    const lines = syslogOutput.split('\n').filter(line => line.trim());

    for (const line of lines) {
      const resolution = parseDnsLogLine(line);
      if (resolution) {
        resolutions.push(resolution);
      }
    }

    // Remove duplicates and limit results
    return deduplicateDnsResolutions(resolutions).slice(0, 20);

  } catch (error) {
    core.warning(`Failed to parse DNS logs: ${error}`);
    return [];
  }
}

function parseDnsLogLine(line: string): DnsResolution | null {
  // IPv4 address pattern: matches valid IPv4 addresses only (0-255.0-255.0-255.0-255)
  const ipv4Pattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';

  // Parse reply lines with IPv4 addresses
  const replyMatch = line.match(new RegExp(`dnsmasq.*reply ([^\\s]+) is (${ipv4Pattern})`));
  if (replyMatch) {
    return {
      domain: replyMatch[1],
      ip: replyMatch[2],
      status: 'RESOLVED'
    };
  }

  // Parse CNAME responses
  const cnameMatch = line.match(/dnsmasq.*reply ([^\s]+) is <CNAME>/);
  if (cnameMatch) {
    return {
      domain: cnameMatch[1],
      ip: 'CNAME',
      status: 'RESOLVED'
    };
  }

  // Parse NXDOMAIN responses (blocked domains)
  const nxdomainMatch = line.match(/dnsmasq.*config ([^\s]+) is NXDOMAIN/);
  if (nxdomainMatch) {
    return {
      domain: nxdomainMatch[1],
      ip: 'NXDOMAIN',
      status: 'BLOCKED'
    };
  }

  return null;
}

function deduplicateDnsResolutions(resolutions: DnsResolution[]): DnsResolution[] {
  const domainMap = new Map<string, DnsResolution[]>();

  // Group resolutions by domain
  for (const resolution of resolutions) {
    if (!domainMap.has(resolution.domain)) {
      domainMap.set(resolution.domain, []);
    }
    domainMap.get(resolution.domain)!.push(resolution);
  }

  const result: DnsResolution[] = [];

  // Process each domain's resolutions
  for (const [domain, domainResolutions] of domainMap) {
    // Sort by priority: RESOLVED > BLOCKED > QUERIED
    const priorityMap: { [key: string]: number } = { 'RESOLVED': 3, 'BLOCKED': 2, 'QUERIED': 1 };
    const sortedResolutions = domainResolutions.sort((a, b) =>
      (priorityMap[b.status] || 0) - (priorityMap[a.status] || 0)
    );

    const highestPriority = sortedResolutions[0];

    if (highestPriority.status === 'RESOLVED') {
      // For resolved domains, collect all unique IPs
      const resolvedIps = sortedResolutions
        .filter(r => r.status === 'RESOLVED' && r.ip !== 'CNAME')
        .map(r => r.ip);

      const uniqueIps = [...new Set(resolvedIps)];

      if (uniqueIps.length === 1) {
        // Single IP - use that resolution
        result.push(highestPriority);
      } else if (uniqueIps.length > 1) {
        // Multiple IPs - create summary entry
        result.push({
          domain: domain,
          ip: uniqueIps.join(', '),
          status: 'RESOLVED'
        });
      } else {
        // No concrete IPs (only CNAME) - use first resolved entry
        const resolvedEntry = sortedResolutions.find(r => r.status === 'RESOLVED');
        if (resolvedEntry) {
          result.push(resolvedEntry);
        }
      }
    } else {
      // Non-resolved status - use highest priority entry
      result.push(highestPriority);
    }
  }

  return result;
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

  let summary = `# Safer Runner Security Report\n\n`;

  const modeIcon = mode === 'enforce' ? '🔒' : '📊';
  summary += `**Mode:** ${modeIcon} ${mode.toUpperCase()}\n`;
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

  details += `| IP Address | Port | Status | Source |\n`;
  details += `|------------|------|--------|--------|\n`;

  const deniedCount = connections.filter(c => c.status === 'DENIED').length;

  for (const conn of connections) {
    let statusDisplay = conn.status;
    if (conn.status === 'DENIED') {
      statusDisplay = `🚫 ${conn.status}`;
    }
    details += `| ${conn.ip} | ${conn.port} | ${statusDisplay} | ${conn.source} |\n`;
  }

  details += `\n**Total connections:** ${connections.length}`;
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

  details += `| Domain | IP Address(es) | Status |\n`;
  details += `|--------|----------------|--------|\n`;

  const blockedCount = dnsResolutions.filter(d => d.status === 'BLOCKED').length;

  for (const dns of dnsResolutions) {
    let status = dns.status;
    if (dns.status === 'BLOCKED') {
      status = `🚫 NXDOMAIN (Filtered)`;
    }

    // Format IP addresses with <br/> separation for readability
    let formattedIps = dns.ip;
    if (dns.ip.includes(', ')) {
      formattedIps = dns.ip.split(', ').join('<br/>');
    }

    details += `| ${dns.domain} | ${formattedIps} | ${status} |\n`;
  }

  details += `\n**Total domains:** ${dnsResolutions.length}`;
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