import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';

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
    await generateJobSummary(connections, dnsResolutions);

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
  // Parse standard IP address replies
  const replyMatch = line.match(/dnsmasq.*reply ([^\s]+) is ([0-9.]+)/);
  if (replyMatch) {
    return {
      domain: replyMatch[1],
      ip: replyMatch[2],
      status: 'RESOLVED'
    };
  }

  // Parse cached responses
  const cachedMatch = line.match(/dnsmasq.*cached ([^\s]+) is ([0-9.]+)/);
  if (cachedMatch) {
    return {
      domain: cachedMatch[1],
      ip: cachedMatch[2],
      status: 'RESOLVED'
    };
  }

  // Parse /etc/hosts responses
  const hostsMatch = line.match(/dnsmasq.*\/etc\/hosts ([^\s]+) is ([0-9.]+)/);
  if (hostsMatch) {
    return {
      domain: hostsMatch[1],
      ip: hostsMatch[2],
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
  const nxdomainMatch = line.match(/dnsmasq.*(?:reply|config) ([^\s]+) is NXDOMAIN/);
  if (nxdomainMatch) {
    return {
      domain: nxdomainMatch[1],
      ip: 'NXDOMAIN',
      status: 'BLOCKED'
    };
  }

  // Parse ipset additions (extracts domain and IP from ipset add lines)
  const ipsetMatch = line.match(/dnsmasq.*ipset add \w+ ([0-9.]+) ([^\s]+)/);
  if (ipsetMatch) {
    return {
      domain: ipsetMatch[2],
      ip: ipsetMatch[1],
      status: 'RESOLVED'
    };
  }

  // Parse DNS queries (A record types only)
  const queryMatch = line.match(/dnsmasq.*query\[A\] ([^\s]+) from/);
  if (queryMatch) {
    return {
      domain: queryMatch[1],
      ip: 'PENDING',
      status: 'QUERIED'
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

async function generateJobSummary(connections: NetworkConnection[], dnsResolutions: DnsResolution[]): Promise<void> {
  const mode = core.getInput('mode') || 'analyze';

  let summary = `## 🛡️ Network Access Provenance\n\n`;
  summary += `**Mode:** \`${mode}\` | **DNS:** Quad9 (9.9.9.9) | **Connections:** ${connections.length} | **DNS Queries:** ${dnsResolutions.length}\n\n`;

  // Network connections table
  if (connections.length === 0) {
    summary += `### Network Connections\n`;
    summary += `*No network connections logged during this run.*\n\n`;
  } else {
    summary += `### Network Connections\n`;
    summary += `| Domain/IP | Port | Status | Source |\n`;
    summary += `|-----------|------|--------|--------|\n`;

    for (const conn of connections) {
      const statusIcon = getStatusIcon(conn.status);
      summary += `| ${conn.ip} | ${conn.port} | ${statusIcon} ${conn.status} | ${conn.source} |\n`;
    }
    summary += `\n`;
  }

  // DNS resolutions table
  if (dnsResolutions.length === 0) {
    summary += `### DNS Resolutions\n`;
    summary += `*No DNS resolutions logged during this run.*\n\n`;
  } else {
    summary += `### DNS Resolutions\n`;
    summary += `| Domain | IP | Status |\n`;
    summary += `|--------|----|---------|\n`;

    for (const dns of dnsResolutions) {
      const statusIcon = getDnsStatusIcon(dns.status);
      const formattedIp = dns.ip.includes(', ') ? dns.ip.replace(/, /g, '<br/>') : dns.ip;
      summary += `| ${dns.domain} | ${formattedIp} | ${statusIcon} ${dns.status} |\n`;
    }
    summary += `\n`;
  }

  // Add summary statistics
  const stats = calculateStats(connections);
  const dnsStats = calculateDnsStats(dnsResolutions);
  summary += `### Summary\n\n`;
  summary += `**Network Connections:**\n`;
  summary += `- **Total:** ${stats.total}\n`;
  summary += `- **Allowed:** ${stats.allowed}\n`;
  summary += `- **Denied:** ${stats.denied}\n`;
  summary += `- **Analyzed:** ${stats.analyzed}\n\n`;

  summary += `**DNS Resolutions:**\n`;
  summary += `- **Total:** ${dnsStats.total}\n`;
  summary += `- **Resolved:** ${dnsStats.resolved}\n`;
  summary += `- **Blocked:** ${dnsStats.blocked}\n`;
  summary += `- **Queried:** ${dnsStats.queried}\n\n`;

  summary += `---\n`;
  summary += `*🔒 Secured by [Safer Runner Action](https://github.com/portswigger-tim/safer-runner-action)*\n`;

  await core.summary.addRaw(summary).write();
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

run();