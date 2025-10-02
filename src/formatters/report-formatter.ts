/**
 * Report Formatter for Safer Runner Action
 *
 * Generates markdown-formatted security reports from network connections and DNS resolutions.
 * All functions are pure (no I/O, no side effects) for maximum testability.
 */

import { NetworkConnection } from '../parsers/network-parser';
import { DnsResolution } from '../parsers/dns-parser';
import { isGitHubRelated } from '../parsers/github-parser';

/**
 * Format network connections into markdown table
 *
 * @param connections - List of network connections
 * @returns Markdown-formatted network connection details
 */
export function generateNetworkConnectionDetails(connections: NetworkConnection[]): string {
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
      const statusDisplay = formatConnectionStatus(conn.status);
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
      const statusDisplay = formatConnectionStatus(conn.status);
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

/**
 * Generate DNS resolution table (without heading)
 *
 * @param dnsResolutions - List of DNS resolutions
 * @returns Markdown-formatted DNS table with statistics
 */
export function generateDnsTable(dnsResolutions: DnsResolution[]): string {
  if (dnsResolutions.length === 0) {
    return `No DNS resolutions recorded.\n\n`;
  }

  let table = '';

  // Separate GitHub and non-GitHub DNS resolutions
  const githubDns = dnsResolutions.filter(d => isGitHubRelated(d.domain));
  const userDns = dnsResolutions.filter(d => !isGitHubRelated(d.domain));
  const blockedDns = dnsResolutions.filter(d => d.status === 'BLOCKED');

  // Show user-defined and blocked DNS first (most important)
  if (userDns.length > 0 || blockedDns.length > 0) {
    const importantDns = [...userDns, ...blockedDns];
    // Remove duplicates
    const uniqueImportant = Array.from(new Map(importantDns.map(d => [d.domain, d])).values());

    table += `| Domain | CNAME(s) | IP Address(es) | Status |\n`;
    table += `|--------|----------|----------------|--------|\n`;

    for (const dns of uniqueImportant) {
      const status = formatDnsStatus(dns.status);
      const formattedIps = formatIpAddresses(dns.ip);
      const formattedCnames = formatCnameChain(dns.cnames);
      table += `| ${dns.domain} | ${formattedCnames} | ${formattedIps} | ${status} |\n`;
    }
    table += `\n`;
  }

  // Show GitHub DNS in collapsed section
  if (githubDns.length > 0) {
    table += `<details>\n<summary>📋 GitHub Infrastructure DNS (${githubDns.length} domains) - Click to expand</summary>\n\n`;
    table += `| Domain | CNAME(s) | IP Address(es) | Status |\n`;
    table += `|--------|----------|----------------|--------|\n`;

    for (const dns of githubDns) {
      const status = formatDnsStatus(dns.status);
      const formattedIps = formatIpAddresses(dns.ip);
      const formattedCnames = formatCnameChain(dns.cnames);
      table += `| ${dns.domain} | ${formattedCnames} | ${formattedIps} | ${status} |\n`;
    }
    table += `\n</details>\n\n`;
  }

  const blockedCount = dnsResolutions.filter(d => d.status === 'BLOCKED').length;
  table += `**Total domains:** ${dnsResolutions.length}`;
  if (blockedCount > 0) {
    table += ` (🛡️ ${blockedCount} filtered)`;
  }
  table += `\n\n`;

  return table;
}

/**
 * Format DNS resolutions into markdown table with heading
 *
 * @param dnsResolutions - List of DNS resolutions
 * @returns Markdown-formatted DNS details with heading
 */
export function generateDnsDetails(dnsResolutions: DnsResolution[]): string {
  let details = `## DNS Information\n\n`;
  details += generateDnsTable(dnsResolutions);
  return details;
}

/**
 * Extract allowed domains from DNS resolutions (excludes GitHub-related domains)
 *
 * @param dnsResolutions - List of DNS resolutions
 * @returns Array of non-GitHub domains that should be allowlisted
 */
function extractAllowedDomains(dnsResolutions: DnsResolution[]): string[] {
  const allowedDomains = new Set<string>();

  for (const dns of dnsResolutions) {
    // Include resolved domains (both IPv4 and CNAME) that are not GitHub-related
    if (dns.status === 'RESOLVED' && !isGitHubRelated(dns.domain)) {
      allowedDomains.add(dns.domain);
    }
  }

  return Array.from(allowedDomains).sort();
}

/**
 * Generate configuration advice for analyze mode
 *
 * @param dnsResolutions - List of DNS resolutions to analyze
 * @returns Markdown-formatted configuration advice
 */
export function generateConfigurationAdvice(dnsResolutions: DnsResolution[]): string {
  const suggestedDomains = extractAllowedDomains(dnsResolutions);

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

/**
 * Format connection status with appropriate emoji
 *
 * @param status - Connection status
 * @returns Formatted status string with emoji
 */
export function formatConnectionStatus(status: string): string {
  if (status === 'DENIED') {
    return `🚫 ${status}`;
  }
  return status;
}

/**
 * Format DNS status with appropriate emoji
 *
 * @param status - DNS resolution status
 * @returns Formatted status string with emoji
 */
export function formatDnsStatus(status: string): string {
  if (status === 'BLOCKED') {
    return `🚫 BLOCKED`;
  }
  return status;
}

/**
 * Format IP addresses for markdown display
 * Converts comma-separated IPs to line-break separated for readability
 *
 * @param ipString - IP address string (may be comma-separated)
 * @returns Formatted IP address string with HTML line breaks
 */
export function formatIpAddresses(ipString: string): string {
  if (ipString.includes(', ')) {
    return ipString.split(', ').join('<br/>');
  }
  return ipString;
}

/**
 * Format CNAME chain for markdown display
 * Converts CNAME array to line-break separated list
 *
 * @param cnames - Optional array of CNAME domains
 * @returns Formatted CNAME chain with HTML line breaks, or '-' if no CNAMEs
 */
export function formatCnameChain(cnames?: string[]): string {
  if (!cnames || cnames.length === 0) {
    return '-';
  }
  return cnames.join('<br/>');
}

/**
 * Get status icon for network connections
 *
 * @param status - Connection status
 * @returns Emoji icon for status
 */
export function getStatusIcon(status: string): string {
  switch (status) {
    case 'ALLOWED': return '✅';
    case 'DENIED': return '❌';
    case 'ANALYZED': return '📊';
    default: return '❓';
  }
}

/**
 * Get status icon for DNS resolutions
 *
 * @param status - DNS resolution status
 * @returns Emoji icon for status
 */
export function getDnsStatusIcon(status: string): string {
  switch (status) {
    case 'RESOLVED': return '✅';
    case 'BLOCKED': return '🚫';
    case 'QUERIED': return '❓';
    default: return '❓';
  }
}
