/**
 * Report Formatter for Safer Runner Action
 *
 * Generates markdown-formatted security reports from network connections and DNS resolutions.
 * All functions are pure (no I/O, no side effects) for maximum testability.
 */

import { NetworkConnection } from '../parsers/network-parser';
import { DnsResolution } from '../parsers/dns-parser';
import { isGitHubRelated } from '../parsers/github-parser';
import { generateSudoersConfig, type SudoCommand } from '../parsers/sudo-parser';
import { RUNNER_USERNAME } from '../sudo';

/**
 * Generate network connection table (without heading)
 *
 * @param connections - List of network connections
 * @returns Markdown-formatted network connection table with statistics
 */
export function generateNetworkConnectionTable(connections: NetworkConnection[]): string {
  if (connections.length === 0) {
    return `No network connections recorded.\n\n`;
  }

  let table = '';

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

    table += `| IP Address | Port | Protocol | Status | Source |\n`;
    table += `|------------|------|----------|--------|--------|\n`;

    for (const conn of uniqueImportant) {
      const statusDisplay = formatConnectionStatus(conn.status);
      table += `| ${conn.ip} | ${conn.port} | ${conn.protocol} | ${statusDisplay} | ${conn.source} |\n`;
    }
    table += `\n`;
  }

  // Show GitHub connections in collapsed section
  if (githubConnections.length > 0) {
    table += `<details>\n<summary>📋 GitHub Infrastructure Connections (${githubConnections.length}) - Click to expand</summary>\n\n`;
    table += `| IP Address | Port | Protocol | Status | Source |\n`;
    table += `|------------|------|----------|--------|--------|\n`;

    for (const conn of githubConnections) {
      const statusDisplay = formatConnectionStatus(conn.status);
      table += `| ${conn.ip} | ${conn.port} | ${conn.protocol} | ${statusDisplay} | ${conn.source} |\n`;
    }
    table += `\n</details>\n\n`;
  }

  const deniedCount = connections.filter(c => c.status === 'DENIED').length;
  table += `**Total connections:** ${connections.length}`;
  if (deniedCount > 0) {
    table += ` (🛡️ ${deniedCount} blocked)`;
  }
  table += `\n\n`;

  return table;
}

/**
 * Generate network connection section with heading
 *
 * @param connections - List of network connections
 * @returns Markdown-formatted network connection section with heading and table
 */
export function generateNetworkConnectionDetails(connections: NetworkConnection[]): string {
  let details = `## Network Connection Details\n\n`;
  details += generateNetworkConnectionTable(connections);
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
 * Generate DNS resolution section with heading
 *
 * @param dnsResolutions - List of DNS resolutions
 * @returns Markdown-formatted DNS section with heading and table
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
 * @param sudoCommands - List of sudo commands executed (optional)
 * @returns Markdown-formatted configuration advice
 */
export function generateConfigurationAdvice(dnsResolutions: DnsResolution[], sudoCommands?: SudoCommand[]): string {
  const suggestedDomains = extractAllowedDomains(dnsResolutions);

  let advice = `## Configuration Advice\n\n`;

  // Determine if we have any configuration to suggest
  const hasDomains = suggestedDomains.length > 0;
  const hasSudoCommands = sudoCommands && sudoCommands.length > 0;
  const noSudoCommands = sudoCommands && sudoCommands.length === 0;

  // If no domains and no sudo usage, keep it minimal
  if (!hasDomains && !hasSudoCommands && !noSudoCommands) {
    advice += `No additional domains detected for allowlist configuration.\n\n`;
    return advice;
  }

  // Single unified configuration example
  if (hasSudoCommands) {
    advice += `Your workflow used **${sudoCommands!.length}** sudo command${sudoCommands!.length === 1 ? '' : 's'}`;
    if (hasDomains) {
      advice += ` and accessed **${suggestedDomains.length}** external domain${suggestedDomains.length === 1 ? '' : 's'}`;
    }
    advice += `. To run in enforce mode:\n\n`;
  } else if (noSudoCommands && hasDomains) {
    advice += `Your workflow accessed **${suggestedDomains.length}** external domain${suggestedDomains.length === 1 ? '' : 's'}`;
    advice += ` and did not use sudo. To run in enforce mode:\n\n`;
  } else if (noSudoCommands && !hasDomains) {
    advice += `No external domains or sudo commands were used. To run in enforce mode with sudo disabled:\n\n`;
  } else if (hasDomains && !sudoCommands) {
    advice += `To run in enforce mode with the domains accessed in this workflow:\n\n`;
  }

  // Generate unified configuration
  advice += '```yaml\n';
  advice += `- uses: portswigger-tim/safer-runner-action@v1\n`;
  advice += `  with:\n`;
  advice += `    mode: enforce\n`;

  // Add allowed-domains if we have them
  if (hasDomains) {
    advice += `    allowed-domains: |\n`;
    for (const domain of suggestedDomains) {
      advice += `      ${domain}\n`;
    }
  }

  // Add sudo configuration if we have commands
  if (hasSudoCommands) {
    advice += `    sudo-config: |\n`;

    // Use the sudo-parser's generateSudoersConfig function
    const sudoersConfig = generateSudoersConfig(sudoCommands!, RUNNER_USERNAME);
    const lines = sudoersConfig.split('\n');
    for (const line of lines) {
      if (line.trim()) {
        advice += `      ${line}\n`;
      }
    }
  } else if (noSudoCommands) {
    // Suggest disabling sudo if not used
    advice += `    disable-sudo: true\n`;
  }

  advice += '```\n\n';

  // Add security note if we have actual restrictions
  if (hasDomains || hasSudoCommands || noSudoCommands) {
    advice += `> **Security Note**: This configuration follows the principle of least privilege`;
    if (hasDomains && hasSudoCommands) {
      advice += ` by restricting network access to specific domains and sudo access to specific commands.\n\n`;
    } else if (hasDomains && noSudoCommands) {
      advice += ` by restricting network access to specific domains and disabling sudo access.\n\n`;
    } else if (hasSudoCommands) {
      advice += ` by restricting sudo access to specific commands.\n\n`;
    } else if (noSudoCommands) {
      advice += ` by disabling sudo access.\n\n`;
    } else {
      advice += `.\n\n`;
    }
  }

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
 * Deduplicates and sorts IP addresses
 *
 * @param ipString - IP address string (may be comma-separated)
 * @returns Formatted IP address string with HTML line breaks
 */
export function formatIpAddresses(ipString: string): string {
  if (ipString.includes(', ')) {
    // Split, deduplicate, sort, and join with line breaks
    const ips = ipString.split(', ').map(ip => ip.trim());
    const uniqueIps = [...new Set(ips)].sort();
    return uniqueIps.join('<br/>');
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
    case 'ALLOWED':
      return '✅';
    case 'DENIED':
      return '❌';
    case 'ANALYZED':
      return '📊';
    default:
      return '❓';
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
    case 'RESOLVED':
      return '✅';
    case 'BLOCKED':
      return '🚫';
    case 'QUERIED':
      return '❓';
    default:
      return '❓';
  }
}
