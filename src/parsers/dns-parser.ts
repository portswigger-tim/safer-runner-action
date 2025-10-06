/**
 * DNS Log Parser
 *
 * Parses dnsmasq logs from syslog to extract DNS resolutions.
 * Tracks request chains by request ID to map domains to their final
 * IP addresses, filtering out intermediate CNAME records.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

export interface DnsResolution {
  domain: string;
  ip: string;
  status: string;
  cnames?: string[]; // Optional CNAME chain for the resolution
}

/**
 * Parse DNS logs from syslog to extract domain resolutions
 * @param logFile Optional path to a specific log file (defaults to /var/log/syslog)
 */
export async function parseDnsLogs(logFile?: string): Promise<DnsResolution[]> {
  try {
    const targetFile = logFile || '/var/log/syslog';

    // Read log file directly (no sudo required - file is world-readable)
    const fs = await import('fs');
    if (!fs.existsSync(targetFile)) {
      core.warning(`DNS log file not found: ${targetFile}`);
      return [];
    }

    const logContent = fs.readFileSync(targetFile, 'utf8');

    // Filter to DNS-related lines only
    const dnsLines = logContent
      .split('\n')
      .filter(line => line.match(/query\[A\]|reply|config.*NXDOMAIN/))
      .join('\n');

    return parseDnsLogsFromString(dnsLines);
  } catch (error) {
    core.warning(`Failed to parse DNS logs: ${error}`);
    return [];
  }
}

/**
 * Parse DNS logs from a string (for testing)
 */
export function parseDnsLogsFromString(logContent: string): DnsResolution[] {
  const lines = logContent.split('\n').filter(line => line.trim());

  // Group log entries by request ID and extract final resolutions
  const resolutions = parseRequestChains(lines);

  // Remove duplicates and limit results
  return deduplicateDnsResolutions(resolutions).slice(0, 1000);
}

/**
 * Parse DNS log lines and track request chains to identify final resolutions
 */
export function parseRequestChains(lines: string[]): DnsResolution[] {
  // Map of request ID to request chain
  const requestChains = new Map<
    string,
    {
      queriedDomain: string;
      ips: string[];
      cnames: string[];
      status: string;
    }
  >();

  // IPv4 address pattern
  const ipv4Pattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';

  for (const line of lines) {
    // Extract request ID: dnsmasq[<pid>]: <request-id> <src-ip>/<src-port>
    const requestIdMatch = line.match(/dnsmasq\[\d+\]:\s+(\d+)\s+[\d.]+\/\d+/);
    if (!requestIdMatch) continue;

    const requestId = requestIdMatch[1];

    // Parse query[A] - this is the original domain being queried
    const queryMatch = line.match(/query\[A\]\s+([^\s]+)\s+from/);
    if (queryMatch) {
      if (!requestChains.has(requestId)) {
        requestChains.set(requestId, {
          queriedDomain: queryMatch[1],
          ips: [],
          cnames: [],
          status: 'QUERIED'
        });
      }
      continue;
    }

    // Parse reply with IPv4 address - extract both domain and IP
    const ipReplyMatch = line.match(new RegExp(`reply ([^\\s]+) is (${ipv4Pattern})`));
    if (ipReplyMatch && requestChains.has(requestId)) {
      const chain = requestChains.get(requestId)!;
      const replyDomain = ipReplyMatch[1];
      const replyIp = ipReplyMatch[2];

      // Add the IP to the list
      chain.ips.push(replyIp);
      chain.status = 'RESOLVED';

      // If the domain in the reply is different from the queried domain, it's a CNAME
      if (replyDomain !== chain.queriedDomain && !chain.cnames.includes(replyDomain)) {
        chain.cnames.push(replyDomain);
      }
      continue;
    }

    // Parse CNAME records - capture intermediate CNAME targets
    const cnameMatch = line.match(/reply ([^\s]+) is <CNAME>/);
    if (cnameMatch && requestChains.has(requestId)) {
      const chain = requestChains.get(requestId)!;
      const cnameDomain = cnameMatch[1];

      // Only add if it's not the original queried domain and not already in the list
      // This captures intermediate CNAMEs that don't appear in IP reply lines
      if (cnameDomain !== chain.queriedDomain && !chain.cnames.includes(cnameDomain)) {
        chain.cnames.push(cnameDomain);
      }
      continue;
    }

    // Parse NXDOMAIN responses (blocked domains)
    const nxdomainMatch = line.match(/config ([^\s]+) is NXDOMAIN/);
    if (nxdomainMatch && requestChains.has(requestId)) {
      const chain = requestChains.get(requestId)!;
      chain.ips = ['NXDOMAIN'];
      chain.status = 'BLOCKED';
      continue;
    }
  }

  // Convert request chains to DnsResolution objects
  const resolutions: DnsResolution[] = [];
  for (const chain of requestChains.values()) {
    if (chain.ips.length > 0) {
      const resolution: DnsResolution = {
        domain: chain.queriedDomain,
        ip: chain.ips.length === 1 ? chain.ips[0] : chain.ips.join(', '),
        status: chain.status
      };

      // Only add cnames if there are any
      if (chain.cnames.length > 0) {
        resolution.cnames = chain.cnames;
      }

      resolutions.push(resolution);
    }
  }

  return resolutions;
}

/**
 * Deduplicate DNS resolutions, prioritizing RESOLVED > BLOCKED > QUERIED
 */
export function deduplicateDnsResolutions(resolutions: DnsResolution[]): DnsResolution[] {
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
    const priorityMap: { [key: string]: number } = { RESOLVED: 3, BLOCKED: 2, QUERIED: 1 };
    const sortedResolutions = domainResolutions.sort(
      (a, b) => (priorityMap[b.status] || 0) - (priorityMap[a.status] || 0)
    );

    const highestPriority = sortedResolutions[0];

    if (highestPriority.status === 'RESOLVED') {
      // For resolved domains, collect all unique IPs
      const resolvedIps = sortedResolutions.filter(r => r.status === 'RESOLVED' && r.ip !== 'CNAME').map(r => r.ip);

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
