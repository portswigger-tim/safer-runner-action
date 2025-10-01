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
}

/**
 * Parse DNS logs from syslog to extract domain resolutions
 */
export async function parseDnsLogs(): Promise<DnsResolution[]> {
  try {
    // Get DNS-related logs from syslog
    let syslogOutput = '';
    await exec.exec('sudo', ['grep', '-E', 'query\\[A\\]|reply|config.*NXDOMAIN', '/var/log/syslog'], {
      listeners: {
        stdout: (data) => { syslogOutput += data.toString(); }
      },
      ignoreReturnCode: true
    });

    return parseDnsLogsFromString(syslogOutput);

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
  return deduplicateDnsResolutions(resolutions).slice(0, 20);
}

/**
 * Parse DNS log lines and track request chains to identify final resolutions
 */
export function parseRequestChains(lines: string[]): DnsResolution[] {
  // Map of request ID to request chain
  const requestChains = new Map<string, {
    queriedDomain: string;
    ips: string[];
    status: string;
  }>();

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
          status: 'QUERIED'
        });
      }
      continue;
    }

    // Parse reply with IPv4 address - this is the final resolution
    const ipReplyMatch = line.match(new RegExp(`reply [^\\s]+ is (${ipv4Pattern})`));
    if (ipReplyMatch && requestChains.has(requestId)) {
      const chain = requestChains.get(requestId)!;
      chain.ips.push(ipReplyMatch[1]);
      chain.status = 'RESOLVED';
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

    // Ignore CNAME entries - we only care about the final IPv4 resolution
  }

  // Convert request chains to DnsResolution objects
  const resolutions: DnsResolution[] = [];
  for (const chain of requestChains.values()) {
    if (chain.ips.length > 0) {
      resolutions.push({
        domain: chain.queriedDomain,
        ip: chain.ips.length === 1 ? chain.ips[0] : chain.ips.join(', '),
        status: chain.status
      });
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
