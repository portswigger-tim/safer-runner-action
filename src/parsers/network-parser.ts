/**
 * Network Log Parser
 *
 * Parses iptables logs from syslog to extract network connection attempts.
 * Identifies connections by status (ALLOWED, DENIED, ANALYZED) and source
 * (GitHub Required, User Defined, Firewall Drop, Monitor Only).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

export interface NetworkConnection {
  ip: string;
  port: string;
  protocol: string;
  status: string;
  source: string;
}

/**
 * Parse network logs from syslog to extract connection attempts
 */
export async function parseNetworkLogs(): Promise<NetworkConnection[]> {
  try {
    // Get syslog content (exclude Pre- prefixed logs from pre-hook - those are analyzed separately)
    // Space before each pattern ensures we don't match Pre-GitHub-Allow: when looking for GitHub-Allow:
    let syslogOutput = '';
    await exec.exec(
      'sudo',
      ['grep', '-E', ' GitHub-Allow: | User-Allow: | Drop-Enforce: | Allow-Analyze: ', '/var/log/syslog'],
      {
        listeners: {
          stdout: data => {
            syslogOutput += data.toString();
          }
        },
        ignoreReturnCode: true
      }
    );

    return parseNetworkLogsFromString(syslogOutput);
  } catch (error) {
    core.warning(`Failed to parse logs: ${error}`);
    return [];
  }
}

/**
 * Parse pre-hook network logs from syslog to extract connection attempts
 */
export async function parsePreHookNetworkLogs(): Promise<NetworkConnection[]> {
  try {
    // Get only Pre- prefixed logs from pre-hook
    // Use space after colon to match log format and avoid partial matches
    let syslogOutput = '';
    await exec.exec(
      'sudo',
      ['grep', '-E', ' Pre-GitHub-Allow: | Pre-User-Allow: | Pre-Allow-Analyze: ', '/var/log/syslog'],
      {
        listeners: {
          stdout: data => {
            syslogOutput += data.toString();
          }
        },
        ignoreReturnCode: true
      }
    );

    return parseNetworkLogsFromString(syslogOutput);
  } catch (error) {
    core.warning(`Failed to parse pre-hook network logs: ${error}`);
    return [];
  }
}

/**
 * Parse network logs from a string (for testing)
 */
export function parseNetworkLogsFromString(logContent: string): NetworkConnection[] {
  const connections: NetworkConnection[] = [];
  const lines = logContent.split('\n').filter(line => line.trim());

  for (const line of lines) {
    const connection = parseLogLine(line);
    if (connection) {
      connections.push(connection);
    }
  }

  // Remove duplicates and limit results
  return deduplicateConnections(connections).slice(0, 1000);
}

/**
 * Parse a single iptables log line to extract connection details
 */
export function parseLogLine(line: string): NetworkConnection | null {
  // Parse iptables log format
  const ipMatch = line.match(/DST=([0-9.]+)/);
  const portMatch = line.match(/DPT=([0-9]+)/);
  const protocolMatch = line.match(/PROTO=(\w+)/);

  if (!ipMatch) return null;

  const ip = ipMatch[1];
  const port = portMatch ? portMatch[1] : '443';
  const protocol = protocolMatch ? protocolMatch[1] : 'TCP';

  let status = 'UNKNOWN';
  let source = 'Unknown';

  // Check for Pre- prefixed logs (from pre-hook monitoring)
  if (line.includes('Pre-GitHub-Allow: ')) {
    status = 'ALLOWED';
    source = 'GitHub Required';
  } else if (line.includes('Pre-User-Allow: ')) {
    status = 'ALLOWED';
    source = 'User Defined';
  } else if (line.includes('Pre-Allow-Analyze: ')) {
    status = 'ANALYZED';
    source = 'Monitor Only';
  } else if (line.includes('GitHub-Allow: ')) {
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

  return { ip, port, protocol, status, source };
}

/**
 * Remove duplicate connections (same IP:port combination)
 */
export function deduplicateConnections(connections: NetworkConnection[]): NetworkConnection[] {
  const seen = new Map<string, NetworkConnection>();

  for (const conn of connections) {
    const key = `${conn.ip}:${conn.port}`;
    if (!seen.has(key)) {
      seen.set(key, conn);
    }
  }

  return Array.from(seen.values());
}
