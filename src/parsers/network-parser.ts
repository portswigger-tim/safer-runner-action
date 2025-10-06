/**
 * Network Log Parser
 *
 * Parses iptables logs from dedicated log files to extract network connection attempts.
 * Identifies connections by status (ALLOWED, DENIED, ANALYZED) and source
 * (GitHub Required, User Defined, Firewall Drop, Monitor Only).
 */

import * as core from '@actions/core';
import * as fs from 'fs';

export interface NetworkConnection {
  ip: string;
  port: string;
  protocol: string;
  status: string;
  source: string;
}

/**
 * Parse network logs from dedicated log file to extract connection attempts
 */
export async function parseNetworkLogs(logFile: string = '/tmp/main-iptables.log'): Promise<NetworkConnection[]> {
  try {
    // Read log file content (no sudo required - file is world-readable)
    if (!fs.existsSync(logFile)) {
      core.warning(`Network log file not found: ${logFile}`);
      return [];
    }

    const logContent = fs.readFileSync(logFile, 'utf8');
    return parseNetworkLogsFromString(logContent);
  } catch (error) {
    core.warning(`Failed to parse network logs from ${logFile}: ${error}`);
    return [];
  }
}

/**
 * Parse pre-hook network logs from dedicated log file to extract connection attempts
 */
export async function parsePreHookNetworkLogs(logFile: string = '/tmp/pre-iptables.log'): Promise<NetworkConnection[]> {
  try {
    // Read log file content (no sudo required - file is world-readable)
    if (!fs.existsSync(logFile)) {
      core.warning(`Pre-hook network log file not found: ${logFile}`);
      return [];
    }

    const logContent = fs.readFileSync(logFile, 'utf8');
    return parseNetworkLogsFromString(logContent);
  } catch (error) {
    core.warning(`Failed to parse pre-hook network logs from ${logFile}: ${error}`);
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
  } else if (line.includes('Main-GitHub-Allow: ')) {
    status = 'ALLOWED';
    source = 'GitHub Required';
  } else if (line.includes('Main-User-Allow: ')) {
    status = 'ALLOWED';
    source = 'User Defined';
  } else if (line.includes('Main-Drop-Enforce: ')) {
    status = 'DENIED';
    source = 'Firewall Drop';
  } else if (line.includes('Main-Allow-Analyze: ')) {
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
