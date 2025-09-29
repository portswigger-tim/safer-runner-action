import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { readFileSync } from 'fs';

interface NetworkConnection {
  ip: string;
  port: string;
  status: string;
  source: string;
}

async function run(): Promise<void> {
  try {
    core.info('🔍 Analyzing network access logs...');

    // Wait for logs to be written
    await new Promise(resolve => setTimeout(resolve, 2000));

    const connections = await parseNetworkLogs();
    await generateJobSummary(connections);

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

async function generateJobSummary(connections: NetworkConnection[]): Promise<void> {
  const mode = core.getInput('mode') || 'analyze';

  let summary = `## 🛡️ Network Access Provenance\n\n`;
  summary += `**Mode:** \`${mode}\` | **DNS:** Quad9 (9.9.9.9) | **Connections:** ${connections.length}\n\n`;

  if (connections.length === 0) {
    summary += `*No network connections logged during this run.*\n\n`;
  } else {
    summary += `| Domain/IP | Port | Status | Source |\n`;
    summary += `|-----------|------|--------|--------|\n`;

    for (const conn of connections) {
      const statusIcon = getStatusIcon(conn.status);
      summary += `| ${conn.ip} | ${conn.port} | ${statusIcon} ${conn.status} | ${conn.source} |\n`;
    }
    summary += `\n`;
  }

  // Add summary statistics
  const stats = calculateStats(connections);
  summary += `### Summary\n\n`;
  summary += `- **Total connections:** ${stats.total}\n`;
  summary += `- **Allowed:** ${stats.allowed}\n`;
  summary += `- **Denied:** ${stats.denied}\n`;
  summary += `- **Analyzed:** ${stats.analyzed}\n\n`;

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

function calculateStats(connections: NetworkConnection[]) {
  return {
    total: connections.length,
    allowed: connections.filter(c => c.status === 'ALLOWED').length,
    denied: connections.filter(c => c.status === 'DENIED').length,
    analyzed: connections.filter(c => c.status === 'ANALYZED').length
  };
}

run();