import { readFileSync } from 'fs';
import { join } from 'path';
import {
  parseNetworkLogsFromString,
  parseLogLine,
  deduplicateConnections,
  NetworkConnection
} from './network-parser';

describe('Network Parser', () => {
  let fixtureContent: string;

  beforeAll(() => {
    fixtureContent = readFileSync(join(__dirname, '__fixtures__', 'iptables-logs.txt'), 'utf8');
  });

  describe('parseLogLine', () => {
    it('should parse GitHub-Allow log line correctly', () => {
      const line = '2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=140.82.114.6 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=19827 DF PROTO=TCP SPT=37704 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0';

      const result = parseLogLine(line);

      expect(result).toEqual({
        ip: '140.82.114.6',
        port: '443',
        status: 'ALLOWED',
        source: 'GitHub Required'
      });
    });

    it('should parse User-Allow log line correctly', () => {
      const line = '2025-10-01T10:53:56.985342+00:00 runnervm3ublj kernel: User-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=44.195.242.49 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=32842 DF PROTO=TCP SPT=55852 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0';

      const result = parseLogLine(line);

      expect(result).toEqual({
        ip: '44.195.242.49',
        port: '443',
        status: 'ALLOWED',
        source: 'User Defined'
      });
    });

    it('should parse Drop-Enforce log line correctly', () => {
      const line = '2025-10-01T10:54:02.901847+00:00 runnervm3ublj kernel: Drop-Enforce: IN= OUT=eth0 SRC=10.1.1.103 DST=8.8.8.8 LEN=79 TOS=0x00 PREC=0x00 TTL=64 ID=9547 PROTO=UDP SPT=38809 DPT=53 LEN=59';

      const result = parseLogLine(line);

      expect(result).toEqual({
        ip: '8.8.8.8',
        port: '53',
        status: 'DENIED',
        source: 'Firewall Drop'
      });
    });

    it('should default to port 443 when DPT is missing', () => {
      const line = '2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=140.82.114.6 LEN=60';

      const result = parseLogLine(line);

      expect(result?.port).toBe('443');
    });

    it('should return null for invalid log lines', () => {
      const line = 'This is not a valid iptables log line';

      const result = parseLogLine(line);

      expect(result).toBeNull();
    });

    it('should return null for log lines without DST', () => {
      const line = '2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135';

      const result = parseLogLine(line);

      expect(result).toBeNull();
    });
  });

  describe('deduplicateConnections', () => {
    it('should remove duplicate IP:port combinations', () => {
      const connections: NetworkConnection[] = [
        { ip: '140.82.114.6', port: '443', status: 'ALLOWED', source: 'GitHub Required' },
        { ip: '140.82.114.6', port: '443', status: 'ALLOWED', source: 'GitHub Required' },
        { ip: '8.8.8.8', port: '53', status: 'DENIED', source: 'Firewall Drop' }
      ];

      const result = deduplicateConnections(connections);

      expect(result).toHaveLength(2);
      expect(result).toContainEqual({ ip: '140.82.114.6', port: '443', status: 'ALLOWED', source: 'GitHub Required' });
      expect(result).toContainEqual({ ip: '8.8.8.8', port: '53', status: 'DENIED', source: 'Firewall Drop' });
    });

    it('should keep connections with same IP but different ports', () => {
      const connections: NetworkConnection[] = [
        { ip: '140.82.114.6', port: '443', status: 'ALLOWED', source: 'GitHub Required' },
        { ip: '140.82.114.6', port: '80', status: 'ALLOWED', source: 'GitHub Required' }
      ];

      const result = deduplicateConnections(connections);

      expect(result).toHaveLength(2);
    });

    it('should handle empty array', () => {
      const result = deduplicateConnections([]);

      expect(result).toEqual([]);
    });
  });

  describe('parseNetworkLogsFromString', () => {
    it('should parse all connections from fixture', () => {
      const result = parseNetworkLogsFromString(fixtureContent);

      expect(result.length).toBeGreaterThan(0);
      expect(result.length).toBeLessThanOrEqual(20); // Respects limit
    });

    it('should identify GitHub-Allow connections', () => {
      const result = parseNetworkLogsFromString(fixtureContent);

      const githubConnections = result.filter(c => c.source === 'GitHub Required');
      expect(githubConnections.length).toBeGreaterThan(0);

      // Verify specific GitHub IP
      const apiGithub = githubConnections.find(c => c.ip === '140.82.114.6');
      expect(apiGithub).toBeDefined();
      expect(apiGithub?.status).toBe('ALLOWED');
    });

    it('should identify User-Allow connections', () => {
      const result = parseNetworkLogsFromString(fixtureContent);

      const userConnections = result.filter(c => c.source === 'User Defined');
      expect(userConnections.length).toBeGreaterThan(0);

      // Verify specific user-allowed IP
      const httpbin = userConnections.find(c => c.ip === '44.195.242.49');
      expect(httpbin).toBeDefined();
      expect(httpbin?.status).toBe('ALLOWED');
    });

    it('should identify Drop-Enforce connections', () => {
      const result = parseNetworkLogsFromString(fixtureContent);

      const deniedConnections = result.filter(c => c.source === 'Firewall Drop');
      expect(deniedConnections.length).toBeGreaterThan(0);

      // Verify blocked IPs
      const blocked = deniedConnections.find(c => c.ip === '8.8.8.8');
      expect(blocked).toBeDefined();
      expect(blocked?.status).toBe('DENIED');
    });

    it('should parse different port numbers correctly', () => {
      const result = parseNetworkLogsFromString(fixtureContent);

      // Check for port 443 (HTTPS)
      const https = result.find(c => c.port === '443');
      expect(https).toBeDefined();

      // Check for port 80 (HTTP)
      const http = result.find(c => c.port === '80');
      expect(http).toBeDefined();

      // Check for port 53 (DNS)
      const dns = result.find(c => c.port === '53');
      expect(dns).toBeDefined();
    });

    it('should handle empty log content', () => {
      const result = parseNetworkLogsFromString('');

      expect(result).toEqual([]);
    });

    it('should handle malformed log content gracefully', () => {
      const malformedLogs = `
        This is not a log line
        Neither is this
        2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=140.82.114.6 DPT=443
        More garbage
      `;

      const result = parseNetworkLogsFromString(malformedLogs);

      // Should parse the one valid line
      expect(result).toHaveLength(1);
      expect(result[0].ip).toBe('140.82.114.6');
    });

    it('should respect the 1000 connection limit', () => {
      // Create more than 1000 unique log lines
      const manyLogs = Array.from({ length: 1100 }, (_, i) =>
        `2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=140.82.114.${i % 256} DPT=${443 + (i % 100)} WINDOW=64240 RES=0x00 SYN URGP=0`
      ).join('\n');

      const result = parseNetworkLogsFromString(manyLogs);

      expect(result).toHaveLength(1000);
    });

    it('should deduplicate before applying limit', () => {
      // Create many duplicate log lines
      const duplicateLogs = Array.from({ length: 30 }, () =>
        '2025-10-01T10:53:56.665352+00:00 runnervm3ublj kernel: GitHub-Allow: IN= OUT=eth0 SRC=10.1.0.135 DST=140.82.114.6 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0'
      ).join('\n');

      const result = parseNetworkLogsFromString(duplicateLogs);

      // Should only have 1 unique connection
      expect(result).toHaveLength(1);
    });
  });
});
