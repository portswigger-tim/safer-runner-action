import { readFileSync } from 'fs';
import { join } from 'path';
import {
  parseDnsLogsFromString,
  parseRequestChains,
  deduplicateDnsResolutions,
  DnsResolution
} from './dns-parser';

describe('DNS Parser', () => {
  let fixtureContent: string;

  beforeAll(() => {
    fixtureContent = readFileSync(join(__dirname, '__fixtures__', 'dnsmasq-logs.txt'), 'utf8');
  });

  describe('parseRequestChains', () => {
    it('should parse simple domain resolution without CNAMEs', () => {
      const logs = [
        '2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 query[A] api.github.com from 127.0.0.1',
        '2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 reply api.github.com is 140.82.114.6'
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        domain: 'api.github.com',
        ip: '140.82.114.6',
        status: 'RESOLVED'
      });
      // Should not have cnames field if there are no CNAMEs
      expect(result[0].cnames).toBeUndefined();
    });

    it('should parse NXDOMAIN (blocked) domains', () => {
      const logs = [
        '2025-10-01T10:53:57.545135+00:00 runnervm3ublj dnsmasq[3001]: 10 127.0.0.1/34199 query[A] example.com from 127.0.0.1',
        '2025-10-01T10:53:57.545224+00:00 runnervm3ublj dnsmasq[3001]: 10 127.0.0.1/34199 config example.com is NXDOMAIN'
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        domain: 'example.com',
        ip: 'NXDOMAIN',
        status: 'BLOCKED'
      });
    });

    it('should track request chains by request ID', () => {
      const logs = [
        '2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 query[A] api.github.com from 127.0.0.1',
        '2025-10-01T10:53:56.816929+00:00 runnervm3ublj dnsmasq[3001]: 3 127.0.0.1/57606 query[A] github.com from 127.0.0.1',
        '2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 reply api.github.com is 140.82.114.6',
        '2025-10-01T10:53:56.820837+00:00 runnervm3ublj dnsmasq[3001]: 3 127.0.0.1/57606 reply github.com is 140.82.114.3'
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(2);
      expect(result).toContainEqual({
        domain: 'api.github.com',
        ip: '140.82.114.6',
        status: 'RESOLVED'
      });
      expect(result).toContainEqual({
        domain: 'github.com',
        ip: '140.82.114.3',
        status: 'RESOLVED'
      });
    });

    it('should handle CNAME chains and return final IP with CNAME records', () => {
      const logs = [
        '2025-10-01T10:53:56.888145+00:00 runnervm3ublj dnsmasq[3001]: 5 127.0.0.1/41452 query[A] results-receiver.actions.githubusercontent.com from 127.0.0.1',
        '2025-10-01T10:53:56.893108+00:00 runnervm3ublj dnsmasq[3001]: 5 127.0.0.1/41452 reply results-receiver.actions.githubusercontent.com is <CNAME>',
        '2025-10-01T10:53:56.894179+00:00 runnervm3ublj dnsmasq[3001]: 5 127.0.0.1/41452 reply glb-db52c2cf8be544.github.com is <CNAME>',
        '2025-10-01T10:53:56.894262+00:00 runnervm3ublj dnsmasq[3001]: 5 127.0.0.1/41452 reply glb-db52c2cf8be544.github.com is 140.82.112.21'
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        domain: 'results-receiver.actions.githubusercontent.com',
        ip: '140.82.112.21',
        status: 'RESOLVED',
        cnames: ['glb-db52c2cf8be544.github.com']
      });
    });

    it('should ignore queries without resolutions', () => {
      const logs = [
        '2025-10-01T10:53:57.483992+00:00 runnervm3ublj dnsmasq[3001]: 9 127.0.0.1/44427 query[A] localhost from 127.0.0.1'
        // No reply line
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(0);
    });

    it('should ignore NODATA-IPv6 entries', () => {
      const logs = [
        '2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 query[A] api.github.com from 127.0.0.1',
        '2025-10-01T10:53:56.664251+00:00 runnervm3ublj dnsmasq[3001]: 2 127.0.0.1/39637 reply api.github.com is NODATA-IPv6',
        '2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 reply api.github.com is 140.82.114.6'
      ];

      const result = parseRequestChains(logs);

      // Should only have the IPv4 resolution
      expect(result).toHaveLength(1);
      expect(result[0].ip).toBe('140.82.114.6');
    });

    it('should handle malformed log lines gracefully', () => {
      const logs = [
        'This is not a valid dnsmasq log line',
        '2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 query[A] api.github.com from 127.0.0.1',
        'Another invalid line',
        '2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 reply api.github.com is 140.82.114.6'
      ];

      const result = parseRequestChains(logs);

      expect(result).toHaveLength(1);
      expect(result[0].domain).toBe('api.github.com');
    });
  });

  describe('deduplicateDnsResolutions', () => {
    it('should keep single IP resolutions as-is', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'api.github.com', ip: '140.82.114.6', status: 'RESOLVED' }
      ];

      const result = deduplicateDnsResolutions(resolutions);

      expect(result).toEqual(resolutions);
    });

    it('should combine multiple IPs for same domain', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'httpbin.org', ip: '44.195.242.49', status: 'RESOLVED' },
        { domain: 'httpbin.org', ip: '34.236.61.135', status: 'RESOLVED' },
        { domain: 'httpbin.org', ip: '52.204.95.73', status: 'RESOLVED' }
      ];

      const result = deduplicateDnsResolutions(resolutions);

      expect(result).toHaveLength(1);
      expect(result[0].domain).toBe('httpbin.org');
      expect(result[0].status).toBe('RESOLVED');
      // Should combine IPs
      expect(result[0].ip).toContain('44.195.242.49');
      expect(result[0].ip).toContain('34.236.61.135');
      expect(result[0].ip).toContain('52.204.95.73');
    });

    it('should prioritize RESOLVED over BLOCKED over QUERIED', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'test.com', ip: '', status: 'QUERIED' },
        { domain: 'test.com', ip: 'NXDOMAIN', status: 'BLOCKED' },
        { domain: 'test.com', ip: '1.2.3.4', status: 'RESOLVED' }
      ];

      const result = deduplicateDnsResolutions(resolutions);

      expect(result).toHaveLength(1);
      expect(result[0].status).toBe('RESOLVED');
      expect(result[0].ip).toBe('1.2.3.4');
    });

    it('should keep BLOCKED status when no RESOLVED exists', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'blocked.com', ip: '', status: 'QUERIED' },
        { domain: 'blocked.com', ip: 'NXDOMAIN', status: 'BLOCKED' }
      ];

      const result = deduplicateDnsResolutions(resolutions);

      expect(result).toHaveLength(1);
      expect(result[0].status).toBe('BLOCKED');
      expect(result[0].ip).toBe('NXDOMAIN');
    });

    it('should handle empty array', () => {
      const result = deduplicateDnsResolutions([]);

      expect(result).toEqual([]);
    });
  });

  describe('parseDnsLogsFromString', () => {
    it('should parse all resolutions from fixture', () => {
      const result = parseDnsLogsFromString(fixtureContent);

      expect(result.length).toBeGreaterThan(0);
      expect(result.length).toBeLessThanOrEqual(20); // Respects limit
    });

    it('should identify resolved domains', () => {
      const result = parseDnsLogsFromString(fixtureContent);

      const resolved = result.filter(r => r.status === 'RESOLVED');
      expect(resolved.length).toBeGreaterThan(0);

      // Check specific known resolution
      const apiGithub = resolved.find(r => r.domain === 'api.github.com');
      expect(apiGithub).toBeDefined();
      expect(apiGithub?.ip).toBe('140.82.114.6');
    });

    it('should identify blocked domains', () => {
      const result = parseDnsLogsFromString(fixtureContent);

      const blocked = result.filter(r => r.status === 'BLOCKED');
      expect(blocked.length).toBeGreaterThan(0);

      // Check specific blocked domain
      const blockedDomain = blocked.find(r => r.domain === 'example.com' || r.domain === 'malicious-test-domain.com');
      expect(blockedDomain).toBeDefined();
      expect(blockedDomain?.ip).toBe('NXDOMAIN');
    });

    it('should handle multi-IP domains correctly', () => {
      // Test with actual multi-IP logs (same request ID, multiple replies)
      const multiIpLogs = `
2025-10-01T10:53:56.980647+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 query[A] httpbin.org from 127.0.0.1
2025-10-01T10:53:56.985035+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 44.195.242.49
2025-10-01T10:53:56.985089+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 34.236.61.135
2025-10-01T10:53:56.985166+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 34.225.98.78
2025-10-01T10:53:56.985217+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 52.204.95.73
2025-10-01T10:53:56.985277+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 98.85.20.193
2025-10-01T10:53:56.985495+00:00 runnervm3ublj dnsmasq[3001]: 7 127.0.0.1/51924 reply httpbin.org is 44.207.255.255
      `;

      const result = parseDnsLogsFromString(multiIpLogs);

      const httpbin = result.find(r => r.domain === 'httpbin.org');
      expect(httpbin).toBeDefined();
      expect(httpbin?.status).toBe('RESOLVED');

      // Should contain multiple IPs separated by commas (all from same request ID)
      const ips = httpbin?.ip.split(', ');
      expect(ips).toBeDefined();
      expect(ips!.length).toBe(6); // All 6 IPs from the same request
      expect(ips).toContain('44.195.242.49');
      expect(ips).toContain('34.236.61.135');
      expect(ips).toContain('52.204.95.73');
    });

    it('should resolve CNAME chains to final IPs', () => {
      const result = parseDnsLogsFromString(fixtureContent);

      // results-receiver.actions.githubusercontent.com goes through CNAME
      const cnameDomain = result.find(r => r.domain === 'results-receiver.actions.githubusercontent.com');
      expect(cnameDomain).toBeDefined();
      expect(cnameDomain?.status).toBe('RESOLVED');
      // Should have final IP, not <CNAME>
      expect(cnameDomain?.ip).not.toContain('CNAME');
      expect(cnameDomain?.ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    });

    it('should handle empty log content', () => {
      const result = parseDnsLogsFromString('');

      expect(result).toEqual([]);
    });

    it('should handle malformed log content gracefully', () => {
      const malformedLogs = `
        This is not a log line
        Neither is this
        2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 query[A] test.com from 127.0.0.1
        2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: 1 127.0.0.1/39637 reply test.com is 1.2.3.4
        More garbage
      `;

      const result = parseDnsLogsFromString(malformedLogs);

      // Should parse the valid query/reply pair
      expect(result).toHaveLength(1);
      expect(result[0].domain).toBe('test.com');
      expect(result[0].ip).toBe('1.2.3.4');
    });

    it('should respect the 1000 resolution limit', () => {
      // Create more than 1000 unique resolutions
      const manyLogs = Array.from({ length: 1100 }, (_, i) =>
        `2025-10-01T10:53:56.659901+00:00 runnervm3ublj dnsmasq[3001]: ${i} 127.0.0.1/39637 query[A] domain${i}.com from 127.0.0.1\n` +
        `2025-10-01T10:53:56.664651+00:00 runnervm3ublj dnsmasq[3001]: ${i} 127.0.0.1/39637 reply domain${i}.com is 1.2.3.${i % 256}`
      ).join('\n');

      const result = parseDnsLogsFromString(manyLogs);

      expect(result).toHaveLength(1000);
    });

    it('should deduplicate before applying limit', () => {
      // Create many duplicate resolutions
      const duplicateLogs = Array.from({ length: 30 }, (_, i) =>
        `2025-10-01T10:53:56.${String(i).padStart(6, '0')}+00:00 runnervm3ublj dnsmasq[3001]: ${i} 127.0.0.1/39637 query[A] test.com from 127.0.0.1\n` +
        `2025-10-01T10:53:56.${String(i + 1).padStart(6, '0')}+00:00 runnervm3ublj dnsmasq[3001]: ${i} 127.0.0.1/39637 reply test.com is 1.2.3.4`
      ).join('\n');

      const result = parseDnsLogsFromString(duplicateLogs);

      // Should only have 1 unique domain
      expect(result).toHaveLength(1);
      expect(result[0].domain).toBe('test.com');
    });
  });
});
