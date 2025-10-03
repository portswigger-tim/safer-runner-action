import {
  generateNetworkConnectionDetails,
  generateDnsTable,
  generateConfigurationAdvice,
  formatConnectionStatus,
  formatDnsStatus,
  formatIpAddresses,
  formatCnameChain,
  getStatusIcon,
  getDnsStatusIcon
} from './report-formatter';
import { NetworkConnection } from '../parsers/network-parser';
import { DnsResolution } from '../parsers/dns-parser';

describe('Report Formatter', () => {
  describe('generateNetworkConnectionDetails', () => {
    it('should handle empty connections', () => {
      const result = generateNetworkConnectionDetails([]);

      expect(result).toContain('## Network Connection Details');
      expect(result).toContain('No network connections recorded');
    });

    it('should format single connection', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('1.2.3.4');
      expect(result).toContain('443');
      expect(result).toContain('ALLOWED');
      expect(result).toContain('User Defined');
    });

    it('should separate GitHub and user connections', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' },
        { ip: '140.82.121.3', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'GitHub Required' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      // User connections should be in main table
      expect(result).toContain('1.2.3.4');

      // GitHub connections should be in collapsed section
      expect(result).toContain('GitHub Infrastructure Connections');
      expect(result).toContain('<details>');
      expect(result).toContain('140.82.121.3');
    });

    it('should format denied connections with emoji', () => {
      const connections: NetworkConnection[] = [
        { ip: '192.168.1.1', port: '80', protocol: 'TCP', status: 'DENIED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('🚫 DENIED');
      expect(result).toContain('192.168.1.1');
    });

    it('should deduplicate connections by IP:port', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' },
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' },
        { ip: '1.2.3.4', port: '80', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      // Should have 2 unique connections (443 and 80)
      const lines = result.split('\n').filter(line => line.includes('1.2.3.4'));
      expect(lines.length).toBe(2);
    });

    it('should show total and blocked count', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' },
        { ip: '5.6.7.8', port: '80', protocol: 'TCP', status: 'DENIED', source: 'User Defined' },
        { ip: '9.10.11.12', port: '22', protocol: 'TCP', status: 'DENIED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('**Total connections:** 3');
      expect(result).toContain('(🛡️ 2 blocked)');
    });

    it('should handle analyzed connections', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ANALYZED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('ANALYZED');
      expect(result).toContain('1.2.3.4');
    });

    it('should create valid markdown tables', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('| IP Address | Port | Protocol | Status | Source |');
      expect(result).toContain('|------------|------|----------|--------|--------|');
    });
  });

  describe('generateDnsTable', () => {
    it('should handle empty DNS resolutions', () => {
      const result = generateDnsTable([]);

      expect(result).toContain('No DNS resolutions recorded');
    });

    it('should format single DNS resolution', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('example.com');
      expect(result).toContain('1.2.3.4');
      expect(result).toContain('RESOLVED');
    });

    it('should separate GitHub and user DNS', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'github.com', ip: '140.82.121.3', status: 'RESOLVED' }
      ];

      const result = generateDnsTable(resolutions);

      // User DNS should be in main table
      expect(result).toContain('example.com');

      // GitHub DNS should be in collapsed section
      expect(result).toContain('GitHub Infrastructure DNS');
      expect(result).toContain('<details>');
      expect(result).toContain('github.com');
    });

    it('should format blocked DNS with emoji', () => {
      const resolutions: DnsResolution[] = [{ domain: 'malicious.com', ip: 'NXDOMAIN', status: 'BLOCKED' }];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('🚫 BLOCKED');
      expect(result).toContain('malicious.com');
    });

    it('should format multiple IPs with line breaks', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4, 5.6.7.8, 9.10.11.12', status: 'RESOLVED' }
      ];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('1.2.3.4<br/>5.6.7.8<br/>9.10.11.12');
    });

    it('should deduplicate DNS by domain', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }
      ];

      const result = generateDnsTable(resolutions);

      const lines = result.split('\n').filter(line => line.includes('example.com'));
      expect(lines.length).toBe(1);
    });

    it('should show total and blocked count', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'blocked1.com', ip: 'NXDOMAIN', status: 'BLOCKED' },
        { domain: 'blocked2.com', ip: 'NXDOMAIN', status: 'BLOCKED' }
      ];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('**Total domains:** 3');
      expect(result).toContain('(🛡️ 2 filtered)');
    });

    it('should display CNAME chain when present', () => {
      const resolutions: DnsResolution[] = [
        {
          domain: 'example.com',
          ip: '1.2.3.4',
          status: 'RESOLVED',
          cnames: ['cdn.example.com', 'edge.cloudfront.net']
        }
      ];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('example.com');
      expect(result).toContain('1.2.3.4');
      expect(result).toContain('cdn.example.com<br/>edge.cloudfront.net');
    });

    it('should display dash when no CNAME chain', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('example.com');
      expect(result).toContain('1.2.3.4');
      // Should contain dash for empty CNAME
      expect(result).toContain(' - |');
    });

    it('should create valid markdown tables', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('| Domain | CNAME(s) | IP Address(es) | Status |');
      expect(result).toContain('|--------|----------|----------------|--------|');
    });

    it('should recognize explicit GitHub domains only', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'something.blob.core.windows.net', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'productionresultssa0.blob.core.windows.net', ip: '5.6.7.8', status: 'RESOLVED' }
      ];

      const result = generateDnsTable(resolutions);

      // Explicit productionresultssa domains should be in GitHub section
      expect(result).toContain('GitHub Infrastructure DNS');
      expect(result).toContain('productionresultssa0.blob.core.windows.net');

      // Broad patterns like 'something.blob.core.windows.net' should be in user section
      // (unless discovered via IPTables evidence)
      expect(result).toContain('something.blob.core.windows.net');
    });
  });

  describe('generateConfigurationAdvice', () => {
    it('should handle empty DNS resolutions', () => {
      const result = generateConfigurationAdvice([]);

      expect(result).toContain('## Configuration Advice');
      expect(result).toContain('No additional domains detected');
    });

    it('should filter out GitHub-related domains', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'github.com', ip: '140.82.121.3', status: 'RESOLVED' },
        { domain: 'actions.githubusercontent.com', ip: '140.82.121.4', status: 'RESOLVED' }
      ];

      const result = generateConfigurationAdvice(resolutions);

      expect(result).toContain('example.com');
      expect(result).not.toContain('github.com');
      expect(result).not.toContain('actions.githubusercontent.com');
    });

    it('should only include RESOLVED domains', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'blocked.com', ip: 'NXDOMAIN', status: 'BLOCKED' },
        { domain: 'queried.com', ip: '', status: 'QUERIED' }
      ];

      const result = generateConfigurationAdvice(resolutions);

      expect(result).toContain('example.com');
      expect(result).not.toContain('blocked.com');
      expect(result).not.toContain('queried.com');
    });

    it('should generate YAML configuration for single domain', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateConfigurationAdvice(resolutions);

      expect(result).toContain('## Configuration Advice');
      expect(result).toContain('```yaml');
      expect(result).toContain('mode: enforce');
      expect(result).toContain('allowed-domains: |');
      expect(result).toContain('      example.com');
      expect(result).toContain('```');
    });

    it('should generate YAML configuration for multiple domains', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'test.org', ip: '5.6.7.8', status: 'RESOLVED' },
        { domain: 'api.service.io', ip: '9.10.11.12', status: 'RESOLVED' }
      ];

      const result = generateConfigurationAdvice(resolutions);

      expect(result).toContain('example.com');
      expect(result).toContain('test.org');
      expect(result).toContain('api.service.io');
    });

    it('should maintain alphabetical order', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'ccc.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'aaa.com', ip: '5.6.7.8', status: 'RESOLVED' },
        { domain: 'bbb.com', ip: '9.10.11.12', status: 'RESOLVED' }
      ];

      const result = generateConfigurationAdvice(resolutions);

      const aaaIndex = result.indexOf('aaa.com');
      const bbbIndex = result.indexOf('bbb.com');
      const cccIndex = result.indexOf('ccc.com');

      expect(aaaIndex).toBeLessThan(bbbIndex);
      expect(bbbIndex).toBeLessThan(cccIndex);
    });

    it('should deduplicate domains', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' },
        { domain: 'example.com', ip: '5.6.7.8', status: 'RESOLVED' }
      ];

      const result = generateConfigurationAdvice(resolutions);

      const matches = result.match(/example\.com/g);
      expect(matches?.length).toBe(1);
    });

    it('should use correct YAML indentation', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateConfigurationAdvice(resolutions);

      // Check proper YAML indentation (6 spaces before domain)
      expect(result).toContain('      example.com');
    });

    it('should include action reference', () => {
      const resolutions: DnsResolution[] = [{ domain: 'example.com', ip: '1.2.3.4', status: 'RESOLVED' }];

      const result = generateConfigurationAdvice(resolutions);

      expect(result).toContain('portswigger-tim/safer-runner-action@v1');
    });
  });

  describe('formatConnectionStatus', () => {
    it('should add emoji for DENIED status', () => {
      expect(formatConnectionStatus('DENIED')).toBe('🚫 DENIED');
    });

    it('should not modify ALLOWED status', () => {
      expect(formatConnectionStatus('ALLOWED')).toBe('ALLOWED');
    });

    it('should not modify ANALYZED status', () => {
      expect(formatConnectionStatus('ANALYZED')).toBe('ANALYZED');
    });

    it('should handle unknown status', () => {
      expect(formatConnectionStatus('UNKNOWN')).toBe('UNKNOWN');
    });
  });

  describe('formatDnsStatus', () => {
    it('should add emoji for BLOCKED status', () => {
      expect(formatDnsStatus('BLOCKED')).toBe('🚫 BLOCKED');
    });

    it('should not modify RESOLVED status', () => {
      expect(formatDnsStatus('RESOLVED')).toBe('RESOLVED');
    });

    it('should not modify QUERIED status', () => {
      expect(formatDnsStatus('QUERIED')).toBe('QUERIED');
    });

    it('should handle unknown status', () => {
      expect(formatDnsStatus('UNKNOWN')).toBe('UNKNOWN');
    });
  });

  describe('formatIpAddresses', () => {
    it('should convert comma-separated IPs to line breaks', () => {
      const result = formatIpAddresses('1.2.3.4, 5.6.7.8, 9.10.11.12');
      expect(result).toBe('1.2.3.4<br/>5.6.7.8<br/>9.10.11.12');
    });

    it('should not modify single IP', () => {
      const result = formatIpAddresses('1.2.3.4');
      expect(result).toBe('1.2.3.4');
    });

    it('should handle CNAME', () => {
      const result = formatIpAddresses('CNAME');
      expect(result).toBe('CNAME');
    });

    it('should handle NXDOMAIN', () => {
      const result = formatIpAddresses('NXDOMAIN');
      expect(result).toBe('NXDOMAIN');
    });

    it('should handle two IPs', () => {
      const result = formatIpAddresses('1.2.3.4, 5.6.7.8');
      expect(result).toBe('1.2.3.4<br/>5.6.7.8');
    });
  });

  describe('formatCnameChain', () => {
    it('should return dash when no CNAMEs', () => {
      const result = formatCnameChain(undefined);
      expect(result).toBe('-');
    });

    it('should return dash when empty array', () => {
      const result = formatCnameChain([]);
      expect(result).toBe('-');
    });

    it('should format single CNAME', () => {
      const result = formatCnameChain(['cdn.example.com']);
      expect(result).toBe('cdn.example.com');
    });

    it('should format multiple CNAMEs with line breaks', () => {
      const result = formatCnameChain(['cdn.example.com', 'glb-12345.cloudfront.net']);
      expect(result).toBe('cdn.example.com<br/>glb-12345.cloudfront.net');
    });

    it('should format three CNAMEs with line breaks', () => {
      const result = formatCnameChain(['first.com', 'second.com', 'third.com']);
      expect(result).toBe('first.com<br/>second.com<br/>third.com');
    });
  });

  describe('getStatusIcon', () => {
    it('should return correct icon for ALLOWED', () => {
      expect(getStatusIcon('ALLOWED')).toBe('✅');
    });

    it('should return correct icon for DENIED', () => {
      expect(getStatusIcon('DENIED')).toBe('❌');
    });

    it('should return correct icon for ANALYZED', () => {
      expect(getStatusIcon('ANALYZED')).toBe('📊');
    });

    it('should return question mark for unknown status', () => {
      expect(getStatusIcon('UNKNOWN')).toBe('❓');
      expect(getStatusIcon('')).toBe('❓');
    });
  });

  describe('getDnsStatusIcon', () => {
    it('should return correct icon for RESOLVED', () => {
      expect(getDnsStatusIcon('RESOLVED')).toBe('✅');
    });

    it('should return correct icon for BLOCKED', () => {
      expect(getDnsStatusIcon('BLOCKED')).toBe('🚫');
    });

    it('should return correct icon for QUERIED', () => {
      expect(getDnsStatusIcon('QUERIED')).toBe('❓');
    });

    it('should return question mark for unknown status', () => {
      expect(getDnsStatusIcon('UNKNOWN')).toBe('❓');
      expect(getDnsStatusIcon('')).toBe('❓');
    });
  });

  describe('Edge cases and special scenarios', () => {
    it('should handle very long domain lists', () => {
      const connections: NetworkConnection[] = Array.from({ length: 100 }, (_, i) => ({
        ip: `192.168.1.${i}`,
        port: '443',
        protocol: 'TCP',
        status: 'ALLOWED',
        source: 'User Defined'
      }));

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('**Total connections:** 100');
    });

    it('should handle special characters in domains', () => {
      const resolutions: DnsResolution[] = [
        { domain: 'test-api.example-domain.com', ip: '1.2.3.4', status: 'RESOLVED' }
      ];

      const result = generateDnsTable(resolutions);

      expect(result).toContain('test-api.example-domain.com');
    });

    it('should handle mixed GitHub and user connections', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'User Defined' },
        { ip: '5.6.7.8', port: '443', protocol: 'TCP', status: 'DENIED', source: 'User Defined' },
        { ip: '140.82.121.3', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'GitHub Required' },
        { ip: '140.82.121.4', port: '443', protocol: 'TCP', status: 'ALLOWED', source: 'GitHub Required' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      // Should have both main table and collapsed section
      expect(result).toContain('| IP Address | Port | Protocol | Status | Source |');
      expect(result).toContain('<details>');
      expect(result).toContain('**Total connections:** 4');
      expect(result).toContain('(🛡️ 1 blocked)');
    });

    it('should handle all-denied connections', () => {
      const connections: NetworkConnection[] = [
        { ip: '1.2.3.4', port: '80', protocol: 'TCP', status: 'DENIED', source: 'User Defined' },
        { ip: '5.6.7.8', port: '22', protocol: 'TCP', status: 'DENIED', source: 'User Defined' }
      ];

      const result = generateNetworkConnectionDetails(connections);

      expect(result).toContain('🚫 DENIED');
      expect(result).toContain('(🛡️ 2 blocked)');
    });
  });
});
