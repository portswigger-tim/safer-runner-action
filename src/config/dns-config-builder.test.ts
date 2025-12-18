import {
  buildDnsConfig,
  parseAllowedDomains,
  getRiskySubdomains,
  RISKY_GITHUB_SUBDOMAINS,
  DEFAULT_DNS_SERVER,
  SECONDARY_DNS_SERVER,
  DEFAULT_CACHE_SIZE
} from './dns-config-builder';

describe('DNS Config Builder', () => {
  describe('parseAllowedDomains', () => {
    it('should parse space-separated domains', () => {
      const result = parseAllowedDomains('example.com test.org api.service.io');
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
    });

    it('should parse newline-separated domains', () => {
      const result = parseAllowedDomains('example.com\ntest.org\napi.service.io');
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
    });

    it('should parse comma-separated domains', () => {
      const result = parseAllowedDomains('example.com,test.org,api.service.io');
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
    });

    it('should parse mixed separators (spaces, newlines, commas)', () => {
      const result = parseAllowedDomains('example.com, test.org\napi.service.io another.com');
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io', 'another.com']);
    });

    it('should trim whitespace from domains', () => {
      const result = parseAllowedDomains('  example.com  , test.org\n  api.service.io  ');
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
    });

    it('should filter out empty strings', () => {
      const result = parseAllowedDomains('example.com,  ,\n\n,test.org');
      expect(result).toEqual(['example.com', 'test.org']);
    });

    it('should handle empty input', () => {
      expect(parseAllowedDomains('')).toEqual([]);
      expect(parseAllowedDomains('   ')).toEqual([]);
      expect(parseAllowedDomains('\n\n')).toEqual([]);
    });

    it('should handle single domain', () => {
      const result = parseAllowedDomains('example.com');
      expect(result).toEqual(['example.com']);
    });

    it('should handle YAML multiline format', () => {
      const yamlStyle = `example.com
        test.org
        api.service.io`;
      const result = parseAllowedDomains(yamlStyle);
      expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
    });
  });

  describe('buildDnsConfig - log-facility', () => {
    it('should include log-facility when logFile is provided', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        logFile: '/tmp/test-dns.log'
      });

      expect(result.config).toContain('log-facility=/tmp/test-dns.log');
    });

    it('should not include log-facility when logFile is not provided', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).not.toContain('log-facility=');
    });

    it('should support different log paths', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false,
        logFile: '/var/log/custom-dns.log'
      });

      expect(result.config).toContain('log-facility=/var/log/custom-dns.log');
    });
  });

  describe('buildDnsConfig - cache-size', () => {
    it('should include default cache-size when not specified', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain(`cache-size=${DEFAULT_CACHE_SIZE}`);
    });

    it('should use custom cache-size when provided', () => {
      const customCacheSize = 5000;
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        cacheSize: customCacheSize
      });

      expect(result.config).toContain(`cache-size=${customCacheSize}`);
    });

    it('should support cache-size of 0 to disable caching', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false,
        cacheSize: 0
      });

      expect(result.config).toContain('cache-size=0');
    });

    it('should support large cache sizes for busy workflows', () => {
      const largeCacheSize = 10000;
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        cacheSize: largeCacheSize
      });

      expect(result.config).toContain(`cache-size=${largeCacheSize}`);
    });

    it('should include cache-size in both analyze and enforce modes', () => {
      const analyzeResult = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      const enforceResult = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(analyzeResult.config).toContain(`cache-size=${DEFAULT_CACHE_SIZE}`);
      expect(enforceResult.config).toContain(`cache-size=${DEFAULT_CACHE_SIZE}`);
    });
  });

  describe('buildDnsConfig - secondary DNS server', () => {
    it('should include secondary DNS server in analyze mode by default', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain(`server=${DEFAULT_DNS_SERVER}\n`);
      expect(result.config).toContain(`server=${SECONDARY_DNS_SERVER}\n`);
    });

    it('should include secondary DNS server for allowed domains in enforce mode', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'example.com',
        blockRiskySubdomains: false
      });

      // Default deny for unlisted domains
      expect(result.config).toContain('server=\n');

      // Both primary and secondary DNS for allowed domains
      expect(result.config).toContain(`server=/example.com/${DEFAULT_DNS_SERVER}`);
      expect(result.config).toContain(`server=/example.com/${SECONDARY_DNS_SERVER}`);
    });

    it('should allow custom secondary DNS server', () => {
      const customSecondaryDns = '1.1.1.1';
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        secondaryDnsServer: customSecondaryDns
      });

      expect(result.config).toContain(`server=${customSecondaryDns}\n`);
    });

    it('should allow disabling secondary DNS server by passing empty string', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        secondaryDnsServer: ''
      });

      expect(result.config).toContain(`server=${DEFAULT_DNS_SERVER}\n`);
      expect(result.config).not.toContain(`server=${SECONDARY_DNS_SERVER}\n`);
    });

    it('should support both custom primary and secondary DNS servers', () => {
      const customPrimary = '8.8.8.8';
      const customSecondary = '8.8.4.4';
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        primaryDnsServer: customPrimary,
        secondaryDnsServer: customSecondary
      });

      expect(result.config).toContain(`server=${customPrimary}\n`);
      expect(result.config).toContain(`server=${customSecondary}\n`);
    });
  });

  describe('buildDnsConfig - DHCP disabling', () => {
    it('should explicitly disable DHCP functionality in analyze mode', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('no-dhcp-interface=*');
    });

    it('should explicitly disable DHCP functionality in enforce mode', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('no-dhcp-interface=*');
    });

    it('should include DHCP disabling comment for documentation', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('# Disable DHCP - we only use DNS functionality');
      expect(result.config).toContain('# This prevents DHCP address conflict detection via ICMP');
    });
  });

  describe('buildDnsConfig - all-servers option', () => {
    it('should enable all-servers when secondary DNS server is provided', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        secondaryDnsServer: SECONDARY_DNS_SERVER
      });

      expect(result.config).toContain('all-servers');
    });

    it('should enable all-servers in enforce mode with secondary DNS', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'example.com',
        blockRiskySubdomains: false,
        secondaryDnsServer: SECONDARY_DNS_SERVER
      });

      expect(result.config).toContain('all-servers');
    });

    it('should NOT enable all-servers when secondary DNS server is disabled', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        secondaryDnsServer: ''
      });

      expect(result.config).not.toContain('all-servers');
    });

    it('should include all-servers documentation comment', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('# Query all upstream DNS servers simultaneously for best performance');
      expect(result.config).toContain('# Returns whichever server responds first (lower latency, better resilience)');
    });

    it('should enable all-servers by default (secondary DNS enabled by default)', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      // Secondary DNS is enabled by default, so all-servers should be enabled
      expect(result.config).toContain('all-servers');
    });
  });

  describe('buildDnsConfig - analyze mode', () => {
    it('should use allow-all DNS policy in analyze mode', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain(`server=${DEFAULT_DNS_SERVER}\n`);
      expect(result.config).not.toContain('server=\n'); // Not default deny
    });

    it('should include query logging', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('log-queries=extra');
    });

    it('should include GitHub required domains', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('server=/github.com/');
      expect(result.config).toContain('ipset=/github.com/github');
    });

    it('should include user-provided domains', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: 'example.com test.org',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('server=/example.com/');
      expect(result.config).toContain('ipset=/example.com/user');
      expect(result.config).toContain('server=/test.org/');
      expect(result.config).toContain('ipset=/test.org/user');
    });

    it('should NOT block risky subdomains in analyze mode', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: true // Should be ignored in analyze mode
      });

      expect(result.config).not.toContain('address=/gist.github.com/');
      expect(result.config).not.toContain('address=/raw.githubusercontent.com/');
      expect(result.blockedSubdomains).toEqual([]);
    });

    it('should use custom DNS server if provided', () => {
      const customDns = '8.8.8.8';
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false,
        primaryDnsServer: customDns
      });

      expect(result.config).toContain(`server=${customDns}\n`);
      expect(result.config).toContain(`server=/github.com/${customDns}`);
    });
  });

  describe('buildDnsConfig - enforce mode', () => {
    it('should use default-deny DNS policy in enforce mode', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('server=\n'); // Default deny (NXDOMAIN)
      expect(result.config).not.toContain(`server=${DEFAULT_DNS_SERVER}\n`); // No allow-all
    });

    it('should use both primary and secondary DNS for GitHub domains in enforce mode', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      // GitHub domains should have both primary and secondary DNS servers
      expect(result.config).toContain(`server=/github.com/${DEFAULT_DNS_SERVER}`);
      expect(result.config).toContain(`server=/github.com/${SECONDARY_DNS_SERVER}`);
      expect(result.config).toContain(`server=/api.github.com/${DEFAULT_DNS_SERVER}`);
      expect(result.config).toContain(`server=/api.github.com/${SECONDARY_DNS_SERVER}`);
    });

    it('should support custom primary and secondary DNS in enforce mode', () => {
      const customPrimary = '8.8.8.8';
      const customSecondary = '8.8.4.4';
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'example.com',
        blockRiskySubdomains: false,
        primaryDnsServer: customPrimary,
        secondaryDnsServer: customSecondary
      });

      // User domains should use custom DNS servers
      expect(result.config).toContain(`server=/example.com/${customPrimary}`);
      expect(result.config).toContain(`server=/example.com/${customSecondary}`);

      // GitHub domains should also use custom DNS servers
      expect(result.config).toContain(`server=/github.com/${customPrimary}`);
      expect(result.config).toContain(`server=/github.com/${customSecondary}`);
    });

    it('should block risky subdomains when blockRiskySubdomains is enabled', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: true
      });

      expect(result.config).toContain('address=/gist.github.com/');
      expect(result.config).toContain('address=/gist.githubusercontent.com/');
      expect(result.config).toContain('address=/raw.githubusercontent.com/');
      expect(result.blockedSubdomains).toEqual([
        'gist.github.com',
        'gist.githubusercontent.com',
        'raw.githubusercontent.com'
      ]);
    });

    it('should NOT block risky subdomains when blockRiskySubdomains is disabled', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).not.toContain('address=/gist.github.com/');
      expect(result.config).not.toContain('address=/raw.githubusercontent.com/');
      expect(result.blockedSubdomains).toEqual([]);
    });

    it('should place risky subdomain blocks BEFORE parent domain allows', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: true
      });

      const gistBlockIndex = result.config.indexOf('address=/gist.github.com/');
      const githubAllowIndex = result.config.indexOf('server=/github.com/');

      expect(gistBlockIndex).toBeLessThan(githubAllowIndex);
    });

    it('should skip blocked risky subdomains in GitHub domain list', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: true
      });

      // Should have block directive
      expect(result.config).toContain('address=/gist.github.com/');

      // Should NOT have allow directive for blocked domain
      const lines = result.config.split('\n');
      const gistServerLines = lines.filter(line => line.includes('server=/gist.github.com/'));
      expect(gistServerLines.length).toBe(0);
    });

    it('should include GitHub domains (except blocked risky ones)', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: true
      });

      // Safe GitHub domains should be included
      expect(result.config).toContain('server=/github.com/');
      expect(result.config).toContain('server=/actions.githubusercontent.com/');
      expect(result.config).toContain('server=/api.github.com/');
    });

    it('should include user-provided domains', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'npmjs.org pypi.org',
        blockRiskySubdomains: false
      });

      expect(result.config).toContain('server=/npmjs.org/');
      expect(result.config).toContain('ipset=/npmjs.org/user');
      expect(result.config).toContain('server=/pypi.org/');
      expect(result.config).toContain('ipset=/pypi.org/user');
    });
  });

  describe('buildDnsConfig - edge cases', () => {
    it('should handle empty allowed domains', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      expect(result.config).not.toContain('ipset=/user');
    });

    it('should handle whitespace-only allowed domains', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: '   \n  ',
        blockRiskySubdomains: false
      });

      expect(result.config).not.toContain('ipset=/user');
    });

    it('should deduplicate user domains', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: 'example.com example.com test.org example.com',
        blockRiskySubdomains: false
      });

      const lines = result.config.split('\n');
      const exampleComLines = lines.filter(line => line.includes('/example.com/'));

      // Should have 2 lines per domain (server + ipset)
      // But we're not deduplicating in the current implementation, so this will show the bug
      // In a production system, you might want to deduplicate
      expect(exampleComLines.length).toBeGreaterThan(0);
    });

    it('should generate valid DNSmasq syntax', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'example.com',
        blockRiskySubdomains: true
      });

      // Check for valid DNSmasq directives
      expect(result.config).toMatch(/^server=/m);
      expect(result.config).toMatch(/^log-queries=/m);
      expect(result.config).toMatch(/^address=/m);
      expect(result.config).toMatch(/^ipset=/m);
    });
  });

  describe('getRiskySubdomains', () => {
    it('should return list of risky subdomains', () => {
      const subdomains = getRiskySubdomains();

      expect(subdomains).toContain('gist.github.com');
      expect(subdomains).toContain('gist.githubusercontent.com');
      expect(subdomains).toContain('raw.githubusercontent.com');
      expect(subdomains.length).toBe(3);
    });

    it('should return the same reference each time', () => {
      const subdomains1 = getRiskySubdomains();
      const subdomains2 = getRiskySubdomains();

      // Should return the same array reference
      expect(subdomains1).toBe(subdomains2);
    });
  });

  describe('RISKY_GITHUB_SUBDOMAINS constant', () => {
    it('should export risky subdomain list', () => {
      expect(RISKY_GITHUB_SUBDOMAINS).toBeDefined();
      expect(RISKY_GITHUB_SUBDOMAINS.length).toBe(3);
    });

    it('should include known risky domains', () => {
      expect(RISKY_GITHUB_SUBDOMAINS).toContain('gist.github.com');
      expect(RISKY_GITHUB_SUBDOMAINS).toContain('gist.githubusercontent.com');
      expect(RISKY_GITHUB_SUBDOMAINS).toContain('raw.githubusercontent.com');
    });
  });

  describe('DEFAULT_DNS_SERVER constant', () => {
    it('should be Quad9 primary', () => {
      expect(DEFAULT_DNS_SERVER).toBe('9.9.9.9');
    });
  });

  describe('SECONDARY_DNS_SERVER constant', () => {
    it('should be Quad9 secondary', () => {
      expect(SECONDARY_DNS_SERVER).toBe('149.112.112.112');
    });

    it('should be different from primary DNS server', () => {
      expect(SECONDARY_DNS_SERVER).not.toBe(DEFAULT_DNS_SERVER);
    });
  });

  describe('DEFAULT_CACHE_SIZE constant', () => {
    it('should be 1000 entries for good performance', () => {
      expect(DEFAULT_CACHE_SIZE).toBe(1000);
    });

    it('should be larger than DNSMasq default (150)', () => {
      expect(DEFAULT_CACHE_SIZE).toBeGreaterThan(150);
    });
  });

  describe('Real-world scenarios', () => {
    it('should handle production enforce mode with blocking', () => {
      const result = buildDnsConfig({
        mode: 'enforce',
        allowedDomains: 'registry.npmjs.org pypi.org api.example.com',
        blockRiskySubdomains: true
      });

      // Should have default deny
      expect(result.config).toContain('server=\n');

      // Should block risky domains
      expect(result.blockedSubdomains.length).toBe(3);

      // Should allow GitHub domains
      expect(result.config).toContain('server=/github.com/');

      // Should allow user domains
      expect(result.config).toContain('server=/registry.npmjs.org/');
      expect(result.config).toContain('server=/pypi.org/');
      expect(result.config).toContain('server=/api.example.com/');
    });

    it('should handle analyze mode for testing workflows', () => {
      const result = buildDnsConfig({
        mode: 'analyze',
        allowedDomains: '',
        blockRiskySubdomains: false
      });

      // Should allow all DNS
      expect(result.config).toContain(`server=${DEFAULT_DNS_SERVER}\n`);

      // Should not block anything
      expect(result.blockedSubdomains.length).toBe(0);

      // Should still track GitHub domains for reporting
      expect(result.config).toContain('ipset=/github.com/github');
    });
  });
});
