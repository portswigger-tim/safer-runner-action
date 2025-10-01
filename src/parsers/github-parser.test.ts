import { getGitHubRequiredDomains, isGitHubDomain, isGitHubInfrastructure, isGitHubRelated } from './github-parser';

describe('GitHub Parser', () => {
  describe('getGitHubRequiredDomains', () => {
    it('should return array of GitHub domains', () => {
      const domains = getGitHubRequiredDomains();
      expect(domains).toBeInstanceOf(Array);
      expect(domains.length).toBeGreaterThan(0);
    });

    it('should include core GitHub domains', () => {
      const domains = getGitHubRequiredDomains();
      expect(domains).toContain('github.com');
      expect(domains).toContain('actions.githubusercontent.com');
      expect(domains).toContain('api.github.com');
    });

    it('should include all productionresultssa domains', () => {
      const domains = getGitHubRequiredDomains();
      for (let i = 0; i < 20; i++) {
        expect(domains).toContain(`productionresultssa${i}.blob.core.windows.net`);
      }
    });
  });

  describe('isGitHubDomain', () => {
    const githubDomains = getGitHubRequiredDomains();

    it('should match exact GitHub domains', () => {
      expect(isGitHubDomain('github.com', githubDomains)).toBe(true);
      expect(isGitHubDomain('actions.githubusercontent.com', githubDomains)).toBe(true);
      expect(isGitHubDomain('api.github.com', githubDomains)).toBe(true);
    });

    it('should match subdomains of GitHub domains', () => {
      expect(isGitHubDomain('run-actions-3-azure-eastus.actions.githubusercontent.com', githubDomains)).toBe(true);
      expect(isGitHubDomain('subdomain.github.com', githubDomains)).toBe(true);
      expect(isGitHubDomain('api.subdomain.github.com', githubDomains)).toBe(true);
    });

    it('should NOT match non-GitHub domains', () => {
      expect(isGitHubDomain('example.com', githubDomains)).toBe(false);
      expect(isGitHubDomain('npmjs.com', githubDomains)).toBe(false);
      expect(isGitHubDomain('google.com', githubDomains)).toBe(false);
    });

    it('should NOT match domains that merely contain github.com', () => {
      // Important: 'notgithub.com' should NOT match even though it contains 'github.com'
      expect(isGitHubDomain('notgithub.com', githubDomains)).toBe(false);
      expect(isGitHubDomain('github.com.evil.com', githubDomains)).toBe(false);
    });

    it('should NOT match risky githubusercontent.com subdomains', () => {
      // These should NOT be in the githubDomains list
      expect(isGitHubDomain('raw.githubusercontent.com', githubDomains)).toBe(false);
      expect(isGitHubDomain('gist.githubusercontent.com', githubDomains)).toBe(false);
    });
  });

  describe('isGitHubInfrastructure', () => {
    it('should match Azure blob storage domains', () => {
      expect(isGitHubInfrastructure('productionresultssa0.blob.core.windows.net')).toBe(true);
      expect(isGitHubInfrastructure('something.blob.core.windows.net')).toBe(true);
    });

    it('should match Azure traffic manager domains', () => {
      expect(isGitHubInfrastructure('github-actions.trafficmanager.net')).toBe(true);
      expect(isGitHubInfrastructure('something.trafficmanager.net')).toBe(true);
    });

    it('should NOT match non-infrastructure domains', () => {
      expect(isGitHubInfrastructure('example.com')).toBe(false);
      expect(isGitHubInfrastructure('google.com')).toBe(false);
      expect(isGitHubInfrastructure('npmjs.com')).toBe(false);
    });

    it('should NOT match risky githubusercontent.com domains', () => {
      // These should NOT match infrastructure patterns
      expect(isGitHubInfrastructure('raw.githubusercontent.com')).toBe(false);
      expect(isGitHubInfrastructure('gist.githubusercontent.com')).toBe(false);
    });

    it('should NOT match safe githubusercontent.com domains', () => {
      // These are in the explicit list, not infrastructure patterns
      expect(isGitHubInfrastructure('actions.githubusercontent.com')).toBe(false);
      expect(isGitHubInfrastructure('objects.githubusercontent.com')).toBe(false);
    });
  });

  describe('isGitHubRelated', () => {
    it('should identify exact GitHub domains as related', () => {
      expect(isGitHubRelated('github.com')).toBe(true);
      expect(isGitHubRelated('actions.githubusercontent.com')).toBe(true);
    });

    it('should identify GitHub subdomains as related', () => {
      expect(isGitHubRelated('run-actions-3-azure-eastus.actions.githubusercontent.com')).toBe(true);
      expect(isGitHubRelated('subdomain.github.com')).toBe(true);
    });

    it('should identify infrastructure domains as related', () => {
      expect(isGitHubRelated('productionresultssa0.blob.core.windows.net')).toBe(true);
      expect(isGitHubRelated('something.trafficmanager.net')).toBe(true);
    });

    it('should NOT identify non-GitHub domains as related', () => {
      expect(isGitHubRelated('npmjs.com')).toBe(false);
      expect(isGitHubRelated('registry.npmjs.org')).toBe(false);
      expect(isGitHubRelated('pypi.org')).toBe(false);
    });

    it('should NOT identify risky GitHub subdomains as related', () => {
      // These should NOT be automatically excluded
      expect(isGitHubRelated('raw.githubusercontent.com')).toBe(false);
      expect(isGitHubRelated('gist.githubusercontent.com')).toBe(false);
    });

    it('should handle edge cases correctly', () => {
      expect(isGitHubRelated('')).toBe(false);
      expect(isGitHubRelated('github')).toBe(false);
      expect(isGitHubRelated('.com')).toBe(false);
    });
  });

  describe('Security considerations', () => {
    it('should exclude risky subdomains that could be used maliciously', () => {
      // These domains allow arbitrary code execution and should NOT be auto-allowed
      const riskyDomains = [
        'raw.githubusercontent.com',
        'gist.githubusercontent.com',
        'user-content.githubusercontent.com'
      ];

      for (const domain of riskyDomains) {
        expect(isGitHubRelated(domain)).toBe(false);
      }
    });

    it('should include safe GitHub infrastructure domains', () => {
      // These are legitimate GitHub Actions infrastructure
      const safeDomains = [
        'actions.githubusercontent.com',
        'objects.githubusercontent.com',
        'github-releases.githubusercontent.com',
        'run-actions-3-azure-eastus.actions.githubusercontent.com'
      ];

      for (const domain of safeDomains) {
        expect(isGitHubRelated(domain)).toBe(true);
      }
    });
  });
});
