import { compilePattern, matchesAny } from '../policy';
import { GITHUB_ACTIONS_DOMAINS } from './github-domains.generated';
import {
  DANGEROUS_BROAD_DOMAINS,
  GITHUB_EXTRAS,
  getGitHubRequiredDomains,
  normalizeMetaDomain,
  fetchGitHubActionsDomains,
  resolveGitHubDomains
} from './github-parser';

describe('GitHub Parser', () => {
  describe('getGitHubRequiredDomains (generated meta snapshot + extras)', () => {
    const domains = getGitHubRequiredDomains();

    it('is the generated snapshot (normalised like the live list) plus the extras, de-duplicated', () => {
      const snapshot = GITHUB_ACTIONS_DOMAINS.map(normalizeMetaDomain).filter(d => d !== null);
      expect(domains).toEqual(expect.arrayContaining([...snapshot, ...GITHUB_EXTRAS]));
      expect(new Set(domains).size).toBe(domains.length);
    });

    it('the only wildcards are the three meta itself lists', () => {
      expect(domains.filter(d => d.includes('*')).sort()).toEqual([
        '*.actions.githubusercontent.com',
        '*.github.com',
        '*.githubapp.com'
      ]);
    });

    it('extras are exact names', () => {
      expect(GITHUB_EXTRAS.filter(d => d.includes('*'))).toEqual([]);
    });

    it('never contains an over-broad shared namespace', () => {
      for (const d of domains) {
        expect(DANGEROUS_BROAD_DOMAINS.has(d.replace(/^\*\./, ''))).toBe(false);
      }
    });

    it('enumerates storage accounts exactly (no account-name globs)', () => {
      const sa = domains.filter(d => d.startsWith('productionresultssa'));
      expect(sa.length).toBeGreaterThan(0);
      for (const d of sa) expect(d).toMatch(/^productionresultssa\d+\.blob\.core\.windows\.net$/);
    });
  });

  describe('exact-by-default coverage (the static list compiled with the proxy matcher)', () => {
    const compiled = getGitHubRequiredDomains().map(compilePattern);

    // Hosts real runners and first-party actions use (flow logs from the v2 suite on
    // ubuntu-latest/24.04/26.04 + api.github.com/meta). A miss here breaks every job.
    it.each([
      'github.com',
      'api.github.com',
      'codeload.github.com',
      'uploads.github.com',
      'npm.pkg.github.com',
      'maven.pkg.github.com',
      'tuf-repo.github.com',
      'actions.githubusercontent.com',
      'pipelines.actions.githubusercontent.com',
      'pipelinesghubeus7.actions.githubusercontent.com',
      'runnerghubeus1.actions.githubusercontent.com',
      'broker.actions.githubusercontent.com',
      'token.actions.githubusercontent.com',
      'vstoken.actions.githubusercontent.com',
      'results-receiver.actions.githubusercontent.com',
      'run-actions-3-azure-eastus.actions.githubusercontent.com',
      'hosted-compute-watchdog-prod-iad-01.githubapp.com',
      'fulcio.githubapp.com',
      'timestamp.githubapp.com',
      'ghcr.io',
      'pkg-containers.githubusercontent.com',
      'objects.githubusercontent.com',
      'release-assets.githubusercontent.com',
      'productionresultssa31.blob.core.windows.net'
    ])('allows %s', host => {
      expect(matchesAny(host, compiled)).toBe(true);
    });

    // SECURITY: subdomains of exact entries are not GitHub's to vouch for (or are a
    // different, registrable tenant), so they must not ride on the GitHub allowlist.
    it.each([
      'x.objects.githubusercontent.com',
      's3cr3t.release-assets.githubusercontent.com',
      'attacker.github-cloud.s3.amazonaws.com',
      'x.api.snapcraft.io',
      'raw.githubusercontent.com',
      'gist.githubusercontent.com',
      'user-content.githubusercontent.com',
      'githubusercontent.com',
      'attacker.blob.core.windows.net',
      'x.productionresultssa31.blob.core.windows.net',
      'evilgithub.com',
      'github.com.evil.net'
    ])('does not allow %s', host => {
      expect(matchesAny(host, compiled)).toBe(false);
    });

    it('every entry is a valid pattern', () => {
      expect(compiled.length).toBe(getGitHubRequiredDomains().length);
    });
  });

  describe('normalizeMetaDomain', () => {
    it('keeps a leading wildcard (meta *.x maps directly onto the v2 *.x pattern)', () => {
      expect(normalizeMetaDomain('*.githubapp.com')).toBe('*.githubapp.com');
      expect(normalizeMetaDomain('*.actions.githubusercontent.com')).toBe('*.actions.githubusercontent.com');
      expect(normalizeMetaDomain('github.com')).toBe('github.com');
    });

    it('keeps specific domains as-is (lowercased, trimmed)', () => {
      expect(normalizeMetaDomain('  ProductionResultsSA100.blob.core.windows.net ')).toBe(
        'productionresultssa100.blob.core.windows.net'
      );
      expect(normalizeMetaDomain('ghcr.io')).toBe('ghcr.io');
    });

    it('drops over-broad shared namespaces even if meta lists them', () => {
      // SECURITY: these are multi-tenant suffixes; allowing them wholesale is an exfil channel.
      expect(normalizeMetaDomain('*.core.windows.net')).toBeNull();
      expect(normalizeMetaDomain('*.githubusercontent.com')).toBeNull();
      expect(normalizeMetaDomain('blob.core.windows.net')).toBeNull();
      expect(normalizeMetaDomain('*.amazonaws.com')).toBeNull();
    });

    it('drops empty or still-wildcarded entries', () => {
      expect(normalizeMetaDomain('')).toBeNull();
      expect(normalizeMetaDomain('foo.*.bar.com')).toBeNull();
      expect(normalizeMetaDomain('*.')).toBeNull();
      expect(normalizeMetaDomain('*.*.github.com')).toBeNull();
    });
  });

  describe('fetchGitHubActionsDomains', () => {
    const realFetch = global.fetch;
    afterEach(() => {
      global.fetch = realFetch;
      jest.restoreAllMocks();
    });

    it('returns normalised domains from .domains.actions on success', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          domains: {
            actions: [
              '*.github.com',
              '*.githubapp.com',
              'productionresultssa200.blob.core.windows.net',
              '*.core.windows.net' // must be filtered out
            ]
          }
        })
      }) as unknown as typeof fetch;

      const result = await fetchGitHubActionsDomains();
      expect(result).toContain('*.github.com');
      expect(result).toContain('*.githubapp.com');
      expect(result).not.toContain('githubapp.com');
      expect(result).toContain('productionresultssa200.blob.core.windows.net');
      expect(result).not.toContain('core.windows.net');
      expect(result).not.toContain('*.core.windows.net');
    });

    it('returns null on a non-OK response', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: false, json: async () => ({}) }) as unknown as typeof fetch;
      expect(await fetchGitHubActionsDomains()).toBeNull();
    });

    it('returns null when the fetch throws (network/timeout)', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as unknown as typeof fetch;
      expect(await fetchGitHubActionsDomains()).toBeNull();
    });

    it('returns null when .domains.actions is missing or empty', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ domains: { actions: [] } })
      }) as unknown as typeof fetch;
      expect(await fetchGitHubActionsDomains()).toBeNull();
    });
  });

  describe('resolveGitHubDomains', () => {
    const realFetch = global.fetch;
    afterEach(() => {
      global.fetch = realFetch;
    });

    it('prefers the live meta list and unions it with the core domains', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ domains: { actions: ['productionresultssa200.blob.core.windows.net'] } })
      }) as unknown as typeof fetch;

      const { domains, source } = await resolveGitHubDomains();
      expect(source).toBe('meta');
      // the hand-curated extras always ride along
      for (const d of GITHUB_EXTRAS) expect(domains).toContain(d);
      // live account present even though it is NOT in the static snapshot
      expect(domains).toContain('productionresultssa200.blob.core.windows.net');
      // static snapshot accounts not re-added from the stale list when meta succeeds
      expect(domains).not.toContain('productionresultssa0.blob.core.windows.net');
    });

    it('falls back to the static list when the fetch fails', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch;
      const { domains, source } = await resolveGitHubDomains();
      expect(source).toBe('static');
      expect(domains).toEqual(getGitHubRequiredDomains());
      expect(domains).toContain('productionresultssa0.blob.core.windows.net');
    });
  });
});
