/**
 * GitHub Domain Parser
 *
 * Identifies GitHub infrastructure domains and filters them from configuration suggestions.
 * This prevents legitimate GitHub domains from appearing in user configuration advice.
 */

/**
 * The exact GitHub Actions results-storage accounts in use, from
 * https://api.github.com/meta (.domains.actions) on 2026-11-04.
 *
 * Expressed as the exact contiguous blocks GitHub registers. The gaps between
 * blocks are deliberate and must be preserved - see the SECURITY note in
 * getGitHubRequiredDomains(). Only list numbers GitHub actually owns.
 */
function productionResultsStorageDomains(): string[] {
  const inUse: number[] = [];
  const addRange = (from: number, to: number) => {
    for (let i = from; i <= to; i++) inUse.push(i);
  };
  addRange(0, 19);
  addRange(30, 49);
  addRange(100, 199);
  return inUse.map(i => `productionresultssa${i}.blob.core.windows.net`);
}

/**
 * Get the list of GitHub required domains that are always allowed.
 * These must match the list in main.ts to ensure consistency.
 */
export function getGitHubRequiredDomains(): string[] {
  // GitHub required domains (must match main.ts)
  return [
    'github.com',
    'actions.githubusercontent.com',
    'api.github.com',
    'codeload.github.com',
    'pkg.actions.githubusercontent.com',
    'ghcr.io',
    'results-receiver.actions.githubusercontent.com',
    // GitHub Actions results storage lives in productionresultssa<N>.blob.core.windows.net
    // accounts. These are an EXPLICIT allowlist of the accounts GitHub actually registers,
    // taken from https://api.github.com/meta (.domains.actions) on 2026-11-04.
    //
    // SECURITY: do NOT pad this range or fill the gaps (e.g. sa20-29, sa50-99, sa200+ are
    // currently unused). Azure storage account names are a single global, first-come
    // namespace, so any name GitHub has not registered can be claimed by anyone - allowing
    // an unused name here would turn enforce mode into an exfiltration channel to an
    // attacker-controlled bucket. A stale list fails safe (a new GitHub account is blocked
    // until we add it); a padded list does not. v1.4.0 fetches this from api.github.com/meta
    // at runtime so it always matches exactly the in-use set.
    ...productionResultsStorageDomains(),
    'objects.githubusercontent.com',
    'objects-origin.githubusercontent.com',
    'github-releases.githubusercontent.com',
    'github-registry-files.githubusercontent.com',
    'pkg.github.com',
    'pkg-containers.githubusercontent.com',
    'github-cloud.githubusercontent.com',
    'github-cloud.s3.amazonaws.com',
    'dependabot-actions.githubapp.com',
    'release-assets.githubusercontent.com',
    'api.snapcraft.io'
  ];
}

/**
 * Check if a domain is a GitHub domain (exact match or subdomain).
 * Examples:
 * - 'actions.githubusercontent.com' matches 'actions.githubusercontent.com'
 * - 'run-actions-3-azure-eastus.actions.githubusercontent.com' is a subdomain of 'actions.githubusercontent.com'
 *
 * @param domain - The domain to check
 * @param githubDomains - List of GitHub required domains
 * @returns true if domain is an exact match or subdomain of any GitHub domain
 */
export function isGitHubDomain(domain: string, githubDomains: string[]): boolean {
  // Check exact match or if domain is a subdomain of any GitHub domain
  return githubDomains.some(ghDomain => domain === ghDomain || domain.endsWith('.' + ghDomain));
}

/**
 * Check if a domain should be excluded from configuration suggestions.
 * A domain is excluded if it's in the explicit GitHub domain list or is a subdomain.
 *
 * @param domain - The domain to check
 * @returns true if domain should be excluded from suggestions
 */
export function isGitHubRelated(domain: string): boolean {
  const githubDomains = getGitHubRequiredDomains();
  return isGitHubDomain(domain, githubDomains);
}
