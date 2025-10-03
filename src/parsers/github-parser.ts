/**
 * GitHub Domain Parser
 *
 * Identifies GitHub infrastructure domains and filters them from configuration suggestions.
 * This prevents legitimate GitHub domains from appearing in user configuration advice.
 */

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
    // Add all the productionresultssa domains...
    ...Array.from({ length: 20 }, (_, i) => `productionresultssa${i}.blob.core.windows.net`),
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
