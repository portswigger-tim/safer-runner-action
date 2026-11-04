/**
 * GitHub Domain Parser
 *
 * Identifies GitHub infrastructure domains and filters them from configuration suggestions.
 * This prevents legitimate GitHub domains from appearing in user configuration advice.
 */

/**
 * Stable GitHub-owned core domains that are always allowed.
 *
 * These are either GitHub-controlled domains (safe to match with subdomains) or
 * specific GitHub-registered names. They do NOT include the dynamic results-storage
 * (productionresultssa*) accounts, which live in getProductionResultsStorageDomains()
 * and are preferably sourced from api.github.com/meta at runtime.
 */
const GITHUB_CORE_DOMAINS: string[] = [
  'github.com',
  'actions.githubusercontent.com',
  'api.github.com',
  'codeload.github.com',
  'pkg.actions.githubusercontent.com',
  'ghcr.io',
  'results-receiver.actions.githubusercontent.com',
  'objects.githubusercontent.com',
  'objects-origin.githubusercontent.com',
  'github-releases.githubusercontent.com',
  'github-registry-files.githubusercontent.com',
  'pkg.github.com',
  'pkg-containers.githubusercontent.com',
  'github-cloud.githubusercontent.com',
  'github-cloud.s3.amazonaws.com',
  // githubapp.com is GitHub-owned at the DNS level (unlike the shared blob.core.windows.net
  // namespace), so matching it + subdomains is safe - this mirrors GitHub's own
  // api.github.com/meta .domains.actions list (which wildcards *.githubapp.com). Covers
  // dependabot, artifact-attestation (fulcio/timestamp), and hosted-compute orchestrators.
  'githubapp.com',
  'release-assets.githubusercontent.com',
  'api.snapcraft.io'
];

/**
 * Over-broad, multi-tenant domain suffixes that must NEVER be allowlisted wholesale,
 * even if a future api.github.com/meta response lists them. These are shared global
 * namespaces (anyone can create a sibling name under them), so allowing the bare
 * suffix would turn enforce mode into an open exfiltration channel. Specific names
 * under them (e.g. productionresultssa100.blob.core.windows.net) are fine; the bare
 * suffix is not.
 */
const DANGEROUS_BROAD_DOMAINS: ReadonlySet<string> = new Set([
  'windows.net',
  'core.windows.net',
  'blob.core.windows.net',
  'githubusercontent.com', // we curate specific subdomains and block raw./gist. explicitly
  'amazonaws.com',
  's3.amazonaws.com',
  'blob.storage.azure.net'
]);

/**
 * The static fallback list of GitHub Actions results-storage accounts in use, from
 * https://api.github.com/meta (.domains.actions) on 2026-11-04.
 *
 * Expressed as the exact contiguous blocks GitHub registers. The gaps between blocks
 * are deliberate and must be preserved.
 *
 * SECURITY: do NOT pad this range or fill the gaps (e.g. sa20-29, sa50-99, sa200+ are
 * currently unused). Azure storage account names are a single global, first-come
 * namespace, so any name GitHub has not registered can be claimed by anyone - allowing
 * an unused name here would turn enforce mode into an exfiltration channel to an
 * attacker-controlled bucket. A stale list fails safe (a new GitHub account is blocked
 * until we add it); a padded list does not. At runtime resolveGitHubDomains() prefers
 * the live meta list over this snapshot.
 */
function getProductionResultsStorageDomains(): string[] {
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
 * Get the static list of GitHub required domains that are always allowed.
 *
 * This is the offline fallback used when the live api.github.com/meta list cannot be
 * fetched (see resolveGitHubDomains()).
 */
export function getGitHubRequiredDomains(): string[] {
  return [...GITHUB_CORE_DOMAINS, ...getProductionResultsStorageDomains()];
}

/**
 * Normalise a domain from api.github.com/meta into a dnsmasq-usable base domain,
 * or return null if it must be dropped.
 *
 * - Leading "*." is stripped: dnsmasq's server=/domain/ rule already matches the
 *   domain and all of its subdomains.
 * - Entries that are still wildcards, empty, or an over-broad shared suffix
 *   (DANGEROUS_BROAD_DOMAINS) are dropped.
 */
export function normalizeMetaDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/^\*\./, '');
  if (!d || d.includes('*')) return null;
  if (DANGEROUS_BROAD_DOMAINS.has(d)) return null;
  return d;
}

/**
 * Fetch the GitHub Actions domain allowlist from api.github.com/meta.
 *
 * Uses the `.domains.actions` section - GitHub's recommended middle tier, which
 * wildcards GitHub-owned domains but enumerates shared-namespace ones (e.g. the
 * productionresultssa* storage accounts) specifically. We deliberately do NOT use
 * `.domains.actions_inbound.wildcard_domains`, which contains *.core.windows.net and
 * *.githubusercontent.com and would re-open the exfiltration surface.
 *
 * @returns the normalised domain list, or null on any failure (caller falls back to static).
 */
export async function fetchGitHubActionsDomains(timeoutMs = 10000): Promise<string[] | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch('https://api.github.com/meta', {
        signal: controller.signal,
        headers: {
          accept: 'application/vnd.github+json',
          'user-agent': 'safer-runner-action'
        }
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return null;
    const data = (await res.json()) as { domains?: { actions?: unknown } };
    const actions = data?.domains?.actions;
    if (!Array.isArray(actions) || actions.length === 0) return null;

    const normalized = actions
      .filter((d): d is string => typeof d === 'string')
      .map(normalizeMetaDomain)
      .filter((d): d is string => d !== null);

    return normalized.length > 0 ? Array.from(new Set(normalized)) : null;
  } catch {
    return null;
  }
}

/**
 * Resolve the GitHub allowlist, preferring the live api.github.com/meta list and
 * falling back to the static snapshot if the fetch fails.
 *
 * On success the GitHub-owned core domains are unioned with the live meta list, so
 * the dynamic results-storage (productionresultssa*) accounts always match exactly
 * what GitHub currently registers - no stale entries, no padding. On failure we use
 * the static list, which fails safe (a newly-added GitHub account is blocked until
 * we ship an update, rather than anything extra being allowed).
 */
export async function resolveGitHubDomains(): Promise<{ domains: string[]; source: 'meta' | 'static' }> {
  const fetched = await fetchGitHubActionsDomains();
  if (fetched && fetched.length > 0) {
    return { domains: Array.from(new Set([...GITHUB_CORE_DOMAINS, ...fetched])), source: 'meta' };
  }
  return { domains: getGitHubRequiredDomains(), source: 'static' };
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
