/**
 * GitHub Domain Parser
 *
 * Identifies GitHub infrastructure domains and filters them from configuration suggestions.
 * This prevents legitimate GitHub domains from appearing in user configuration advice.
 */

/**
 * Stable GitHub-owned core domains that are always allowed.
 *
 * Patterns use the v2 allowlist syntax: a bare name is EXACT (that name only) and `*.name`
 * covers every subdomain (not the apex). Before beta.5 a bare name also matched all of its
 * subdomains, so every entry was audited (against api.github.com/meta .domains.actions and
 * the hosts real runners use) when exact-by-default landed:
 *
 *  - GitHub-owned zones whose subdomains the runner or common actions use get the apex AND
 *    `*.`: github.com (api., codeload., uploads., pkg. ...), actions.githubusercontent.com
 *    (pipelines*, runner*, broker., token. (OIDC), results-receiver., vstoken. ...),
 *    githubapp.com (hosted-compute-*, dependabot, fulcio./timestamp. attestations) and
 *    ghcr.io (meta .packages lists *.ghcr.io). The apex is included even where meta lists
 *    only the wildcard: it is GitHub-owned, so it costs nothing and can't break a runner.
 *  - Everything else is exact, as meta lists it. Several of these sit under shared or
 *    third-party namespaces where suffix matching was a latent exfil channel: e.g.
 *    `<anything>.github-cloud.s3.amazonaws.com` is a different, registrable S3 bucket, and
 *    subdomains of the *.githubusercontent.com hosts are not all GitHub's to vouch for.
 *
 * The dynamic results-storage (productionresultssa*) accounts are NOT here; they live in
 * getProductionResultsStorageDomains() and are preferably sourced from api.github.com/meta.
 */
const GITHUB_CORE_DOMAINS: string[] = [
  'github.com',
  '*.github.com',
  'actions.githubusercontent.com',
  '*.actions.githubusercontent.com',
  'githubapp.com',
  '*.githubapp.com',
  'ghcr.io',
  '*.ghcr.io',
  // exact names (several are also covered by a wildcard above; listed so the static
  // fallback documents what the runner needs)
  'api.github.com',
  'codeload.github.com',
  'pkg.github.com',
  'pkg.actions.githubusercontent.com',
  'results-receiver.actions.githubusercontent.com',
  'objects.githubusercontent.com',
  'objects-origin.githubusercontent.com',
  'github-releases.githubusercontent.com',
  'github-registry-files.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'pkg-containers.githubusercontent.com',
  'github-cloud.githubusercontent.com',
  'github-cloud.s3.amazonaws.com',
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
export const DANGEROUS_BROAD_DOMAINS: ReadonlySet<string> = new Set([
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
 * Normalise a domain from api.github.com/meta into an allowlist pattern, or return null if
 * it must be dropped.
 *
 * - A leading "*." is KEPT: meta's `*.github.com` means "subdomains of github.com", which is
 *   exactly what the v2 pattern `*.github.com` means (meta lists the apex separately).
 * - Any other wildcard, an empty entry, or an over-broad shared suffix
 *   (DANGEROUS_BROAD_DOMAINS, checked on the part after "*.") is dropped.
 */
export function normalizeMetaDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase();
  const base = d.startsWith('*.') ? d.slice(2) : d;
  if (!base || base.includes('*')) return null;
  if (DANGEROUS_BROAD_DOMAINS.has(base)) return null;
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
