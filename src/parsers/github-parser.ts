/**
 * The GitHub allowlist: api.github.com/meta .domains.actions (live, else the generated
 * snapshot) + a tiny hand-curated GITHUB_EXTRAS, with the guards that keep meta from ever
 * widening it into a shared namespace.
 */

import { GITHUB_ACTIONS_DOMAINS } from './github-domains.generated';

/**
 * Hosts the runner needs that api.github.com/meta .domains.actions does not list. Hand-curated
 * and kept tiny: everything GitHub states it needs comes from meta (live at runtime, else the
 * generated snapshot in github-domains.generated.ts - `npm run gen:domains`).
 *
 * Patterns are v2 allowlist syntax: a bare name is EXACT and `*.name` covers every subdomain.
 * NO wildcards here: a wildcard is a DNS channel to that zone. The only wildcards are the ones
 * meta itself lists (*.github.com, *.githubapp.com, *.actions.githubusercontent.com). A new
 * entry needs observed real-runner traffic and a one-line reason. Not even an apex "because it
 * costs nothing": meta lists github.com's apex but not actions.githubusercontent.com's or
 * githubapp.com's, so those aren't contacted.
 */
export const GITHUB_EXTRAS: readonly string[] = [
  // ghcr.io (in meta) answers blob/layer GETs with a 307 to this host: every ghcr pull
  'pkg-containers.githubusercontent.com'
];

/**
 * Risky GitHub subdomains that serve arbitrary user content (malicious payloads), refused in
 * enforce mode when block-risky-github-subdomains is on: a deny override, so `*.github.com`
 * does not let them through.
 */
export const RISKY_GITHUB_SUBDOMAINS = [
  'gist.github.com', // Gist web interface
  'gist.githubusercontent.com', // CVE-2025-30066: tj-actions downloaded malicious Python from this exact domain
  'raw.githubusercontent.com' // Common vector for serving malicious raw file content
] as const;

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
 * The offline GitHub allowlist: the generated meta snapshot plus GITHUB_EXTRAS. Used when the
 * live api.github.com/meta list cannot be fetched (see resolveGitHubDomains()).
 *
 * SECURITY: the snapshot enumerates the productionresultssa* storage accounts exactly as meta
 * lists them; never pad or range-fill them. Azure storage account names are a global,
 * first-come namespace, so an unregistered name would be an exfil channel. A stale snapshot
 * fails safe (a new account is blocked until regenerated).
 */
export function getGitHubRequiredDomains(): string[] {
  const snapshot = GITHUB_ACTIONS_DOMAINS.map(normalizeMetaDomain).filter((d): d is string => d !== null);
  return Array.from(new Set([...snapshot, ...GITHUB_EXTRAS]));
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
 * Resolve the GitHub allowlist, preferring the live api.github.com/meta list and falling back
 * to the generated snapshot if the fetch fails. GITHUB_EXTRAS are added either way. On
 * success the snapshot is NOT merged in, so the storage accounts match exactly what GitHub
 * registers today.
 */
export async function resolveGitHubDomains(): Promise<{ domains: string[]; source: 'meta' | 'static' }> {
  const fetched = await fetchGitHubActionsDomains();
  if (fetched && fetched.length > 0) {
    return { domains: Array.from(new Set([...fetched, ...GITHUB_EXTRAS])), source: 'meta' };
  }
  return { domains: getGitHubRequiredDomains(), source: 'static' };
}
