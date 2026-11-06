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

/** One endpoint of the built-in platform allowlist: path is an http-filter path pattern. */
export interface PlatformEndpoint {
  host: string;
  path: string;
  methods: string[];
}

/**
 * Built-in platform allowlist for http-filter (docs/DESIGN-L7-path-method.md): the endpoints
 * the Actions machinery and first-party actions need, so that filtering a GitHub host does not
 * break the job's own step logs, artifacts, cache or OIDC. Applied (when allow-github-platform
 * is on) only on a host the job filters, as allows that win over the job's own rules.
 *
 * EXPLICIT (host, path, methods) only, reads included - never a blanket "*": GET, HEAD, which
 * would trust far more than the platform uses. Workflow-chosen writes (e.g. SARIF upload) are
 * NOT platform and stay user-controlled. Grow it from observed real-runner traffic (the proxy
 * flow log); a missing entry only breaks that job's platform step, never enforcement.
 */
export const GITHUB_PLATFORM_ENDPOINTS: readonly PlatformEndpoint[] = [
  // results service RPCs: step logs, step status (WorkflowStepsUpdate), artifact + cache
  { host: 'results-receiver.actions.githubusercontent.com', path: '/twirp/*', methods: ['POST'] },
  // artifact / log / cache blobs via the signed URLs the results service hands out: uploads
  // (PUT: Put Blob / Put Block / Put Block List) and downloads (GET, HEAD for properties)
  { host: 'productionresultssa*.blob.core.windows.net', path: '/actions-results/*', methods: ['GET', 'HEAD', 'PUT'] },
  { host: 'productionresultssa*.blob.core.windows.net', path: '/actions-cache/*', methods: ['GET', 'HEAD', 'PUT'] },
  // OIDC token request (ACTIONS_ID_TOKEN_REQUEST_URL)
  { host: 'run-actions-*-azure-*.actions.githubusercontent.com', path: '*/idtoken/*', methods: ['GET'] }
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
 * The meta groups the GitHub list is built from, raw (no normalisation): `.domains.actions`
 * (required) + `.domains.artifact_attestations` (GitHub's Sigstore for actions/attest-*; an
 * array, or an object with a `services` array). Null when `.domains.actions` is missing/empty.
 * Shared by the live fetch and `npm run gen:domains` so the snapshot matches the live path.
 */
export function metaDomainGroups(data: unknown): unknown[] | null {
  const domains = (data as { domains?: { actions?: unknown; artifact_attestations?: unknown } })?.domains;
  const actions = domains?.actions;
  if (!Array.isArray(actions) || actions.length === 0) return null;
  const att = domains?.artifact_attestations;
  const services = Array.isArray(att) ? att : (att as { services?: unknown })?.services;
  return [...actions, ...(Array.isArray(services) ? services : [])];
}

/**
 * Fetch the GitHub Actions domain allowlist from api.github.com/meta.
 *
 * Uses the `.domains.actions` section (+ artifact attestations, see metaDomainGroups) -
 * GitHub's recommended middle tier, which
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
    const actions = metaDomainGroups(await res.json());
    if (!actions) return null;

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
