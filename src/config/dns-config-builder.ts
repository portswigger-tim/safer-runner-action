/**
 * DNS Configuration Builder for DNSmasq
 *
 * Builds DNSmasq configuration strings based on mode (analyze/enforce),
 * allowed domains, and security settings. This module contains pure functions
 * for testability - it doesn't execute any commands or have side effects.
 */

import { getGitHubRequiredDomains } from '../parsers/github-parser';

/**
 * Risky GitHub subdomains that can be used for malicious payloads
 * These are blocked in enforce mode when block-risky-github-subdomains is enabled
 */
export const RISKY_GITHUB_SUBDOMAINS = [
  'gist.github.com',              // Gist web interface
  'gist.githubusercontent.com',   // CVE-2025-30066: tj-actions downloaded malicious Python from this exact domain
  'raw.githubusercontent.com'     // Common vector for serving malicious raw file content
] as const;

/**
 * Default DNS server (Quad9 - 98% malware blocking)
 */
export const DEFAULT_DNS_SERVER = '9.9.9.9';

export interface DnsConfigOptions {
  mode: 'analyze' | 'enforce';
  allowedDomains: string;
  blockRiskySubdomains: boolean;
  dnsServer?: string;
}

export interface DnsConfigResult {
  config: string;
  blockedSubdomains: string[];
}

/**
 * Parse user-provided allowed domains from input string
 * Supports both space-separated and newline-separated formats
 *
 * @param allowedDomains - Raw domain list string
 * @returns Array of trimmed, non-empty domains
 */
export function parseAllowedDomains(allowedDomains: string): string[] {
  if (!allowedDomains) {
    return [];
  }

  // Split on spaces, newlines, commas, and filter empty strings
  return allowedDomains
    .split(/[\s\n,]+/)
    .map(d => d.trim())
    .filter(d => d.length > 0);
}

/**
 * Build DNSmasq configuration string
 *
 * @param options - Configuration options
 * @returns DNSmasq configuration and list of blocked subdomains
 */
export function buildDnsConfig(options: DnsConfigOptions): DnsConfigResult {
  const { mode, allowedDomains, blockRiskySubdomains, dnsServer = DEFAULT_DNS_SERVER } = options;

  let config = `# Enable query logging for summary generation
log-queries=extra

`;

  // Configure DNS policy based on mode
  if (mode === 'enforce') {
    // NXDOMAIN all unlisted DNS (default deny)
    config += 'server=\n';
  } else {
    // Analyze mode: allow all DNS queries
    config += `server=${dnsServer}\n`;
  }

  // Track which subdomains we actually blocked
  const blockedSubdomains: string[] = [];

  // Block risky GitHub subdomains in enforce mode (if enabled)
  if (mode === 'enforce' && blockRiskySubdomains) {
    for (const subdomain of RISKY_GITHUB_SUBDOMAINS) {
      // address directive without IP returns NXDOMAIN (blocks the domain)
      // This MUST come BEFORE the parent domain server directive
      config += `address=/${subdomain}/\n`;
      blockedSubdomains.push(subdomain);
    }
  }

  // Add GitHub required domains
  const githubDomains = getGitHubRequiredDomains();
  for (const domain of githubDomains) {
    // Skip domains that are in the risky subdomain blocklist
    if (mode === 'enforce' && RISKY_GITHUB_SUBDOMAINS.includes(domain as any)) {
      continue;
    }
    config += `server=/${domain}/${dnsServer}\n`;
    config += `ipset=/${domain}/github\n`;
  }

  // Add custom allowed domains if provided
  const userDomains = parseAllowedDomains(allowedDomains);
  for (const domain of userDomains) {
    config += `server=/${domain}/${dnsServer}\n`;
    config += `ipset=/${domain}/user\n`;
  }

  return { config, blockedSubdomains };
}

/**
 * Get risky subdomain list (for logging/reporting)
 */
export function getRiskySubdomains(): readonly string[] {
  return RISKY_GITHUB_SUBDOMAINS;
}
