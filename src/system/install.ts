/**
 * Pinned, sha256-verified downloads of the release tarballs the services run (mitmproxy, CoreDNS).
 */

import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { realHost, sleep, sudo, timed, type Host } from './host';

export const DOWNLOAD_ATTEMPTS = 5;
/** per attempt, the response body included */
export const DOWNLOAD_TIMEOUT_MS = 60_000;
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_MAX_MS = 10_000;

/** A downloaded artefact that is not the pinned one: never retried. */
class DigestMismatch extends Error {}

/**
 * The wait before retry `n` (1-based): exponential from 1s, capped at 10s, with jitter (50-150%)
 * so many jobs hitting the same outage do not retry in step. About 15s in all before the 5th.
 */
export function backoffMs(n: number, random: () => number = Math.random): number {
  return Math.round(Math.min(BACKOFF_BASE_MS * 2 ** (n - 1), BACKOFF_MAX_MS) * (0.5 + random()));
}

/** Where a pinned artefact can be downloaded from. */
export interface DownloadSource {
  url: string;
  /** a GitHub REST API release-asset URL: needs `Accept: application/octet-stream` */
  api?: boolean;
}

/** One request: the body, or an error (HTTP status, network, timeout). */
async function fetchOnce(src: DownloadSource): Promise<Buffer> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), DOWNLOAD_TIMEOUT_MS);
  try {
    const res = await fetch(src.url, {
      signal: abort.signal,
      // the GitHub API refuses requests without a User-Agent; no credentials are ever sent
      headers: { 'user-agent': 'safer-runner-action', ...(src.api ? { accept: 'application/octet-stream' } : {}) }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  } catch (e) {
    if (abort.signal.aborted) throw new Error(`timed out after ${DOWNLOAD_TIMEOUT_MS / 1000}s`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Download a pinned release artefact and verify its sha256 before anything touches it. Each
 * round tries every source in order, moving straight to the next on any failure; there are
 * DOWNLOAD_ATTEMPTS rounds, with backoff between them. A source that serves the wrong digest is
 * not tried again (and nothing from it is written); every source is checked against the same
 * pin. When every source has failed, setup fails.
 */
export async function downloadVerified(
  sources: readonly DownloadSource[],
  sha256: string,
  dest: string,
  label: string
): Promise<void> {
  await timed(`download ${label}`, async () => {
    let lastError: unknown;
    const mismatched = new Set<DownloadSource>();
    for (let round = 1; round <= DOWNLOAD_ATTEMPTS && mismatched.size < sources.length; round++) {
      if (round > 1) await sleep(backoffMs(round - 1));
      for (const src of sources) {
        if (mismatched.has(src)) continue;
        const from = new URL(src.url).host;
        try {
          const buf = await fetchOnce(src);
          const digest = crypto.createHash('sha256').update(buf).digest('hex');
          if (digest !== sha256) {
            mismatched.add(src);
            throw new DigestMismatch(`sha256 mismatch for ${src.url}: got ${digest}, want ${sha256}`);
          }
          fs.writeFileSync(dest, buf);
          core.info(`${label}: downloaded from ${from}, sha256 verified`);
          return;
        } catch (e) {
          lastError = e;
          core.warning(`${label} download from ${from} failed (attempt ${round}/${DOWNLOAD_ATTEMPTS}): ${e}`);
        }
      }
    }
    throw new Error(`could not download ${label}: ${lastError}`);
  });
}

/**
 * Install one binary from a pinned, sha256-verified release tarball, root-owned 0755.
 * Skipped if the destination already exists (a re-run on the same VM).
 */
export async function installPinnedBinary(
  sources: readonly DownloadSource[],
  sha256: string,
  member: string,
  dest: string,
  label: string,
  h: Host = realHost
): Promise<void> {
  if (fs.existsSync(dest)) {
    core.info(`${label} already installed at ${dest}`);
    return;
  }
  const tmp = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || '/tmp', 'safer-runner-'));
  const tarball = path.join(tmp, `${label}.tar.gz`);
  await downloadVerified(sources, sha256, tarball, label);
  await timed(`extract ${label}`, async () => {
    await h.run('tar', ['-xzf', tarball, '-C', tmp, member]);
    await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', path.dirname(dest)], {}, h);
    await sudo(['install', '-m', '0755', '-o', 'root', '-g', 'root', path.join(tmp, member), dest], {}, h);
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}
