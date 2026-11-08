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

/** One attempt: the body, or an error (HTTP status, network, timeout). */
async function fetchOnce(url: string): Promise<Buffer> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), DOWNLOAD_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: abort.signal });
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
 * Download a pinned release artefact and verify its sha256 before anything touches it. Network
 * errors, HTTP errors and timeouts are retried with backoff (DOWNLOAD_ATTEMPTS in all); a digest
 * mismatch fails at once.
 */
export async function downloadVerified(url: string, sha256: string, dest: string, label: string): Promise<void> {
  await timed(`download ${label}`, async () => {
    let lastError: unknown;
    for (let attempt = 1; attempt <= DOWNLOAD_ATTEMPTS; attempt++) {
      if (attempt > 1) await sleep(backoffMs(attempt - 1));
      try {
        const buf = await fetchOnce(url);
        const digest = crypto.createHash('sha256').update(buf).digest('hex');
        if (digest !== sha256) {
          throw new DigestMismatch(`sha256 mismatch for ${url}: got ${digest}, want ${sha256}`);
        }
        fs.writeFileSync(dest, buf);
        return;
      } catch (e) {
        lastError = e;
        if (e instanceof DigestMismatch) break;
        core.warning(`${label} download attempt ${attempt}/${DOWNLOAD_ATTEMPTS} failed: ${e}`);
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
  url: string,
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
  await downloadVerified(url, sha256, tarball, label);
  await timed(`extract ${label}`, async () => {
    await h.run('tar', ['-xzf', tarball, '-C', tmp, member]);
    await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', path.dirname(dest)], {}, h);
    await sudo(['install', '-m', '0755', '-o', 'root', '-g', 'root', path.join(tmp, member), dest], {}, h);
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}
