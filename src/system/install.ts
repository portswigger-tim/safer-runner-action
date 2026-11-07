/**
 * Pinned, sha256-verified downloads of the release tarballs the services run (mitmproxy, CoreDNS).
 */

import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { realHost, sudo, timed, type Host } from './host';

/**
 * Download a pinned release artefact and verify its sha256 before anything touches it
 * (3 attempts on network errors; a digest mismatch fails immediately).
 */
export async function downloadVerified(url: string, sha256: string, dest: string, label: string): Promise<void> {
  await timed(`download ${label}`, async () => {
    let lastError: unknown;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const buf = Buffer.from(await res.arrayBuffer());
        const digest = crypto.createHash('sha256').update(buf).digest('hex');
        if (digest !== sha256) {
          throw new Error(`sha256 mismatch for ${url}: got ${digest}, want ${sha256}`);
        }
        fs.writeFileSync(dest, buf);
        return;
      } catch (e) {
        lastError = e;
        if (String(e).includes('sha256 mismatch')) break;
        core.warning(`${label} download attempt ${attempt} failed: ${e}`);
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
