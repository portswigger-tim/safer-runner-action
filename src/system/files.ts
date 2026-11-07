/**
 * Writes the paths a service renders (FileSpec), as root, in the order given.
 */

import { realHost, sudo, type Host } from './host';
import type { FileSpec, Owner } from './types';

/**
 * Content goes in before owner and mode are set, so a file written here is briefly readable as
 * root's default. Fine for world-readable files; a restricted one (the baseline, sudoers) must be
 * its own named step that sets owner and mode first (touch, chown, chmod, then tee).
 */
function assertWorldReadable(f: FileSpec): void {
  if (f.kind === 'file' && (parseInt(f.mode, 8) & 0o004) === 0) {
    throw new Error(`writeFiles: ${f.path} (${f.mode}) is restricted: write it in a named step, not as an inert file`);
  }
}

export async function writeFiles(h: Host, files: FileSpec[]): Promise<void> {
  files.forEach(assertWorldReadable);
  for (const f of files) {
    if (f.kind === 'dir') {
      const [user, group] = f.owner.split(':');
      await sudo(['install', '-d', '-m', f.mode, '-o', user, '-g', group, f.path], {}, h);
      continue;
    }
    if (f.kind === 'file') await sudo(['tee', f.path], { input: Buffer.from(f.content), silent: true }, h);
    else await sudo(['touch', f.path], {}, h);
    await sudo(['chown', f.owner, f.path], {}, h);
    await sudo(['chmod', f.mode, f.path], {}, h);
  }
}

/** One root-owned file on the runner: content first, then owner and mode. */
export async function sudoWrite(
  file: string,
  content: string,
  mode: string,
  owner: Owner = 'root:root'
): Promise<void> {
  await writeFiles(realHost, [{ kind: 'file', path: file, content, mode, owner }]);
}
