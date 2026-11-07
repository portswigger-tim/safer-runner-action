/**
 * Writes the paths a service renders (FileSpec), as root, in the order given.
 */

import { realHost, sudo, type Host } from './host';
import type { FileSpec } from './types';

export async function writeFiles(h: Host, files: FileSpec[]): Promise<void> {
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
export async function sudoWrite(file: string, content: string, mode: string, owner = 'root:root'): Promise<void> {
  await writeFiles(realHost, [{ kind: 'file', path: file, content, mode, owner }]);
}
