/**
 * The proxy's per-run CA: its TLS identity for intercepted connections. Generated as the proxy
 * user straight into its tmpfs confdir; the private key is never written anywhere else, and
 * never through writeFiles (it is not an inert file).
 */

import * as path from 'path';
import { CA_CERT_FILE, PROXY_CA_KEY_FILE, PROXY_CONF_DIR, PROXY_USER, TEARDOWN_BIN } from '../../constants';
import { writeFiles } from '../../system/files';
import { sudo, type Host } from '../../system/host';
import type { FileSpec } from '../../system/types';

declare const caReady: unique symbol;
/** The CA exists: key + cert in the proxy's confdir, the public cert at CA_CERT_FILE. Minted only by generateCa(). */
export type CaReady = { readonly [caReady]: true };

/**
 * Generate the per-run CA: RSA-2048 (broadest client compatibility), 3-day validity, key
 * only ever on tmpfs, 0600, owned by the proxy user. mitmproxy mints leaf certs from it.
 * Publishes the public certificate to CA_CERT_FILE.
 */
export async function generateCa(h: Host): Promise<CaReady> {
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', path.dirname(PROXY_CONF_DIR)], {}, h);
  await sudo(['install', '-d', '-m', '0700', '-o', PROXY_USER, '-g', PROXY_USER, PROXY_CONF_DIR], {}, h);
  const key = `${PROXY_CONF_DIR}/ca-key.pem`;
  const cert = `${PROXY_CONF_DIR}/ca-cert.pem`;
  const subject = `/O=safer-runner/CN=safer-runner ephemeral CA ${process.env.GITHUB_RUN_ID || ''}`.trim();
  await sudo(
    [
      '-u',
      PROXY_USER,
      'sh',
      '-c',
      'umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3 ' +
        `-keyout "$1" -out "$2" -subj "$3" ` +
        '-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign ' +
        `&& cat "$1" "$2" > "$4" && rm -f "$1"`,
      'sh',
      key,
      cert,
      subject,
      PROXY_CA_KEY_FILE
    ],
    {},
    h
  );
  // mitmproxy looks for <confdir>/mitmproxy-ca.pem (key + cert)
  await sudo(['install', '-m', '0644', '-o', 'root', '-g', 'root', cert, CA_CERT_FILE], {}, h);
  return Object.freeze({}) as CaReady;
}

/**
 * Root-owned teardown helper. The only privileged command the post step needs, so with
 * disable-sudo it is the single extra sudoers entry (exact path, no arguments).
 * Deleting the key on disk is all it does: the running proxy keeps the CA in memory so the
 * runner can still finish the job through it; the VM is destroyed afterwards. It removes
 * exactly the key files generateCa() and mitmproxy create.
 */
export function teardownHelper(): FileSpec {
  const script = `#!/bin/sh
# safer-runner: destroy the ephemeral CA private key (written by the action, root-owned).
rm -f ${PROXY_CA_KEY_FILE} ${PROXY_CONF_DIR}/ca-key.pem ${PROXY_CONF_DIR}/mitmproxy-ca.p12
`;
  return { kind: 'file', path: TEARDOWN_BIN, content: script, mode: '0755', owner: 'root:root' };
}

export async function installTeardown(h: Host, _ca: CaReady): Promise<void> {
  await writeFiles(h, [teardownHelper()]);
}
