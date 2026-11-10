/** Post step: the names the resolver refused, for its part of the summary. */

import { DNS_LOG, SELFTEST_HOST } from '../../constants';
import { readRefusedNames } from './log';

/**
 * Refused names, less the ones the setup self-tests looked up (refused by design; not the job's
 * traffic): the DNS self-test's name, and the SNI self-test's host, which analyze resolves.
 */
export function observeDns(dnsSelfTestName: string | undefined): string[] {
  return readRefusedNames(DNS_LOG).filter(n => n !== dnsSelfTestName && n !== SELFTEST_HOST);
}
