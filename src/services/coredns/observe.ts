/** Post step: the names the resolver refused, for its part of the summary. */

import { DNS_LOG } from '../../constants';
import { readRefusedNames } from './log';

/** Refused names, less the one the DNS self-test looked up (refused by design; not the job's traffic). */
export function observeDns(dnsSelfTestName: string | undefined): string[] {
  return readRefusedNames(DNS_LOG).filter(n => n !== dnsSelfTestName);
}
