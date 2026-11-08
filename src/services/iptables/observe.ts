/** Post step: the firewall's LOG lines, for its part of the summary (and the containers'). */

import * as fs from 'fs';
import { FIREWALL_LOG } from '../../constants';
import { parseFirewallLog, type FirewallEvent } from './log';

export function observeFirewall(): FirewallEvent[] {
  return fs.existsSync(FIREWALL_LOG) ? parseFirewallLog(fs.readFileSync(FIREWALL_LOG, 'utf8')) : [];
}
