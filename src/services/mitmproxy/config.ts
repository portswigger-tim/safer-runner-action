/**
 * The proxy's pure config: policy.json, the flow log, and the mitmdump unit. No I/O.
 */

import {
  ADDON_DIR,
  ETC_DIR,
  FLOW_LOG,
  MITMDUMP_BIN,
  POLICY_FILE,
  PROXY_CONF_DIR,
  PROXY_LISTEN_HOST,
  PROXY_STREAM_LARGE_BODIES,
  PROXY_UNIT,
  PROXY_USER
} from '../../constants';
import type { PolicyConfig } from '../../policy';
import type { Rendered } from '../../system/types';
import { HARDENING } from '../../system/unit';

export interface ProxyPorts {
  /** host listener (nat OUTPUT REDIRECT) */
  port: number;
  /** container listener (nat PREROUTING DNAT from the docker bridges); the addon classifies by it */
  containerPort: number;
}

export interface ProxyFacts {
  policy: PolicyConfig;
  ports: ProxyPorts;
}

export function mitmdumpArgs(o: ProxyPorts): string[] {
  return [
    MITMDUMP_BIN,
    // two transparent listeners: a connection's listener tells host from container traffic
    '--mode',
    `transparent@${PROXY_LISTEN_HOST}:${o.port}`,
    '--mode',
    `transparent@${PROXY_LISTEN_HOST}:${o.containerPort}`,
    '--set',
    `confdir=${PROXY_CONF_DIR}`,
    '--set',
    'connection_strategy=lazy',
    '--set',
    `stream_large_bodies=${PROXY_STREAM_LARGE_BODIES}`,
    '--set',
    'block_global=false',
    '--set',
    'flow_detail=0',
    '--set',
    'termlog_verbosity=warn',
    '-s',
    `${ADDON_DIR}/policy.py`
  ];
}

/**
 * policy.json (read by the addon at every (re)start) and the flow log, which the proxy user
 * writes and the post step reads without sudo. The unit runs mitmdump as the proxy user with
 * UMask 0077, writable only where it must write: its confdir (the CA) and the flow log.
 */
export function render(f: ProxyFacts): Rendered {
  return {
    inert: [
      { kind: 'dir', path: ETC_DIR, mode: '0755', owner: 'root:root' },
      {
        kind: 'file',
        path: POLICY_FILE,
        content: JSON.stringify(f.policy, null, 2) + '\n',
        mode: '0644',
        owner: 'root:root'
      },
      { kind: 'touch', path: FLOW_LOG, mode: '0644', owner: `${PROXY_USER}:${PROXY_USER}` }
    ],
    unit: {
      unit: PROXY_UNIT,
      description: 'safer-runner egress proxy',
      user: PROXY_USER,
      props: ['UMask=0077', ...HARDENING, `ReadWritePaths=${PROXY_CONF_DIR} ${FLOW_LOG}`, 'LimitNOFILE=65536'],
      env: { HOME: PROXY_CONF_DIR, SAFER_RUNNER_POLICY: POLICY_FILE },
      argv: mitmdumpArgs(f.ports)
    }
  };
}
