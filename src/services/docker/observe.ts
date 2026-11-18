/** Post step: the containers' egress and (analyze) the job's use of docker, for docker's part of the summary. */

import * as core from '@actions/core';
import type { DockerPolicy } from '../../config/inputs.js';
import type { FlowRecord } from '../../flowlog.js';
import type { Mode } from '../../policy.js';
import { realHost } from '../../system/host.js';
import type { FirewallEvent } from '../iptables/log.js';
import { evaluateDocker } from './config.js';
import { summarizeContainers, type ContainerSummary } from './containers.js';
import { containerAddresses, observeDocker, type DockerEventsStart } from './index.js';
import type { DockerPolicyReport } from './report.js';

/** What the setup marker recorded about docker. */
export interface DockerMarker {
  mode: Mode;
  /** the docker policy and the verified access (G4) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running'; caRestart?: boolean };
  /** analyze: where the docker events recording started */
  dockerEvents?: DockerEventsStart;
  /** when setup wrote the marker */
  at?: string;
}

/** Per-container egress: the container listener's flow records and the container firewall chain. */
export async function observeContainers(records: FlowRecord[], firewall: FirewallEvent[]): Promise<ContainerSummary[]> {
  return summarizeContainers(records, firewall, await containerAddresses());
}

/**
 * Analyze: the job's use of docker after setup, what the docker policy setup recorded would
 * break in enforce, and the docker setting to suggest. Report only.
 */
export async function observeDockerPolicy(marker: DockerMarker): Promise<DockerPolicyReport | undefined> {
  const policy = marker.docker?.requested as DockerPolicy | undefined;
  if (marker.mode !== 'analyze' || !policy) return undefined;
  try {
    const observed = await observeDocker(realHost, marker.dockerEvents, marker.at, marker.docker?.access);
    return { policy, observed, evaluation: evaluateDocker(policy, observed) };
  } catch (error) {
    // costs only the docker evaluation: the rest of the report still renders
    core.warning(`No docker evaluation: ${error}`);
    return undefined;
  }
}
