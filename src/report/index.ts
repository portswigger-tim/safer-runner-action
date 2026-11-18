/**
 * The job summary. Each service owns its part: it parses its own log (services/<svc>/log.ts) and
 * renders its own section (services/<svc>/report.ts, pure), returning a Section (section.ts);
 * compose.ts puts the parts together. Every name or path a step chose goes through redact.ts
 * before it is printed (the C5 disclosure boundary). suggest.ts runs proxy/suggest.py and
 * proxy/sudo_suggest.py for the suggested http-filter and sudo-config.
 */

export * from '../services/coredns/log.js';
export * from '../services/iptables/log.js';
export * from '../services/sudo/log.js';
export * from '../services/docker/log.js';
export * from '../services/mitmproxy/flows.js';
export * from '../services/mitmproxy/http-filter.js';
export {
  statusSummary,
  type ProxyObserved,
  type ProxySection,
  type ProxyTotals
} from '../services/mitmproxy/report.js';
export * from '../services/docker/containers.js';
export {
  DOCKER_PARTIAL,
  dockerUseCount,
  dockerUseText,
  imageLabel,
  type DockerPolicyReport,
  type DockerReportObserved
} from '../services/docker/report.js';
export {
  sudoConfigYaml,
  type SudoConfigSuggestion,
  type SudoObserved,
  type SudoPolicyReport
} from '../services/sudo/report.js';
export * from './checks.js';
export * from './compose.js';
export * from './markdown.js';
export * from './redact.js';
export * from './section.js';
export * from './suggest.js';
