/**
 * The job summary. Each service owns its part: it parses its own log (services/<svc>/log.ts) and
 * renders its own section (services/<svc>/report.ts, pure), returning a Section (section.ts);
 * compose.ts puts the parts together. Every name or path a step chose goes through redact.ts
 * before it is printed (the C5 disclosure boundary). suggest.ts runs proxy/suggest.py and
 * proxy/sudo_suggest.py for the suggested http-filter and sudo-config.
 */

export * from '../services/coredns/log';
export * from '../services/iptables/log';
export * from '../services/sudo/log';
export * from '../services/docker/log';
export * from '../services/mitmproxy/flows';
export * from '../services/mitmproxy/http-filter';
export { addressClass, statusSummary, type ProxyObserved, type ProxySection } from '../services/mitmproxy/report';
export * from '../services/docker/containers';
export {
  DOCKER_BEST_EFFORT,
  DOCKER_KEEP_CAVEAT,
  DOCKER_PARTIAL,
  dockerUseCount,
  dockerUseText,
  imageLabel,
  type DockerPolicyReport,
  type DockerReportObserved
} from '../services/docker/report';
export {
  SUDO_BEST_EFFORT,
  SUDO_CONFIG_CAVEAT,
  sudoConfigYaml,
  type SudoConfigSuggestion,
  type SudoObserved,
  type SudoPolicyReport
} from '../services/sudo/report';
export * from './checks';
export * from './compose';
export * from './markdown';
export * from './redact';
export * from './section';
export * from './suggest';
