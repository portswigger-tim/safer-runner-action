/**
 * Shapes shared by the services: what a service's pure render() returns, and the readiness
 * tokens its effects hand on. A step that needs another step done first takes that step's token,
 * so calling them out of order is a compile error (setup/run.ts).
 */

/** A path setup creates as root. `owner` is `user:group`. */
export type FileSpec =
  /** `install -d`: created with its mode and owner */
  | { kind: 'dir'; path: string; mode: string; owner: string }
  /** written, then chown + chmod */
  | { kind: 'file'; path: string; content: string; mode: string; owner: string }
  /** created empty if missing (never truncated: a log on a re-run keeps its lines), then chown + chmod */
  | { kind: 'touch'; path: string; mode: string; owner: string };

/**
 * A transient systemd unit (systemd-run), run as `user`, restarted on any exit. `props` are the
 * unit's own properties, in order (system/unit.ts adds the restart policy).
 */
export interface UnitSpec {
  unit: string;
  description: string;
  user: string;
  props: string[];
  /** `--setenv` entries, in order */
  env?: Record<string, string>;
  argv: string[];
}

/**
 * What a service renders from its facts. `inert` files change nothing on their own: they take
 * effect only when a later step (starting the unit) uses them, so writing them early is safe.
 * Writes that change the system's behaviour (resolv.conf, sudoers, ...) are never inert: they
 * live in a named step of the service.
 */
export interface Rendered {
  inert: FileSpec[];
  unit: UnitSpec;
}

declare const done: unique symbol;
/** Proof that a step has run; only that step can create one. */
export type Ready<Step extends string> = { readonly [done]: Step };

/** CoreDNS is up and answering (services/coredns start). */
export type DnsReady = Ready<'dns'>;
/** The system resolver points at CoreDNS (services/coredns cutover). */
export type ResolverOn = Ready<'resolver'>;

/** Mint a token. Only the step that the token stands for calls this. */
export function ready<T extends Ready<string>>(): T {
  return Object.freeze({}) as T;
}
