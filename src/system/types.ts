/**
 * Shapes shared by the services: what a service's pure render() returns and its effects consume.
 *
 * Readiness tokens are declared by the service that owns the step, not here: a branded type over
 * a symbol that module does not export, minted only by that step (`Object.freeze({}) as Token`).
 * A step that needs another done first takes its token, so the wrong order does not compile.
 * src/system/tokens.test.ts lists every token with its owning file and its ordering invariant
 * in src/orchestration.test.ts, and fails if a token is minted anywhere else.
 */

/** `user:group` */
export type Owner = `${string}:${string}`;

/** A path setup creates as root. `owner` is `user:group`. */
export type FileSpec =
  /** `install -d`: created with its mode and owner */
  | { kind: 'dir'; path: string; mode: string; owner: Owner }
  /** written, then chown + chmod; world-readable only (a restricted file is a named step) */
  | { kind: 'file'; path: string; content: string; mode: string; owner: Owner }
  /** created empty if missing (never truncated: a log on a re-run keeps its lines), then chown + chmod */
  | { kind: 'touch'; path: string; mode: string; owner: Owner };

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
  /** restart on any exit (the default), or never: a unit whose restart would change the system */
  restart?: 'always' | 'no';
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
