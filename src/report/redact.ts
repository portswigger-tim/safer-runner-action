/**
 * Redaction of blocked hostnames before they are printed (job summary, job log).
 *
 * A blocked name can be the payload: `<encoded secret>.attacker.example`. Blocking the lookup
 * or connection is pointless if the report then publishes the name. GitHub already masks the
 * literal value of a registered secret in logs and summaries, so what gets through is an
 * ENCODED form - hex, base32, base64 - which in a DNS label looks like a run of `[a-z0-9_-]`
 * with almost no vowels and a sprinkle of digits. Words don't. This complements GitHub's
 * masking; it doesn't replace it.
 *
 * Every label of a blocked name is checked, the registrable domain and the TLD included. Per
 * label:
 *  - LONG_LABEL_LEN+ chars: redacted (DNS-tunnel chunks run to the 63-char limit);
 *  - SHORT_HEX_LEN+ chars (ignoring `-`/`_`) of digits, or of hex with a digit: redacted;
 *  - under ENCODED_MIN_LEN: shown;
 *  - otherwise redacted when it is all hex, or its letters have fewer than MAX_VOWEL_RATIO
 *    vowels, or it has MIN_DIGIT_RUNS+ separate runs of digits, or (tie-breaker,
 *    ENTROPY_MIN_LEN+) Shannon entropy of ENTROPY_BITS+ bits per char.
 * A redacted label, or a run of them, prints as REDACTED: no length, so the shape of the
 * hidden part carries nothing either.
 *
 * Measured on random data: hex of 8+ chars (6+ with a digit) and anything 40+ chars, 100%;
 * base32/base64 of 8-12 chars ~55-65%, 16 chars ~75%, 24 chars ~93%. A stricter rule starts
 * hiding real hostnames (`runnerghubwus31`, `microsoftonline`). This is a best-effort filter
 * that keeps obviously encoded values out of the report, not a guarantee: data shaped to avoid
 * it (short or word-like labels) can get through whole and recoverable, even in a single name.
 * It doesn't apply to the raw logs on the runner (`proxy-flows.jsonl` and the DNS/firewall
 * logs are unredacted).
 *
 * The suggested http-filter is built in proxy/suggest.py, which holds the redaction it needs:
 * the same label check (looks_encoded) for names, and the stricter check for path segments
 * (path_segment_shown). Both copies of the label check run against proxy/test-vectors.json
 * "redact".
 */

export const HEX_MIN_LEN = 8;
/** digits, or hex with at least one digit, from this length (`a1b2c3`, `482913`) */
export const SHORT_HEX_LEN = 6;
/** labels shorter than this (after dropping `-`/`_`) are shown unless SHORT_HEX_LEN catches them */
export const ENCODED_MIN_LEN = 8;
/** words have about 40% vowels among their letters; random base32/64 about 20% */
export const MAX_VOWEL_RATIO = 0.25;
/** separate runs of digits inside a label (`a1b22c3`): encodings scatter them, names don't */
export const MIN_DIGIT_RUNS = 3;
export const LONG_LABEL_LEN = 40;
export const ENTROPY_MIN_LEN = 20;
export const ENTROPY_BITS = 4.0;
export const REDACTED = '‹redacted›';

export function shannonBits(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

/** Does this label look like encoded data rather than a name a person chose? */
export function looksEncoded(label: string): boolean {
  const l = label.toLowerCase();
  if (l.length >= LONG_LABEL_LEN) return true;
  const core = l.replace(/[-_]/g, '');
  if (core.length >= SHORT_HEX_LEN && /^[0-9a-f]+$/.test(core) && /[0-9]/.test(core)) return true;
  if (core.length < ENCODED_MIN_LEN) return false;
  if (core.length >= HEX_MIN_LEN && /^[0-9a-f]+$/.test(core)) return true;
  const letters = core.replace(/[^a-z]/g, '');
  const vowels = letters.replace(/[^aeiouy]/g, '').length;
  if (letters.length === 0 || vowels / letters.length < MAX_VOWEL_RATIO) return true;
  if ((core.match(/[0-9]+/g) ?? []).length >= MIN_DIGIT_RUNS) return true;
  return core.length >= ENTROPY_MIN_LEN && shannonBits(core) >= ENTROPY_BITS;
}

/** `name` with every payload-looking label replaced by REDACTED (a run of them by one). */
export function redactName(name: string): string {
  const out: string[] = [];
  for (const l of name.toLowerCase().split('.')) {
    if (!looksEncoded(l)) out.push(l);
    else if (out[out.length - 1] !== REDACTED) out.push(REDACTED);
  }
  return out.join('.');
}

/** True when redactName would hide part of the name (never paste such a name into YAML). */
export function needsRedaction(name: string): boolean {
  return redactName(name) !== name.toLowerCase();
}

/** Request methods a report shows by name; any other token is the caller's choice, so it can be the data. */
export const STANDARD_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'];
/** how any other method is shown: a fixed word, never the token itself */
export const CUSTOM_METHOD = 'INVALID';

/** `method` (upper-cased) when it is a standard one, else CUSTOM_METHOD. */
export function methodLabel(method: unknown): string {
  const m = String(method ?? '').toUpperCase();
  return STANDARD_METHODS.includes(m) ? m : CUSTOM_METHOD;
}

/**
 * How the path of a refused request is shown: always this, never the path. Whoever sent the
 * request chose the path, and no per-segment check stops data split into short chunks.
 */
export const PATH_HIDDEN = '‹path hidden›';

// ---------------------------------------------------------------- sudo command lines

/**
 * Sudo command lines the job ran (the summary and the job log). An argument can be a credential
 * (`--token=...`, `mysql -p ...`), and GitHub masks only the literal value of a registered secret.
 * Each argument that could carry one prints as REDACTED, so the path and the number of arguments
 * stay readable. The same check decides which lines proxy/sudo_suggest.py leaves out of the
 * suggested sudo-config (secret_mask, path_secret); both run against proxy/test-vectors.json
 * "sudo_secret". Best effort, like the name check: a short credential with no telltale flag in
 * front of it can still get through.
 */

/** credentials with a known shape */
const TOKEN_PREFIX = /^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|npm_|AKIA|ASIA|sk-)/;
const LONG_RUN = /[A-Za-z0-9]{32,}/;
const PART = /[/.@+_=:-]/;
const SECRET_PART_LEN = 16;
/** a flag whose value is a credential: the next argument (or the value after `=`) */
const SECRET_FLAGS = new Set([
  '--password',
  '--passwd',
  '--pass',
  '--token',
  '--secret',
  '--api-key',
  '--apikey',
  '--auth'
]);
/** `NAME=value` with a name like these: the value is a credential */
const SECRET_NAME = /pass|pwd|secret|token|key|auth|cred|cookie|session/i;
/** words an HTTP credential follows (`-H Authorization: Bearer x`, joined by spaces in the sudo log) */
const AUTH_WORDS = new Set(['authorization', 'bearer', 'basic', 'token', 'cookie', 'x-api-key']);
/** `scheme://user:password@` */
const USERINFO = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/@\s]*:[^/@\s]*@/;
/** the name in `name=value`, shown when it is a plain option or variable name */
const PLAIN_NAME = /^-{0,2}[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

/** Could this argument be a credential? (sudo_suggest.looks_secret) */
export function looksSecret(arg: string): boolean {
  if (TOKEN_PREFIX.test(arg) || LONG_RUN.test(arg)) return true;
  return arg.split(PART).some(p => p.length >= SECRET_PART_LEN && looksEncoded(p));
}

/** `-phunter2` (mysql), not `-p22` (a port) or `-p/x` (a path). */
function shortPValue(arg: string): boolean {
  return (
    arg.length > 2 && ['-p', '-P'].includes(arg.slice(0, 2)) && !'-/.'.includes(arg[2]) && !/^\d+$/.test(arg.slice(2))
  );
}

/** For each argument: could it carry a credential? (sudo_suggest.secret_mask) */
export function secretMask(args: readonly string[]): boolean[] {
  return args.map((a, i) => {
    const prev = i ? args[i - 1] : '';
    const eq = a.indexOf('=');
    const name = eq < 0 ? '' : a.slice(0, eq);
    return (
      looksSecret(a) ||
      SECRET_FLAGS.has(prev.toLowerCase()) ||
      // `mysql -p hunter2`; not `mkdir -p /x` (a path) or `ssh -p 22` (a port)
      (['-p', '-P'].includes(prev) && !/^[/.-]/.test(a) && !/^\d+$/.test(a)) ||
      shortPValue(a) ||
      // `curl -u user:password`
      (['-u', '--user'].includes(prev) && a.includes(':')) ||
      AUTH_WORDS.has(prev.toLowerCase().replace(/:+$/, '')) ||
      (eq >= 0 && (SECRET_FLAGS.has(name.toLowerCase()) || SECRET_NAME.test(name) || looksSecret(a.slice(eq + 1)))) ||
      USERINFO.test(a)
    );
  });
}

/** The arguments as printed: a masked one as REDACTED, or `name=` + REDACTED when its name is plain. */
export function sudoArgsShown(args: readonly string[]): string[] {
  const mask = secretMask(args);
  return args.map((a, i) => {
    if (!mask[i]) return a;
    const name = a.slice(0, a.indexOf('='));
    return a.includes('=') && PLAIN_NAME.test(name) && !looksSecret(name) ? `${name}=${REDACTED}` : REDACTED;
  });
}

/** A command path as printed: a segment that looks like encoded data as REDACTED (sudo_suggest.path_secret). */
export function sudoPathShown(path: string): string {
  return path
    .split('/')
    .map(seg => (seg && (looksSecret(seg) || seg.split('.').some(looksEncoded)) ? REDACTED : seg))
    .join('/');
}

/** `[-u user] <path> <args>` as printed, from a sudo log entry (arguments are space-joined there). */
export function sudoCommandShown(c: { command: string; args: string; targetUser?: string }): string {
  const user = c.targetUser && c.targetUser !== 'root' ? `-u ${c.targetUser} ` : '';
  const args = sudoArgsShown(c.args.split(/\s+/).filter(Boolean));
  return user + [sudoPathShown(c.command), ...args].join(' ');
}
