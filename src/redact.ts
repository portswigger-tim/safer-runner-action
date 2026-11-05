/**
 * Redaction of blocked hostnames before they are printed (job summary, job log).
 *
 * A blocked name can be the payload: `<encoded secret>.attacker.example`. Blocking the lookup
 * or connection is pointless if the report then publishes the name. GitHub already masks the
 * literal value of a registered secret in logs and summaries, so what gets through is an
 * ENCODED form - hex, base32, base64 - which in a DNS label looks like a long run of
 * `[a-z0-9_-]` with almost no vowels and a sprinkle of digits. Words don't. This complements
 * GitHub's masking; it doesn't replace it.
 *
 * Rules, per label, everything left of the zone:
 *  - the zone is always shown: the registrable domain (last two labels, three under a
 *    multi-part public suffix) or a longer caller-given suffix (e.g. the allowlisted parent).
 *    The user still sees which zone to act on; only payload-looking labels are hidden.
 *  - a label of LONG_LABEL_LEN+ chars is redacted (DNS-tunnel chunks run to the 63-char limit);
 *    one under ENCODED_MIN_LEN (ignoring `-`/`_`) is shown. In between it is redacted to
 *    `‹N chars›` when it is all hex, or its letters have fewer than MAX_VOWEL_RATIO vowels, or it
 *    has MIN_DIGIT_RUNS+ separate runs of digits, or (tie-breaker, ENTROPY_MIN_LEN+) Shannon
 *    entropy of ENTROPY_BITS+ bits per char. Charset and length are the primary signals.
 *
 * Measured on random data: hex of any length 12+ and anything 40+ chars, 100%; base32 of 20
 * bytes (32 chars) 99.6%; 12-byte base64 (16 chars) ~72%; 9-byte base64 (12 chars) ~43%. Short
 * labels carry little each, and a stricter rule starts hiding real hostnames
 * (`runnerghubwus31`, `microsoftonline`). A best-effort filter, not a guarantee.
 */

export const HEX_MIN_LEN = 12;
/** labels shorter than this (after dropping `-`/`_`) are always shown: too short to carry much */
export const ENCODED_MIN_LEN = 12;
/** words have about 40% vowels among their letters; random base32/64 about 20% */
export const MAX_VOWEL_RATIO = 0.25;
/** separate runs of digits inside a label (`a1b22c3`): encodings scatter them, names don't */
export const MIN_DIGIT_RUNS = 3;
export const LONG_LABEL_LEN = 40;
export const ENTROPY_MIN_LEN = 20;
export const ENTROPY_BITS = 4.0;

/** Second-level labels under which the registrable domain has three labels (co.uk, com.au...). */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.jp',
  'ne.jp',
  'co.za',
  'com.br',
  'com.cn',
  'co.in',
  'co.kr',
  'com.mx',
  'com.tr',
  'com.sg',
  'com.hk'
]);

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
  if (core.length < ENCODED_MIN_LEN) return false;
  if (/^[0-9a-f]+$/.test(core)) return true;
  const letters = core.replace(/[^a-z]/g, '');
  const vowels = letters.replace(/[^aeiouy]/g, '').length;
  if (letters.length === 0 || vowels / letters.length < MAX_VOWEL_RATIO) return true;
  if ((core.match(/[0-9]+/g) ?? []).length >= MIN_DIGIT_RUNS) return true;
  return core.length >= ENTROPY_MIN_LEN && shannonBits(core) >= ENTROPY_BITS;
}

function zoneLabels(labels: string[]): number {
  if (labels.length >= 3 && MULTI_PART_SUFFIXES.has(labels.slice(-2).join('.'))) return 3;
  return Math.min(2, labels.length);
}

/**
 * `name` with every payload-looking label left of the zone replaced by `‹N chars›`.
 * `keepSuffix`: a longer suffix that is always shown (it must be a suffix of name).
 */
export function redactName(name: string, keepSuffix?: string): string {
  const n = name.toLowerCase();
  const labels = n.split('.');
  let keep = zoneLabels(labels);
  if (keepSuffix && (n === keepSuffix || n.endsWith('.' + keepSuffix))) {
    keep = Math.max(keep, keepSuffix.split('.').length);
  }
  const head = labels.slice(0, labels.length - keep).map(l => (looksEncoded(l) ? `‹${l.length} chars›` : l));
  return [...head, ...labels.slice(labels.length - keep)].join('.');
}

/** True when redactName would hide part of the name (never paste such a name into YAML). */
export function needsRedaction(name: string): boolean {
  return redactName(name) !== name.toLowerCase();
}
