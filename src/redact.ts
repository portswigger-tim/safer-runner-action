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
 * Every label of a blocked name is checked, the registrable domain and the TLD included. Only a
 * caller-given suffix (the allowlisted parent, from the job's own configuration) is shown as is.
 * Per label:
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

/**
 * `name` with every payload-looking label replaced by REDACTED (a run of them by one).
 * `keepSuffix`: a trusted suffix that is always shown (it must be a suffix of name).
 */
export function redactName(name: string, keepSuffix?: string): string {
  const n = name.toLowerCase();
  const labels = n.split('.');
  const keep = keepSuffix && (n === keepSuffix || n.endsWith('.' + keepSuffix)) ? keepSuffix.split('.').length : 0;
  const out: string[] = [];
  for (const l of labels.slice(0, labels.length - keep)) {
    if (!looksEncoded(l)) out.push(l);
    else if (out[out.length - 1] !== REDACTED) out.push(REDACTED);
  }
  return [...out, ...labels.slice(labels.length - keep)].join('.');
}

/** True when redactName would hide part of the name (never paste such a name into YAML). */
export function needsRedaction(name: string): boolean {
  return redactName(name) !== name.toLowerCase();
}
