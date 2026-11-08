/** Small Markdown helpers for the job summary. Untrusted text goes through code() / codeBlock(). */

const MAX_ROWS = 300;

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Untrusted text (hostnames come from the job's own Host headers) as a code span in a table. */
export function code(s: string): string {
  return (
    '`' +
    s
      .slice(0, 253)
      .replace(/`/g, "'")
      .replace(/\|/g, '\\|')
      .replace(/[\r\n]/g, ' ') +
    '`'
  );
}

export function table(header: string[], align: string[], rows: string[][]): string {
  return [`| ${header.join(' | ')} |`, `|${align.join('|')}|`, ...rows.map(r => `| ${r.join(' | ')} |`)].join('\n');
}

/** The first MAX_ROWS rows, and a note saying how many more are only in the job log. */
export function capped<T>(rows: T[]): { shown: T[]; note: string } {
  if (rows.length <= MAX_ROWS) return { shown: rows, note: '' };
  return {
    shown: rows.slice(0, MAX_ROWS),
    note: `\n\n**+${rows.length - MAX_ROWS} more not shown here** - the full list is in the post step's job log.`
  };
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Longest backtick run + 1, so untrusted text can't close the fence early. */
function fenceFor(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map(m => m.length));
  return '`'.repeat(Math.max(3, longest + 1));
}

export function codeBlock(lang: string, text: string): string {
  const f = fenceFor(text);
  return `${f}${lang}\n${text}\n${f}`;
}
