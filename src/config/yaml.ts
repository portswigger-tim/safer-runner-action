/**
 * Strict reading of the structured YAML inputs (http-filter, sudo-config).
 */

import { LineCounter, isAlias, parseDocument, visit } from 'yaml';
import type { Document, Node } from 'yaml';

/** Plain words for the YAML errors a user is most likely to hit; any other uses the library's text. */
const YAML_HINTS: Record<string, string> = {
  TAB_AS_INDENT: 'indent with spaces, not tabs',
  BAD_INDENT: 'inconsistent indentation',
  BLOCK_AS_IMPLICIT_KEY: 'inconsistent indentation (a line is indented more than the line above it)',
  MULTILINE_IMPLICIT_KEY: 'inconsistent indentation (a key must be on one line)',
  BAD_ALIAS: 'put a value that starts with * in quotes'
};

export interface StrictYamlOptions {
  /** explains a parse error the hints don't cover */
  fallback: string;
  /** input-specific hints, by YAML error code */
  hints?: Record<string, string>;
  uniqueKeys?: boolean;
}

/**
 * A YAML input, read strictly: core schema, YAML 1.2, no anchors, aliases, tags, document
 * markers or directives (never resolved or ignored). Errors name the input and the line.
 */
export function strictYaml(
  raw: string,
  name: string,
  o: StrictYamlOptions
): { doc: Document.Parsed; at: (n: Node | null | undefined) => string } {
  const lines = new LineCounter();
  const doc = parseDocument(raw, {
    lineCounter: lines,
    prettyErrors: false,
    schema: 'core',
    strict: true,
    uniqueKeys: o.uniqueKeys ?? true,
    version: '1.2'
  });
  const line = (offset: number) => `${name} line ${lines.linePos(offset).line}`;
  const at = (n: Node | null | undefined) => line(n?.range?.[0] ?? 0);
  const hints = { ...YAML_HINTS, ...o.hints };
  const problems = [...doc.errors, ...doc.warnings];
  if (problems.length) {
    const p = problems.find(e => e.code === 'BAD_ALIAS') ?? problems[0];
    const text = hints[p.code] ?? `${p.message.split('\n')[0]} (${o.fallback})`;
    throw new Error(`${line(p.pos[0])}: ${text}`);
  }
  if (doc.directives?.docStart || doc.directives?.docEnd) {
    throw new Error(`${name}: remove the YAML document markers (--- and ...) and any % directives`);
  }
  visit(doc, {
    Node(_, n) {
      if (isAlias(n) || n.anchor || n.tag) {
        throw new Error(`${at(n)}: YAML anchors (&), aliases (*name) and tags (!) are not allowed`);
      }
    }
  });
  return { doc, at };
}
