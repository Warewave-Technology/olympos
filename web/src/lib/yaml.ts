// Minimal YAML helpers for read-only views: a serializer (mock data, fallback when the server
// sends no YAML) and a line tokenizer for syntax highlighting. Not a YAML parser.

const PLAIN_UNSAFE = /^[\s\-?:,[\]{}#&*!|>'"%@`]|: | #|[\s:]$|^(true|false|yes|no|on|off|null|~|y|n)$/i;
const NUMBER = /^[-+]?(\d[\d_]*(\.\d*)?([eE][-+]?\d+)?|\.\d+|0x[0-9a-fA-F]+|0o[0-7]+|\.inf|\.nan)$/;

function scalar(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  const s = String(v);
  if (s === '' || PLAIN_UNSAFE.test(s) || NUMBER.test(s) || /[\n\t]/.test(s)) return s.includes("'") || /[\n\t]/.test(s) ? JSON.stringify(s) : `'${s}'`;
  return s;
}

function keyText(k: string): string {
  return /^[A-Za-z0-9_./-][A-Za-z0-9_./() -]*$/.test(k) && !k.endsWith(' ') ? k : scalar(k);
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function lines(v: unknown, indent: number): string[] {
  const pad = ' '.repeat(indent);
  if (Array.isArray(v)) {
    if (v.length === 0) return [`${pad}[]`];
    const out: string[] = [];
    for (const item of v) {
      if (isObj(item) && Object.keys(item).length) {
        const inner = lines(item, indent + 2);
        out.push(`${pad}- ${inner[0].slice(indent + 2)}`, ...inner.slice(1));
      } else if (Array.isArray(item) && item.length) {
        out.push(`${pad}-`, ...lines(item, indent + 2));
      } else out.push(`${pad}- ${isObj(item) ? '{}' : Array.isArray(item) ? '[]' : scalar(item)}`);
    }
    return out;
  }
  if (isObj(v)) {
    const entries = Object.entries(v).filter(([, x]) => x !== undefined);
    if (entries.length === 0) return [`${pad}{}`];
    const out: string[] = [];
    for (const [k, x] of entries) {
      if (isObj(x) && Object.keys(x).length) out.push(`${pad}${keyText(k)}:`, ...lines(x, indent + 2));
      else if (Array.isArray(x) && x.length) out.push(`${pad}${keyText(k)}:`, ...lines(x, indent));
      else if (typeof x === 'string' && x.includes('\n')) out.push(`${pad}${keyText(k)}: |`, ...x.replace(/\n$/, '').split('\n').map((l) => `${pad}  ${l}`));
      else out.push(`${pad}${keyText(k)}: ${isObj(x) ? '{}' : Array.isArray(x) ? '[]' : scalar(x)}`);
    }
    return out;
  }
  return [`${pad}${scalar(v)}`];
}

/** JSON-ish value → YAML text (2-space indent, block style, lists not indented under keys). */
export function toYaml(v: unknown): string {
  return lines(v, 0).join('\n') + '\n';
}

export type YamlTokenType = 'key' | 'str' | 'num' | 'bool' | 'punct' | 'comment' | 'plain';
export interface YamlToken {
  t: YamlTokenType;
  v: string;
}

function valueTokens(v: string): YamlToken[] {
  if (!v) return [];
  const hash = v.search(/(^|\s)#/);
  const val = hash >= 0 ? v.slice(0, hash) : v;
  const out: YamlToken[] = [];
  const lead = /^\s*/.exec(val)![0];
  if (lead) out.push({ t: 'plain', v: lead });
  const body = val.slice(lead.length);
  const trimmed = body.trimEnd();
  if (trimmed) {
    const t: YamlTokenType = /^['"]/.test(trimmed) ? 'str' : NUMBER.test(trimmed) ? 'num' : /^(true|false|null|~)$/i.test(trimmed) ? 'bool' : /^[|>][-+]?$/.test(trimmed) || /^(\{\}|\[\])$/.test(trimmed) ? 'punct' : 'str';
    out.push({ t, v: trimmed });
    if (body.length > trimmed.length) out.push({ t: 'plain', v: body.slice(trimmed.length) });
  }
  if (hash >= 0) out.push({ t: 'comment', v: v.slice(hash) });
  return out;
}

/** Tokens of one YAML line for highlighting. Block-scalar continuation lines come back as plain text. */
export function yamlLineTokens(line: string, inBlock = false): YamlToken[] {
  if (inBlock) return [{ t: 'plain', v: line }];
  const m = /^(\s*)(- +|-$)?(.*)$/.exec(line)!;
  const out: YamlToken[] = [];
  if (m[1]) out.push({ t: 'plain', v: m[1] });
  if (m[2]) out.push({ t: 'punct', v: m[2] });
  const rest = m[3];
  if (/^\s*#/.test(rest)) return [...out, { t: 'comment', v: rest }];
  const kv = /^((?:'[^']*'|"(?:[^"\\]|\\.)*"|[^'"#:][^:#]*?)):(?=\s|$)(.*)$/.exec(rest);
  if (kv) {
    out.push({ t: 'key', v: kv[1] }, { t: 'punct', v: ':' }, ...valueTokens(kv[2]));
    return out;
  }
  return [...out, ...valueTokens(rest)];
}

/** Tokenize a whole document, tracking `key: |` block scalars. */
export function yamlTokens(text: string): YamlToken[][] {
  const out: YamlToken[][] = [];
  let blockIndent = -1;
  for (const line of text.replace(/\n$/, '').split('\n')) {
    const indent = /^\s*/.exec(line)![0].length;
    const inBlock = blockIndent >= 0 && (line.trim() === '' || indent > blockIndent);
    if (!inBlock) blockIndent = -1;
    out.push(yamlLineTokens(line, inBlock));
    if (!inBlock && /:\s*[|>][-+]?\s*$/.test(line)) blockIndent = indent;
  }
  return out;
}
