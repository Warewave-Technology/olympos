// Plain-language explanation of Kyverno policies (legacy kyverno.io ClusterPolicy/Policy rules and
// policies.kyverno.io CEL ValidatingPolicy kinds) plus pass/fail examples derived from the current
// violations. No CEL engine: simple expression shapes are translated, anything else is shown as code.

import type { KyvernoPolicyDetail, KyvernoViolation } from '../api/types';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strs = (v: unknown): string[] => arr(v).map(String);

export const CEL_KINDS = ['ValidatingPolicy', 'NamespacedValidatingPolicy', 'ImageValidatingPolicy', 'NamespacedImageValidatingPolicy'];
export const isCelKind = (kind: string | undefined) => !!kind && CEL_KINDS.includes(kind);

export interface Check {
  /** Plain-language sentence. */
  text: string;
  /** Field path the check is about (legacy pattern), when known. */
  path?: string;
  /** CEL expression or raw condition. */
  code?: string;
  message?: string;
  /** A value that satisfies the check (for the passing example); null = the field must be absent. */
  fix?: { path: string; value: string | null };
}
export interface RuleExplanation {
  name: string;
  type: 'validate' | 'mutate' | 'generate' | 'verifyImages' | 'cel' | 'other';
  applies: string[];
  excludes: string[];
  conditions: string[];
  checks: Check[];
  message: string;
}

// ------------------------------------------------------------ match / exclude (legacy)

function describeResources(r: Obj): string {
  const kinds = strs(r.kinds);
  const ns = strs(r.namespaces);
  const names = strs(r.names);
  const ops = strs(r.operations);
  const parts = [kinds.length ? kinds.join(', ') : 'any resource'];
  if (names.length) parts.push(`named ${names.join(', ')}`);
  parts.push(ns.length ? `in namespace${ns.length > 1 ? 's' : ''} ${ns.join(', ')}` : 'in all namespaces');
  if (isObj(r.selector)) parts.push(`with labels ${selectorText(r.selector)}`);
  if (isObj(r.namespaceSelector)) parts.push(`in namespaces with labels ${selectorText(r.namespaceSelector)}`);
  if (ops.length) parts.push(`on ${ops.join('/')}`);
  return parts.join(' ');
}

export function selectorText(sel: Obj): string {
  const out = Object.entries(isObj(sel.matchLabels) ? sel.matchLabels : {}).map(([k, v]) => `${k}=${String(v)}`);
  for (const e of arr(sel.matchExpressions)) {
    if (!isObj(e)) continue;
    const vals = strs(e.values).join(', ');
    out.push(e.operator === 'Exists' ? `${e.key} exists` : e.operator === 'DoesNotExist' ? `no ${e.key}` : `${e.key} ${e.operator === 'NotIn' ? 'not in' : 'in'} (${vals})`);
  }
  return out.join(', ') || 'any';
}

function matchBlock(m: unknown): string[] {
  if (!isObj(m)) return [];
  const out: string[] = [];
  if (isObj(m.resources)) out.push(describeResources(m.resources));
  for (const x of arr(m.any)) if (isObj(x) && isObj(x.resources)) out.push(describeResources(x.resources));
  const all = arr(m.all).filter(isObj);
  if (all.length) out.push(all.map((x) => (isObj(x.resources) ? describeResources(x.resources) : '')).filter(Boolean).join(' and '));
  return out;
}

// ------------------------------------------------------------ patterns (legacy validate.pattern)

function constraint(v: unknown): { text: string; fix: string | null } {
  if (typeof v === 'boolean' || typeof v === 'number') return { text: `must be ${v}`, fix: String(v) };
  if (v === null) return { text: 'must be empty', fix: null };
  const s = String(v);
  if (s === '?*') return { text: 'must be set (any non-empty value)', fix: 'example' };
  if (s === '*') return { text: 'must be present', fix: 'example' };
  if (s === '!*') return { text: 'must not be set', fix: null };
  if (s.includes('|')) {
    const opts = s.split('|').map((x) => x.trim());
    return { text: `must be one of ${opts.join(', ')}`, fix: opts[0] };
  }
  const cmp = /^(>=|<=|>|<)\s*(.+)$/.exec(s);
  if (cmp) {
    const n = Number(cmp[2]);
    const sym = { '>=': '≥', '<=': '≤', '>': '>', '<': '<' }[cmp[1]]!;
    return { text: `must be ${sym} ${cmp[2]}`, fix: Number.isFinite(n) ? String(cmp[1] === '>' ? n + 1 : cmp[1] === '<' ? n - 1 : n) : cmp[2] };
  }
  if (s.startsWith('!')) return { text: `must not be ${s.slice(1)}`, fix: s.slice(1) === 'true' ? 'false' : s.slice(1) === 'false' ? 'true' : 'other' };
  if (/[*?]/.test(s)) return { text: `must match ${s}`, fix: s.replace(/\*/g, 'x').replace(/\?/g, 'a') };
  return { text: `must be ${s}`, fix: s };
}

function walkPattern(node: unknown, path: string, out: Check[], cond: string) {
  if (Array.isArray(node)) {
    for (const n of node) walkPattern(n, `${path}[*]`, out, cond);
    return;
  }
  if (isObj(node)) {
    for (const [rawK, v] of Object.entries(node)) {
      const a = /^([=X+^<])\((.+)\)$/.exec(rawK);
      const key = a ? a[2] : rawK;
      const p = path ? `${path}.${key}` : key;
      if (a?.[1] === 'X') {
        out.push({ text: `${cond}${p} must not be set`, path: p, fix: { path: p, value: null } });
        continue;
      }
      if (a?.[1] === '=') {
        walkPattern(v, p, out, `${cond}if ${p} is set, `);
        continue;
      }
      if (a?.[1] === '^') {
        walkPattern(v, p, out, `${cond}at least one ${p}: `);
        continue;
      }
      walkPattern(v, p, out, cond);
    }
    return;
  }
  const c = constraint(node);
  out.push({ text: `${cond}${path} ${c.text}`, path, fix: { path, value: c.fix } });
}

export function patternChecks(pattern: unknown): Check[] {
  const out: Check[] = [];
  walkPattern(pattern, '', out, '');
  return out;
}

function conditionText(c: Obj): string {
  const key = String(c.key ?? '').replace(/^\{\{\s*|\s*\}\}$/g, '');
  const val = Array.isArray(c.value) ? `[${c.value.map(String).join(', ')}]` : String(c.value ?? '');
  return `${key} ${String(c.operator ?? 'Equals')} ${val}`.trim();
}

function conditionsList(block: unknown): string[] {
  if (Array.isArray(block)) return block.filter(isObj).map(conditionText);
  if (!isObj(block)) return [];
  const any = arr(block.any).filter(isObj).map(conditionText);
  const all = arr(block.all).filter(isObj).map(conditionText);
  return [...(all.length ? [all.join(' AND ')] : []), ...(any.length ? [any.join(' OR ')] : [])];
}

// ------------------------------------------------------------ CEL

const unwrapObj = (p: string) => p.replace(/^object\./, '');

/** Plain-language reading of common CEL shapes; null when the expression is not recognized. */
export function celToText(expr: string, subject = ''): { text: string; fix?: { path: string; value: string | null } } | null {
  const e = expr.trim().replace(/\s+/g, ' ');
  let m: RegExpExecArray | null;
  if ((m = /^!\s*has\(([\w.]+)\)$/.exec(e))) return { text: `${subject}${unwrapObj(m[1])} must not be set`, fix: { path: unwrapObj(m[1]), value: null } };
  if ((m = /^has\(([\w.]+)\)$/.exec(e))) return { text: `${subject}${unwrapObj(m[1])} must be set`, fix: { path: unwrapObj(m[1]), value: 'example' } };
  if ((m = /^'([^']+)' in ([\w.]+)$/.exec(e))) {
    const base = unwrapObj(m[2]);
    return { text: `${subject}${base.endsWith('labels') ? `label ${m[1]}` : base.endsWith('annotations') ? `annotation ${m[1]}` : `${base}.${m[1]}`} must be set`, fix: { path: `${base}.${m[1]}`, value: 'example' } };
  }
  if ((m = /^([\w.]+)\.(all|exists)\((\w+), (.+)\)$/.exec(e))) {
    const coll = unwrapObj(m[1]);
    const inner = m[4].replace(new RegExp(`\\b${m[3]}\\.`, 'g'), `${coll}[*].`);
    const sub = celToText(inner);
    const word = m[2] === 'all' ? 'every item of' : 'at least one item of';
    return sub ? { text: `${word} ${coll}: ${sub.text.replace(`${coll}[*].`, '')}`, fix: sub.fix } : { text: `${word} ${coll} must satisfy ${m[4]}` };
  }
  if ((m = /^([\w.[\]*]+) (==|!=) ('[^']*'|"[^"]*"|true|false|\d+)$/.exec(e))) {
    const v = m[3].replace(/^['"]|['"]$/g, '');
    const p = unwrapObj(m[1]);
    return m[2] === '==' ? { text: `${subject}${p} must be ${v}`, fix: { path: p, value: v } } : { text: `${subject}${p} must not be ${v}`, fix: { path: p, value: v === 'true' ? 'false' : v === 'false' ? 'true' : 'other' } };
  }
  if ((m = /^(!?)([\w.[\]*]+)\.(startsWith|endsWith|contains|matches)\(('[^']*'|"[^"]*")\)$/.exec(e))) {
    const v = m[4].slice(1, -1);
    const verb = { startsWith: 'start with', endsWith: 'end with', contains: 'contain', matches: 'match' }[m[3]]!;
    const p = unwrapObj(m[2]);
    return { text: `${subject}${p} must ${m[1] ? 'not ' : ''}${verb} ${v}`, fix: m[1] ? undefined : { path: p, value: m[3] === 'startsWith' ? `${v}example` : m[3] === 'endsWith' ? `example${v}` : v } };
  }
  if ((m = /^size\(([\w.]+)\) (>|>=) (\d+)$/.exec(e))) return { text: `${subject}${unwrapObj(m[1])} must have ${m[2] === '>' ? 'more than' : 'at least'} ${m[3]} item(s)` };
  const parts = e.split(' && ');
  if (parts.length > 1) {
    const subs = parts.map((x) => celToText(x));
    // the last part is usually the specific one (has(labels) && 'team' in labels → set labels.team)
    if (subs.every(Boolean)) return { text: subs.map((x) => x!.text).join(' and '), fix: [...subs].reverse().find((x) => x!.fix)?.fix };
  }
  return null;
}

function resourceRuleText(r: Obj): string {
  const res = strs(r.resources);
  const ops = strs(r.operations);
  const groups = strs(r.apiGroups).map((g) => (g === '' ? 'core' : g));
  return `${res.join(', ') || 'any resource'}${groups.length && !(groups.length === 1 && groups[0] === 'core') ? ` (${groups.join(', ')})` : ''}${ops.length ? ` on ${ops.join('/')}` : ''}`;
}

function explainCel(spec: Obj, policyName: string): RuleExplanation[] {
  const mc = isObj(spec.matchConstraints) ? spec.matchConstraints : {};
  const applies = arr(mc.resourceRules).filter(isObj).map(resourceRuleText);
  for (const r of arr(spec.matchImageReferences)) if (isObj(r)) applies.push(`images matching ${String(r.glob ?? r.expression ?? '')}`);
  if (isObj(mc.namespaceSelector)) applies.push(`in namespaces with labels ${selectorText(mc.namespaceSelector)}`);
  if (isObj(mc.objectSelector)) applies.push(`objects with labels ${selectorText(mc.objectSelector)}`);
  const excludes = arr(mc.excludeResourceRules).filter(isObj).map(resourceRuleText);
  const conditions = arr(spec.matchConditions)
    .filter(isObj)
    .map((c) => {
      const t = celToText(String(c.expression ?? ''));
      return `${String(c.name ?? 'condition')}: ${t ? t.text.replace(/must be set/, 'is set') : String(c.expression ?? '')}`;
    });
  for (const v of arr(spec.variables)) if (isObj(v)) conditions.push(`variable ${String(v.name)} = ${String(v.expression)}`);
  const checks: Check[] = arr(spec.validations)
    .filter(isObj)
    .map((v) => {
      const expr = String(v.expression ?? '');
      const t = celToText(expr);
      return { text: t?.text ?? 'Custom CEL check (see the expression)', code: expr, message: String(v.message ?? v.messageExpression ?? ''), fix: t?.fix };
    });
  for (const a of arr(spec.attestors)) if (isObj(a)) checks.push({ text: `images must be signed (attestor ${String(a.name ?? '')})` });
  return [{ name: policyName, type: 'cel', applies, excludes, conditions, checks, message: checks.find((c) => c.message)?.message ?? '' }];
}

// ------------------------------------------------------------ entry points

export function explainPolicy(p: Pick<KyvernoPolicyDetail, 'kind' | 'name' | 'spec'>): RuleExplanation[] {
  const spec = isObj(p.spec) ? p.spec : {};
  if (isCelKind(p.kind) || (!Array.isArray(spec.rules) && (spec.validations || spec.matchConstraints))) return explainCel(spec, p.name);
  return arr(spec.rules)
    .filter(isObj)
    .map((r) => {
      const v = isObj(r.validate) ? r.validate : null;
      const checks: Check[] = [];
      let type: RuleExplanation['type'] = v ? 'validate' : r.mutate ? 'mutate' : r.generate ? 'generate' : r.verifyImages ? 'verifyImages' : 'other';
      if (v) {
        if (v.pattern !== undefined) checks.push(...patternChecks(v.pattern));
        const any = arr(v.anyPattern);
        if (any.length) checks.push(...any.map((ap, i) => ({ text: `option ${i + 1} of ${any.length}: ${patternChecks(ap).map((c) => c.text).join('; ')}`, fix: patternChecks(ap)[0]?.fix })));
        if (isObj(v.deny)) for (const c of conditionsList(v.deny.conditions)) checks.push({ text: `denied when ${c}`, code: c });
        if (isObj(v.podSecurity)) checks.push({ text: `pods must meet the Pod Security Standard "${String(v.podSecurity.level ?? 'baseline')}" (${String(v.podSecurity.version ?? 'latest')})` });
        if (isObj(v.cel))
          for (const x of arr(v.cel.expressions).filter(isObj)) {
            const t = celToText(String(x.expression ?? ''));
            checks.push({ text: t?.text ?? 'Custom CEL check (see the expression)', code: String(x.expression ?? ''), message: String(x.message ?? ''), fix: t?.fix });
          }
      } else if (r.verifyImages) {
        type = 'verifyImages';
        for (const vi of arr(r.verifyImages).filter(isObj)) checks.push({ text: `images ${strs(vi.imageReferences).join(', ') || '*'} must be signed` });
      } else if (r.mutate) checks.push({ text: 'changes matching resources when they are created or updated (mutation)' });
      else if (r.generate) checks.push({ text: 'creates or syncs a resource when a matching resource appears (generation)' });
      return {
        name: String(r.name ?? 'rule'),
        type,
        applies: matchBlock(r.match),
        excludes: matchBlock(r.exclude),
        conditions: conditionsList(r.preconditions),
        checks,
        message: v ? String(v.message ?? '') : '',
      };
    });
}

/** Kyverno mode: CEL validationActions containing Deny → Enforce; legacy validationFailureAction. */
export function policyMode(p: Pick<KyvernoPolicyDetail, 'kind' | 'spec' | 'mode'>): { mode: 'Enforce' | 'Audit'; detail: string } {
  const spec = isObj(p.spec) ? p.spec : {};
  if (Array.isArray(spec.validationActions)) {
    const acts = strs(spec.validationActions);
    return { mode: acts.includes('Deny') ? 'Enforce' : 'Audit', detail: `validationActions: ${acts.join(', ')}` };
  }
  if (typeof spec.validationFailureAction === 'string') return { mode: /enforce/i.test(spec.validationFailureAction) ? 'Enforce' : 'Audit', detail: `validationFailureAction: ${spec.validationFailureAction}` };
  return { mode: p.mode, detail: '' };
}

export interface Example {
  key: string;
  verdict: 'fail' | 'pass';
  kind: string;
  namespace: string;
  name: string;
  /** Relevant fields: path → shown value ("(not set)" when missing). */
  fields: [string, string][];
  rule: string;
  message: string;
  /** For the passing example: what changed. */
  change?: string;
}

export function renderMessage(msg: string, v: Pick<KyvernoViolation, 'resource_name' | 'resource_namespace' | 'resource_kind'>): string {
  return msg
    .replace(/\{\{\s*request\.object\.metadata\.name\s*\}\}/g, v.resource_name)
    .replace(/\{\{\s*request\.(object\.metadata\.)?namespace\s*\}\}/g, v.resource_namespace)
    .replace(/\{\{\s*request\.object\.kind\s*\}\}/g, v.resource_kind);
}

function ruleFor(rules: RuleExplanation[], v: KyvernoViolation): RuleExplanation | undefined {
  return rules.find((r) => r.name === v.rule) ?? rules.find((r) => r.checks.some((c) => c.message && v.message.includes(c.message))) ?? rules.find((r) => r.checks.some((c) => c.fix)) ?? rules[0];
}

function checkFor(rule: RuleExplanation | undefined, v: KyvernoViolation | null): Check | undefined {
  if (!rule) return undefined;
  return (v && rule.checks.find((c) => c.fix && c.message && v.message.includes(c.message))) ?? rule.checks.find((c) => c.fix) ?? rule.checks[0];
}

const shownBefore = (c: Check | undefined) => (c?.fix?.value === null ? 'set' : '(not set)');

/**
 * Up to `max` failing examples built from real violations, each followed by the same resource
 * changed so that it passes (derived from the rule's pattern or a recognized CEL check). With no
 * violations, one synthetic pair from the first rule.
 */
export function buildExamples(detail: Pick<KyvernoPolicyDetail, 'kind' | 'name' | 'spec' | 'violations'>, rules = explainPolicy(detail), max = 2): Example[] {
  const out: Example[] = [];
  const seen = new Set<string>();
  for (const v of detail.violations) {
    if (out.length >= max * 2) break;
    const rule = ruleFor(rules, v);
    const sig = `${v.rule}|${v.resource_kind}`;
    if (seen.has(sig) && detail.violations.length > max) continue;
    seen.add(sig);
    const c = checkFor(rule, v);
    // PolicyReport messages wrap the rule message: "validation error: <msg> rule <r> failed at path /…/"
    const msg = renderMessage(v.message || rule?.message || '', v)
      .replace(/^validation error:\s*/i, '')
      .replace(/\s*rule [\w.-]+ failed at path \S*$/i, '')
      .trim();
    const path = c?.fix?.path ?? c?.path;
    out.push({ key: `f-${out.length}`, verdict: 'fail', kind: v.resource_kind, namespace: v.resource_namespace, name: v.resource_name, fields: path ? [[path, shownBefore(c)]] : [], rule: v.rule || rule?.name || detail.name, message: msg });
    if (c?.fix) {
      const val = c.fix.value === null ? '(removed)' : c.fix.value;
      out.push({ key: `p-${out.length}`, verdict: 'pass', kind: v.resource_kind, namespace: v.resource_namespace, name: v.resource_name, fields: [[c.fix.path, val]], rule: v.rule || rule?.name || detail.name, message: 'passes', change: c.fix.value === null ? `remove ${c.fix.path}` : `set ${c.fix.path}: ${c.fix.value}` });
    }
  }
  if (out.length === 0) {
    const rule = rules.find((r) => r.checks.some((c) => c.fix)) ?? rules[0];
    const c = checkFor(rule, null);
    if (rule && c?.fix) {
      const kind = /^(\w+)/.exec(rule.applies[0] ?? '')?.[1] ?? 'Pod';
      const k = kind === 'any' ? 'Pod' : kind.replace(/s$/, '').replace(/^pod$/i, 'Pod');
      out.push({ key: 'f-0', verdict: 'fail', kind: k, namespace: 'default', name: 'example', fields: [[c.fix.path, shownBefore(c)]], rule: rule.name, message: c.message || rule.message || c.text });
      out.push({ key: 'p-1', verdict: 'pass', kind: k, namespace: 'default', name: 'example', fields: [[c.fix.path, c.fix.value === null ? '(removed)' : c.fix.value]], rule: rule.name, message: 'passes', change: c.fix.value === null ? `remove ${c.fix.path}` : `set ${c.fix.path}: ${c.fix.value}` });
    }
  }
  return out;
}
