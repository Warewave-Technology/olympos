import { describe, expect, it } from 'vitest';
import type { KyvernoViolation } from '../api/types';
import { buildExamples, celToText, explainPolicy, patternChecks, policyMode } from '../lib/kyverno';
import { toYaml, yamlLineTokens } from '../lib/yaml';

const v = (p: Partial<KyvernoViolation>): KyvernoViolation => ({ rule: 'check-team', result: 'fail', severity: 'medium', message: "validation error: label 'team' is required. rule check-team failed at path /metadata/labels/team/", resource_kind: 'Pod', resource_namespace: 'lab', resource_name: 'web-7f9c', ...p });

describe('Kyverno explanations', () => {
  it('reads legacy patterns with anchors', () => {
    expect(patternChecks({ metadata: { labels: { team: '?*' } } }).map((c) => c.text)).toEqual(['metadata.labels.team must be set (any non-empty value)']);
    const t = patternChecks({ spec: { containers: [{ '=(securityContext)': { '=(runAsUser)': '>0' } }], '=(volumes)': [{ 'X(hostPath)': 'null' }] } }).map((c) => c.text);
    expect(t).toEqual(['if spec.containers[*].securityContext is set, if spec.containers[*].securityContext.runAsUser is set, spec.containers[*].securityContext.runAsUser must be > 0', 'if spec.volumes is set, spec.volumes[*].hostPath must not be set']);
    expect(patternChecks({ image: '!*:latest' })[0].text).toBe('image must not be *:latest');
    expect(patternChecks({ image: 'acr.io/* | ghcr.io/*' })[0].text).toBe('image must be one of acr.io/*, ghcr.io/*');
  });

  it('explains legacy rules: match, exclude, message and mode', () => {
    const spec = { validationFailureAction: 'Enforce', rules: [{ name: 'check-team', match: { any: [{ resources: { kinds: ['Pod'], namespaces: ['lab'] } }] }, exclude: { any: [{ resources: { namespaces: ['kube-system'] } }] }, validate: { message: "label 'team' is required", pattern: { metadata: { labels: { team: '?*' } } } } }] };
    const [r] = explainPolicy({ kind: 'ClusterPolicy', name: 'require-labels', spec });
    expect(r.applies).toEqual(['Pod in namespace lab']);
    expect(r.excludes).toEqual(['any resource in namespace kube-system']);
    expect(r.message).toBe("label 'team' is required");
    expect(policyMode({ kind: 'ClusterPolicy', spec, mode: 'Audit' }).mode).toBe('Enforce');
  });

  it('translates common CEL shapes and keeps others as code', () => {
    expect(celToText("has(object.metadata.labels) && 'team' in object.metadata.labels")).toEqual({ text: 'metadata.labels must be set and label team must be set', fix: { path: 'metadata.labels.team', value: 'example' } });
    expect(celToText("object.spec.containers.all(c, !c.image.endsWith(':latest'))")?.text).toBe('every item of spec.containers: image must not end with :latest');
    expect(celToText('!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))')).toBeNull();
    const [r] = explainPolicy({ kind: 'ValidatingPolicy', name: 'p', spec: { validationActions: ['Audit'], matchConstraints: { resourceRules: [{ apiGroups: [''], resources: ['pods'], operations: ['CREATE'] }] }, validations: [{ expression: 'x || y', message: 'm' }] } });
    expect(r.applies).toEqual(['pods on CREATE']);
    expect(r.checks[0]).toMatchObject({ text: 'Custom CEL check (see the expression)', code: 'x || y', message: 'm' });
    expect(policyMode({ kind: 'ValidatingPolicy', spec: { validationActions: ['Deny', 'Audit'] }, mode: 'Audit' }).mode).toBe('Enforce');
  });

  it('builds a failing example from a violation and a passing one with the fix', () => {
    const spec = { rules: [{ name: 'check-team', match: { any: [{ resources: { kinds: ['Pod'] } }] }, validate: { message: "label 'team' is required", pattern: { metadata: { labels: { team: '?*' } } } } }] };
    const ex = buildExamples({ kind: 'ClusterPolicy', name: 'require-labels', spec, violations: [v({})] });
    expect(ex.map((e) => [e.verdict, e.namespace, e.name, e.fields, e.message])).toEqual([
      ['fail', 'lab', 'web-7f9c', [['metadata.labels.team', '(not set)']], "label 'team' is required."],
      ['pass', 'lab', 'web-7f9c', [['metadata.labels.team', 'example']], 'passes'],
    ]);
    // no violations: a synthetic pair
    expect(buildExamples({ kind: 'ClusterPolicy', name: 'require-labels', spec, violations: [] }).map((e) => e.verdict)).toEqual(['fail', 'pass']);
  });

  it('serializes and tokenizes YAML', () => {
    expect(toYaml({ a: { b: ['x', { c: '?*' }] }, d: true, e: '' })).toBe("a:\n  b:\n  - x\n  - c: '?*'\nd: true\ne: ''\n");
    expect(yamlLineTokens('  - name: run # c').map((t) => t.t)).toEqual(['plain', 'punct', 'key', 'punct', 'plain', 'str', 'comment']);
    expect(yamlLineTokens("x: '?*'").map((t) => t.t)).toEqual(['key', 'punct', 'plain', 'str']);
  });
});
