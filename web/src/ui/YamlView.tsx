import { useMemo } from 'react';
import { yamlTokens } from '../lib/yaml';
import { CopyButton } from './kit';

/** Read-only, syntax-highlighted YAML with line numbers and a copy button. */
export function YamlView({ yaml, label, maxHeight = 420 }: { yaml: string; label: string; maxHeight?: number }) {
  const lines = useMemo(() => yamlTokens(yaml || ''), [yaml]);
  return (
    <div className="yaml">
      <div className="yaml-bar">
        <span className="muted small">{label}</span>
        <CopyButton text={yaml} label="Copy YAML" className="btn sm" />
      </div>
      <pre className="yaml-code" style={{ maxHeight }} aria-label={label} tabIndex={0}>
        <code>
          {lines.map((toks, n) => (
            <span className="yl" key={n}>
              <span className="yl-n" aria-hidden="true">
                {n + 1}
              </span>
              <span className="yl-t">
                {toks.map((t, i) =>
                  t.t === 'plain' ? (
                    t.v
                  ) : (
                    <span key={i} className={`y-${t.t}`}>
                      {t.v}
                    </span>
                  ),
                )}
                {'\n'}
              </span>
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
