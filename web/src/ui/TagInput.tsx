import { useRef, useState, type ClipboardEvent, type KeyboardEvent, type ReactNode } from 'react';
import { equalityTerms, formatLabels, matchesSelector, parseLabelTerm, parseSelector, splitTerms } from '../lib/labels';
import { plural } from '../lib/format';
import { IconClose } from './icons';

export interface TagInputProps {
  /** Id of the text field (a <label htmlFor={id}> names it). */
  id: string;
  value: Record<string, string>;
  onChange: (value: Record<string, string>) => void;
  placeholder?: string;
  readOnly?: boolean;
  disabled?: boolean;
  /** Accessible name of the chip list, e.g. "Labels added". */
  listLabel?: string;
  /** Shown instead of chips when read-only and empty. */
  emptyText?: ReactNode;
  /** Reports text that was typed but not accepted (so a form can block submit). */
  onDraftError?: (error: string | null) => void;
  'aria-invalid'?: boolean | 'true' | 'false';
  'aria-describedby'?: string;
}

const normalize = (s: string) => s.replace(/\s*=\s*/g, '=');

/**
 * Kubernetes labels as chips. Type key=value and press Enter, comma or Tab; a pasted
 * "a=b,c=d" becomes several chips. Invalid text stays in the field with a message.
 * Backspace in the empty field removes the last chip.
 */
export function TagInput({ id, value, onChange, placeholder = 'key=value', readOnly, disabled, listLabel = 'Labels added', emptyText = 'none', onDraftError, ...rest }: TagInputProps) {
  const [text, setText] = useState('');
  const [error, setErrorState] = useState<string | null>(null);
  const [announce, setAnnounce] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const entries = Object.entries(value);
  const errId = `${id}-tagerr`;

  const setError = (e: string | null) => {
    setErrorState(e);
    onDraftError?.(e);
  };

  /** Adds valid terms; returns the rejected ones and the first error. */
  const addTerms = (terms: string[]): { rest: string[]; error: string | null } => {
    const next = { ...value };
    const restTerms: string[] = [];
    const added: string[] = [];
    let err: string | null = null;
    for (const raw of terms) {
      const t = parseLabelTerm(raw);
      if (!t.ok) {
        restTerms.push(raw);
        err ??= t.error;
        continue;
      }
      if (t.key in next && next[t.key] !== t.value) {
        restTerms.push(raw);
        err ??= `${t.key} is already set to "${next[t.key]}". Remove that tag first.`;
        continue;
      }
      next[t.key] = t.value;
      added.push(`${t.key}=${t.value}`);
    }
    if (added.length) {
      onChange(next);
      setAnnounce(`Added ${added.join(', ')}`);
    }
    return { rest: restTerms, error: err };
  };

  const commit = (src: string): boolean => {
    const terms = splitTerms(normalize(src));
    if (terms.length === 0) {
      setText('');
      setError(null);
      return true;
    }
    const r = addTerms(terms);
    setText(r.rest.join(', '));
    setError(r.error);
    return r.error === null;
  };

  const remove = (key: string) => {
    const next = { ...value };
    const label = `${key}=${next[key]}`;
    delete next[key];
    onChange(next);
    setAnnounce(`Removed ${label}`);
    inputRef.current?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      if (!text.trim()) {
        if (e.key === ',') e.preventDefault();
        return; // empty Enter submits the form as usual
      }
      e.preventDefault();
      commit(text);
      return;
    }
    if (e.key === 'Tab' && text.trim()) {
      commit(text); // focus moves on as usual
      return;
    }
    if (e.key === 'Backspace' && text === '' && entries.length > 0) {
      e.preventDefault();
      remove(entries[entries.length - 1][0]);
    }
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData('text');
    if (!/[,;\n\s]/.test(normalize(pasted).trim())) return;
    e.preventDefault();
    commit(text + pasted);
  };

  const describedBy = [rest['aria-describedby'], error ? errId : null].filter(Boolean).join(' ') || undefined;
  const invalid = !!error || rest['aria-invalid'] === true || rest['aria-invalid'] === 'true';

  return (
    <>
      <div
        className={`tags-in${invalid ? ' invalid' : ''}${readOnly ? ' readonly' : ''}${disabled ? ' disabled' : ''}`}
        onMouseDown={(e) => {
          if (e.target === e.currentTarget && inputRef.current) {
            e.preventDefault();
            inputRef.current.focus();
          }
        }}
      >
        {entries.length > 0 ? (
          <ul className="tags" aria-label={listLabel} id={readOnly ? id : undefined}>
            {entries.map(([k, v]) => (
              <li key={k} className="tag">
                <span className="mono">
                  {k}={v}
                </span>
                {!readOnly && !disabled && (
                  <button type="button" className="tag-x" aria-label={`Remove ${k}=${v}`} onClick={() => remove(k)}>
                    <IconClose width={12} height={12} />
                  </button>
                )}
              </li>
            ))}
          </ul>
        ) : (
          readOnly && (
            <span className="muted small" id={id}>
              {emptyText}
            </span>
          )
        )}
        {!readOnly && (
          <input
            ref={inputRef}
            id={id}
            className="tags-field mono"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              if (error) setError(null);
            }}
            onKeyDown={onKeyDown}
            onPaste={onPaste}
            onBlur={() => {
              if (text.trim()) commit(text);
            }}
            placeholder={entries.length ? undefined : placeholder}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            disabled={disabled}
            enterKeyHint="enter"
          />
        )}
      </div>
      {error && (
        <div className="field-error" id={errId} role="alert">
          {error}
        </div>
      )}
      <span className="sr-only" aria-live="polite">
        {announce}
      </span>
    </>
  );
}

/**
 * Cluster scope by labels: key=value chips (AND-ed; none = all clusters), with an
 * "advanced selector" text mode for set-based expressions such as `env in (a,b)`.
 * Shows how many clusters match today.
 */
export function ScopeInput({
  id,
  value,
  onChange,
  clusters,
  error,
  hintId,
  onDraftError,
}: {
  id: string;
  /** Label selector; "" or "all" means all clusters. */
  value: string;
  onChange: (selector: string) => void;
  clusters?: { labels: Record<string, string> }[];
  error?: string;
  hintId?: string;
  onDraftError?: (error: string | null) => void;
}) {
  const [advanced, setAdvanced] = useState(() => equalityTerms(value) === null);
  const chips = equalityTerms(value) ?? {};
  const parsed = parseSelector(value);
  const all = value.trim() === '' || value.trim() === 'all';
  const matching = clusters && !parsed.error ? clusters.filter((c) => matchesSelector(value, c.labels ?? {})).length : null;
  const canChips = equalityTerms(value) !== null;
  const countId = `${id}-count`;
  const selErr = advanced && parsed.error ? parsed.error : undefined;
  const describedBy = [hintId, countId].filter(Boolean).join(' ');

  return (
    <div className="stack-sm" style={{ gap: 8 }}>
      {advanced ? (
        <input
          id={id}
          className="in mono"
          value={value === 'all' ? '' : value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="env in (prod,staging), team=data, !legacy"
          aria-invalid={!!(error || selErr) || undefined}
          aria-describedby={describedBy}
          autoComplete="off"
          spellCheck={false}
        />
      ) : (
        <TagInput id={id} value={chips} onChange={(m) => onChange(formatLabels(m, ','))} placeholder="All clusters · add env=prod" listLabel="Required labels" onDraftError={onDraftError} aria-invalid={!!error} aria-describedby={describedBy} />
      )}
      {selErr && (
        <div className="field-error" role="alert">
          {selErr}
        </div>
      )}
      <div className="spread small">
        <span className="muted" id={countId} aria-live="polite">
          {matching === null
            ? all
              ? 'All clusters'
              : ''
            : all
              ? `All clusters · ${plural(clusters!.length, 'cluster')} today`
              : `Matches ${plural(matching, 'cluster')} of ${clusters!.length} today`}
        </span>
        {advanced ? (
          <span className="inline-sm">
            {!canChips && <span className="muted" id={`${id}-chips-why`}>Only key=value terms can be chips</span>}
            <button
              type="button"
              className="link-btn"
              disabled={!canChips}
              aria-describedby={!canChips ? `${id}-chips-why` : undefined}
              onClick={() => {
                onDraftError?.(null);
                setAdvanced(false);
              }}
            >
              Use label chips
            </button>
          </span>
        ) : (
          <button
            type="button"
            className="link-btn"
            onClick={() => {
              onDraftError?.(null);
              setAdvanced(true);
            }}
          >
            Advanced selector
          </button>
        )}
      </div>
    </div>
  );
}
