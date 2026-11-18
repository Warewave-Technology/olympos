import { useRef, useState, type ClipboardEvent, type KeyboardEvent, type ReactNode } from 'react';
import { equalityTerms, formatLabels, matchesSelector, parseLabelTerm, parseSelector, splitTerms } from '../lib/labels';
import { plural } from '../lib/format';
import { IconClose } from './icons';

interface TagInputCommon {
  /** Id of the text field (a <label htmlFor={id}> names it). */
  id: string;
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
/** Kubernetes labels: key=value chips. */
export interface TagInputLabelsProps extends TagInputCommon {
  mode?: 'labels';
  value: Record<string, string>;
  onChange: (value: Record<string, string>) => void;
}
/** Plain values (database names, …): one chip per value, duplicates ignored. */
export interface TagInputValuesProps extends TagInputCommon {
  mode: 'values';
  value: string[];
  onChange: (value: string[]) => void;
  /** Returns an error message for a value that is not accepted (default: no spaces or commas). */
  validate?: (value: string) => string | null;
}
export type TagInputProps = TagInputLabelsProps | TagInputValuesProps;

const normalize = (s: string) => s.replace(/\s*=\s*/g, '=');

/** Loose check for a plain value chip: not empty, no whitespace or commas, at most 128 characters. */
export function validatePlainValue(v: string): string | null {
  if (!v) return 'Enter a value.';
  if (/[\s,;]/.test(v)) return `"${v}" contains a space or comma. Enter one name per chip.`;
  if (v.length > 128) return 'Use at most 128 characters.';
  return null;
}

/** PostgreSQL / ClickHouse database identifier, checked loosely (quoted identifiers allow almost anything). */
export function validateDatabaseName(v: string): string | null {
  const e = validatePlainValue(v);
  if (e) return e.replace('Enter a value.', 'Enter a database name.');
  if (/["'`\\]/.test(v)) return `"${v}" contains a quote or backslash. Use the plain database name.`;
  if (v.length > 63) return 'Database names are at most 63 characters.';
  return null;
}

type Parsed = { ok: true; key: string; label: string } | { ok: false; error: string };

/**
 * Chips input. `mode="labels"` (default): Kubernetes labels, type key=value and press
 * Enter, comma or Tab; a pasted "a=b,c=d" becomes several chips. `mode="values"`: plain
 * values such as database names (no key=value). Invalid text stays in the field with a
 * message. Backspace in the empty field removes the last chip.
 */
export function TagInput(props: TagInputProps) {
  const { id, readOnly, disabled, onDraftError, ...rest } = props;
  const values = props.mode === 'values';
  const placeholder = props.placeholder ?? (values ? 'name' : 'key=value');
  const listLabel = props.listLabel ?? (values ? 'Values added' : 'Labels added');
  const emptyText = props.emptyText ?? 'none';
  const [text, setText] = useState('');
  const [error, setErrorState] = useState<string | null>(null);
  const [announce, setAnnounce] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const items: { key: string; label: string }[] = props.mode === 'values' ? props.value.map((v) => ({ key: v, label: v })) : Object.entries(props.value).map(([k, v]) => ({ key: k, label: `${k}=${v}` }));
  const errId = `${id}-tagerr`;

  const setError = (e: string | null) => {
    setErrorState(e);
    onDraftError?.(e);
  };

  const parse = (raw: string): Parsed => {
    if (props.mode === 'values') {
      const e = (props.validate ?? validatePlainValue)(raw);
      return e ? { ok: false, error: e } : { ok: true, key: raw, label: raw };
    }
    const t = parseLabelTerm(raw);
    return t.ok ? { ok: true, key: t.key, label: `${t.key}=${t.value}` } : { ok: false, error: t.error };
  };

  /** Adds valid terms; returns the rejected ones and the first error. */
  const addTerms = (terms: string[]): { rest: string[]; error: string | null } => {
    const restTerms: string[] = [];
    const added: string[] = [];
    let err: string | null = null;
    if (props.mode === 'values') {
      const next = [...props.value];
      for (const raw of terms) {
        const t = parse(raw);
        if (!t.ok) {
          restTerms.push(raw);
          err ??= t.error;
          continue;
        }
        if (next.includes(t.key)) continue; // already there: nothing to add
        next.push(t.key);
        added.push(t.label);
      }
      if (added.length) props.onChange(next);
    } else {
      const next = { ...props.value };
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
      if (added.length) props.onChange(next);
    }
    if (added.length) setAnnounce(`Added ${added.join(', ')}`);
    return { rest: restTerms, error: err };
  };

  const commit = (src: string): boolean => {
    const terms = splitTerms(values ? src : normalize(src));
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
    const item = items.find((i) => i.key === key);
    if (props.mode === 'values') props.onChange(props.value.filter((v) => v !== key));
    else {
      const next = { ...props.value };
      delete next[key];
      props.onChange(next);
    }
    setAnnounce(`Removed ${item?.label ?? key}`);
    inputRef.current?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',' || (values && e.key === ' ')) {
      if (!text.trim()) {
        if (e.key !== 'Enter') e.preventDefault();
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
    if (e.key === 'Backspace' && text === '' && items.length > 0) {
      e.preventDefault();
      remove(items[items.length - 1].key);
    }
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData('text');
    if (!/[,;\n\s]/.test((values ? pasted : normalize(pasted)).trim())) return;
    e.preventDefault();
    commit(text + (text && values ? ',' : '') + pasted);
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
        {items.length > 0 ? (
          <ul className="tags" aria-label={listLabel} id={readOnly ? id : undefined}>
            {items.map((it) => (
              <li key={it.key} className="tag">
                <span className="mono">{it.label}</span>
                {!readOnly && !disabled && (
                  <button type="button" className="tag-x" aria-label={`Remove ${it.label}`} onClick={() => remove(it.key)}>
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
            placeholder={items.length ? undefined : placeholder}
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
