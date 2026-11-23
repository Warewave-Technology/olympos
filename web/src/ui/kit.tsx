import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { ApiError, errorMessage } from '../api/client';
import { useFocusTrap } from '../lib/focusTrap';
import { IconClose, IconCopy, IconInbox } from './icons';

// ------------------------------------------------------------ badges
export type Tone = 'ok' | 'warn' | 'crit' | 'info' | 'mute';

/** Status badge. Always has text — status is never color-only. */
export function Badge({ tone = 'mute', children, title, className }: { tone?: Tone; children: ReactNode; title?: string; className?: string }) {
  return (
    <span className={`badge ${tone}${className ? ' ' + className : ''}`} title={title}>
      {children}
    </span>
  );
}

/** Errors longer than this are clamped to three lines with a toggle for the rest. */
const LONG_ERROR = 120;

/** An error that wraps anywhere; a long one is clamped to three lines, the full text one click away (and in the tooltip). */
export function ClampedError({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > LONG_ERROR;
  return (
    <span className="clamp-wrap">
      <span className={`clamp ico-crit${long && !open ? ' clamp-3' : ''}`} title={long ? text : undefined}>
        {text}
      </span>
      {long && (
        <button type="button" className="link-btn small" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? 'Show less' : 'Show the full error'}
        </button>
      )}
    </span>
  );
}

export function Chip({ children }: { children: ReactNode }) {
  return <span className="chip">{children}</span>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={`mono${className ? ' ' + className : ''}`}>{children}</span>;
}

/**
 * The only way a secret value is ever rendered: a fixed mask. There is no reveal
 * control and the component does not accept a value prop on purpose.
 */
export function SecretValue() {
  return (
    <span className="secret-hidden" aria-label="Value hidden" role="img">
      ••••••••
    </span>
  );
}

// ------------------------------------------------------------ states
export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <span className="spinner" role="status" aria-label={label} />;
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="state" aria-busy="true">
      <div className="inline">
        <Spinner label={label} />
        <span className="muted">{label}</span>
      </div>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state">
      <div className="state-title">{title}</div>
      {children && <div className="state-body">{children}</div>}
      {action && <div className="inline">{action}</div>}
    </div>
  );
}

/** Detail pane of a list/detail page when nothing is selected, so the page never looks half empty. */
export function DetailPlaceholder({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <section className="card detail-empty" aria-label={title}>
      <span className="ico-big" aria-hidden="true">
        {icon ?? <IconInbox />}
      </span>
      <h2>{title}</h2>
      {children && <p>{children}</p>}
    </section>
  );
}

/** Server messages are lowercase fragments ("not found"); show them as sentences. */
export function sentence(s: string): string {
  const t = s.trim();
  if (!t) return t;
  const c = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(c) ? c : c + '.';
}

function hintFor(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 0) return 'Check that the Olympos server is running and reachable, then retry.';
    if (e.status === 404) return 'It may have been removed, or it is outside the clusters your grants cover.';
    if (e.status === 403) return 'Ask an Olympos admin for a grant that covers this.';
    if (e.status >= 500) return 'Retry in a moment. If it keeps failing, check the server logs.';
  }
  return 'Retry. If it keeps failing, reload the page.';
}

export function ErrorState({ what, error, onRetry }: { what: string; error: unknown; onRetry?: () => void }) {
  if (error instanceof ApiError && error.status === 403) return <ForbiddenState what={what} />;
  return (
    <div className="state error" role="alert">
      <div className="state-title">Could not load {what}</div>
      <div className="state-body">
        {sentence(errorMessage(error))} {hintFor(error)}
      </div>
      {onRetry && (
        <button type="button" className="btn sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function ForbiddenState({ what }: { what: string }) {
  return (
    <div className="state">
      <div className="state-title">You do not have access to {what}</div>
      <div className="state-body">Your grants do not include this. Ask an Olympos admin (Settings › Access) to extend your role or scope.</div>
    </div>
  );
}

interface QueryLike<T> {
  data: T | undefined;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => unknown;
}

/** Renders loading / error / permission-denied / empty / content for a list query. */
export function QueryView<T>({
  q,
  what,
  isEmpty,
  empty,
  children,
}: {
  q: QueryLike<T>;
  what: string;
  isEmpty?: (d: T) => boolean;
  empty?: ReactNode;
  children: (d: T) => ReactNode;
}) {
  if (q.isPending) return <Loading label={`Loading ${what}…`} />;
  if (q.isError) return <ErrorState what={what} error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data as T;
  if (isEmpty && isEmpty(d)) return <>{empty}</>;
  return <>{children(d)}</>;
}

export function FormError({ error }: { error: unknown }) {
  if (!error) return null;
  const fields = error instanceof ApiError ? Object.keys(error.fields) : [];
  return (
    <div className="note crit" role="alert">
      <b>{sentence(errorMessage(error))}</b>
      {fields.length > 0 && <span> Check the highlighted fields.</span>}
    </div>
  );
}

export function fieldError(error: unknown, name: string): string | undefined {
  return error instanceof ApiError ? error.fields[name] : undefined;
}

// ------------------------------------------------------------ forms
export function Field({
  label,
  htmlFor,
  error,
  hint,
  children,
  className,
}: {
  label: ReactNode;
  htmlFor: string;
  error?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <label className="lbl" htmlFor={htmlFor} id={`${htmlFor}-label`}>
        {label}
      </label>
      {children}
      {error && (
        <div className="field-error" id={`${htmlFor}-err`} role="alert">
          {error}
        </div>
      )}
      {hint && !error && (
        <div className="field-hint" id={`${htmlFor}-hint`}>
          {hint}
        </div>
      )}
    </div>
  );
}

/** Props for an input inside <Field> so errors are announced. */
export function aria(id: string, error?: string, hint?: boolean) {
  return {
    id,
    'aria-invalid': error ? (true as const) : undefined,
    'aria-describedby': error ? `${id}-err` : hint ? `${id}-hint` : undefined,
  };
}

// ------------------------------------------------------------ modal & drawer
function usePortal(): HTMLElement {
  return document.body;
}

export function Modal({
  open,
  onClose,
  eyebrow,
  title,
  description,
  children,
  size,
  danger,
  eyebrowTone,
  initialFocus,
  closeOnBackdrop = true,
}: {
  open: boolean;
  onClose: () => void;
  eyebrow?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  size?: 'wide' | 'narrow' | 'xl';
  danger?: boolean;
  eyebrowTone?: 'crit';
  initialFocus?: React.RefObject<HTMLElement | null>;
  /** false: a click on the backdrop does not close (a filled form); Esc and the close button still do. */
  closeOnBackdrop?: boolean;
}) {
  const titleId = useId();
  const descId = useId();
  const ref = useFocusTrap<HTMLDivElement>(open, onClose, initialFocus);
  const target = usePortal();
  if (!open) return null;
  return createPortal(
    <div
      className="overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && closeOnBackdrop) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={`dialog${size ? ' ' + size : ''}${danger ? ' danger' : ''}`}
      >
        <div className="dialog-head">
          <div>
            {eyebrow && <div className={`eyebrow${eyebrowTone ? ' ' + eyebrowTone : ''}`}>{eyebrow}</div>}
            <h2 id={titleId}>{title}</h2>
            {description && (
              <div className="desc" id={descId}>
                {description}
              </div>
            )}
          </div>
          <button type="button" className="btn icon" aria-label="Close" onClick={onClose}>
            <IconClose />
          </button>
        </div>
        {children}
      </div>
    </div>,
    target,
  );
}

/** Right-side drawer with focus trap and Esc to close (Vaults change requests). */
export function Drawer({
  open,
  onClose,
  eyebrow,
  title,
  children,
  initialFocus,
}: {
  open: boolean;
  onClose: () => void;
  eyebrow?: ReactNode;
  title: ReactNode;
  children: ReactNode;
  initialFocus?: React.RefObject<HTMLElement | null>;
}) {
  const titleId = useId();
  const ref = useFocusTrap<HTMLElement>(open, onClose, initialFocus);
  const target = usePortal();
  if (!open) return null;
  return createPortal(
    <>
      <div className="drawer-overlay" aria-hidden="true" onMouseDown={onClose} />
      <aside ref={ref} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} className="drawer">
        <div className="spread">
          <span className="eyebrow">{eyebrow}</span>
          <button type="button" className="btn icon" aria-label="Close" onClick={onClose}>
            <IconClose />
          </button>
        </div>
        <h2 id={titleId}>{title}</h2>
        {children}
      </aside>
    </>,
    target,
  );
}

// ------------------------------------------------------------ misc controls
export function CopyButton({ text, label = 'Copy', className = 'btn' }: { text: string; label?: string; className?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  useEffect(() => {
    if (state === 'idle') return;
    const t = setTimeout(() => setState('idle'), 2000);
    return () => clearTimeout(t);
  }, [state]);
  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setState('ok');
        } catch {
          setState('fail');
        }
      }}
    >
      <IconCopy />
      <span aria-live="polite">{state === 'ok' ? 'Copied' : state === 'fail' ? 'Copy failed — select the text' : label}</span>
    </button>
  );
}

/** Type-to-confirm input for irreversible actions. */
export function TypeToConfirm({ expected, value, onChange, label, id }: { expected: string; value: string; onChange: (v: string) => void; label?: ReactNode; id: string }) {
  const ok = value === expected;
  return (
    <div>
      <label className="lbl" htmlFor={id}>
        {label ?? (
          <>
            Type <span className="mono">{expected}</span> to confirm
          </>
        )}
      </label>
      <input
        id={id}
        className="in mono"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        aria-describedby={`${id}-hint`}
      />
      <div className="field-hint" id={`${id}-hint`} aria-live="polite">
        {ok ? 'Matches.' : value ? 'Does not match yet.' : ' '}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button
          key={t.id}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="button"
          role="tab"
          aria-selected={value === t.id}
          tabIndex={value === t.id ? 0 : -1}
          onClick={() => onChange(t.id)}
          onKeyDown={(e) => {
            if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
            const n = (i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
            onChange(tabs[n].id);
            refs.current[n]?.focus();
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ------------------------------------------------------------ toasts
type Toast = { id: number; text: string; tone: 'ok' | 'crit' | 'info' | 'warn' };
const ToastCtx = createContext<(text: string, tone?: Toast['tone']) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast['tone'] = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div aria-live="polite" role="status">
        {toasts.slice(-1).map((t) => (
          <div key={t.id} className={`toast ${t.tone}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}

/**
 * Runs an async action and tracks pending/error WITHOUT remembering its arguments.
 * Used instead of useMutation wherever the request carries a secret (passwords, root
 * tokens, SAS tokens, change-request values): useMutation keeps `variables` in the
 * mutation cache, this does not.
 */
export function useAction<R>() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const run = useCallback(async (fn: () => Promise<R>): Promise<R | undefined> => {
    setPending(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      if (mounted.current) setError(e);
      return undefined;
    } finally {
      if (mounted.current) setPending(false);
    }
  }, []);
  const reset = useCallback(() => setError(null), []);
  return { run, pending, error, reset };
}

/** Re-render every `ms` (countdowns, "40 s ago"). */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}
