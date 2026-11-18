import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { IconCheck, IconChevronDown, IconSearch } from './icons';

export interface SelectOption<T extends string = string> {
  value: T;
  label: ReactNode;
  /** Plain text for typeahead and search; defaults to `label` when it is a string. */
  text?: string;
  /** Secondary line under the label. */
  hint?: ReactNode;
  disabled?: boolean;
}

export interface SelectProps<T extends string> {
  /** Id of the trigger button; a <label htmlFor={id}> (e.g. from <Field>) names it. */
  id?: string;
  value: T;
  onChange: (value: T) => void;
  options: SelectOption<T>[];
  placeholder?: ReactNode;
  /** Adds a filter field to the popover (long lists such as time zones). */
  searchable?: boolean;
  searchLabel?: string;
  disabled?: boolean;
  invalid?: boolean;
  size?: 'sm';
  mono?: boolean;
  /** Fit the trigger to its content instead of the full width (toolbar filters). */
  inline?: boolean;
  className?: string;
  'aria-label'?: string;
  'aria-labelledby'?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean | 'true' | 'false';
}

const textOf = (o: SelectOption): string => o.text ?? (typeof o.label === 'string' ? o.label : String(o.value));

function nextEnabled(list: SelectOption[], from: number, dir: 1 | -1): number {
  for (let i = from; i >= 0 && i < list.length; i += dir) if (!list[i].disabled) return i;
  return -1;
}

export interface PopoverPlacement {
  left: number;
  width: number;
  top?: number;
  bottom?: number;
  maxHeight: number;
}

/** Widest a popover grows to fit its option text; longer labels end in an ellipsis. */
export const POPOVER_MAX_WIDTH = 440;
const EDGE = 8;

/**
 * Where the listbox goes: at least as wide as the trigger, as wide as its longest option
 * (`content`, measured without wrapping) up to POPOVER_MAX_WIDTH and the viewport, below the
 * trigger unless there is clearly more room above, and shifted/right-aligned to stay on screen.
 */
export function placePopover(
  trigger: { left: number; right: number; top: number; bottom: number; width: number },
  viewport: { width: number; height: number },
  content: { width: number },
  opts: { searchable?: boolean } = {},
): PopoverPlacement {
  const vw = viewport.width;
  const vh = viewport.height;
  const room = Math.max(0, vw - 2 * EDGE);
  const width = Math.min(room, Math.max(trigger.width, Math.min(Math.ceil(content.width), POPOVER_MAX_WIDTH)));
  // left-align with the trigger; when that overflows, right-align with it; then clamp to the viewport
  let left = trigger.left;
  if (left + width > vw - EDGE) left = trigger.right - width;
  left = Math.max(EDGE, Math.min(left, vw - EDGE - width));
  const below = vh - trigger.bottom - 12;
  const above = trigger.top - 12;
  const want = opts.searchable ? 360 : 320;
  const up = below < Math.min(want, 220) && above > below;
  return {
    left,
    width,
    top: up ? undefined : trigger.bottom + 4,
    bottom: up ? vh - trigger.top + 4 : undefined,
    maxHeight: Math.max(140, Math.min(want, up ? above : below)),
  };
}

/**
 * Select-only combobox (WAI-ARIA APG): a button that opens a listbox popover.
 * Keyboard: ↓/↑/Enter/Space open; ↓ ↑ Home End PageUp PageDown move; type to jump;
 * Enter/Space choose; Esc closes without changing the value (and does not close an
 * enclosing dialog). The popover is rendered next to the trigger (not portalled) so it
 * stays inside dialog focus traps, and positioned `fixed` so scroll containers do not
 * clip it.
 */
export function Select<T extends string>(props: SelectProps<T>) {
  const { value, onChange, options, placeholder = 'Select…', searchable, searchLabel = 'Filter options', disabled, size, mono, inline, className } = props;
  const auto = useId().replace(/:/g, '');
  const id = props.id ?? `sel-${auto}`;
  const listId = `${id}-listbox`;
  const optId = (i: number) => `${id}-opt-${i}`;
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [query, setQuery] = useState('');
  const [pos, setPos] = useState<PopoverPlacement | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const typed = useRef({ buf: '', at: 0 });

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return searchable && q ? options.filter((o) => textOf(o).toLowerCase().includes(q)) : options;
  }, [options, query, searchable]);
  const selectedIndex = options.findIndex((o) => o.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;
  const invalid = props.invalid || props['aria-invalid'] === true || props['aria-invalid'] === 'true';

  const popRef = useRef<HTMLDivElement>(null);
  /** Natural (unwrapped) width of the open popover, measured once per opening. */
  const natural = useRef(0);
  const place = useCallback(() => {
    const b = btnRef.current;
    if (!b) return;
    const pop = popRef.current;
    if (pop && !natural.current) {
      // measure at max-content (labels never wrap), before an explicit width is set
      const prev = pop.style.width;
      pop.style.width = 'max-content';
      natural.current = pop.getBoundingClientRect().width || pop.scrollWidth;
      pop.style.width = prev;
    }
    setPos(placePopover(b.getBoundingClientRect(), { width: window.innerWidth || 1200, height: window.innerHeight || 800 }, { width: natural.current }, { searchable }));
  }, [searchable]);

  const openList = (at: 'selected' | 'first' | 'last' | number = 'selected', initialQuery = '') => {
    if (disabled) return;
    setQuery(initialQuery);
    const list = initialQuery ? options.filter((o) => textOf(o).toLowerCase().includes(initialQuery.toLowerCase())) : options;
    let i: number;
    if (typeof at === 'number') i = at;
    else if (at === 'first' || initialQuery) i = nextEnabled(list, 0, 1);
    else if (at === 'last') i = nextEnabled(list, list.length - 1, -1);
    else i = selectedIndex >= 0 && !options[selectedIndex].disabled ? selectedIndex : nextEnabled(list, 0, 1);
    setActive(i);
    setOpen(true);
  };

  const close = useCallback((focusTrigger = true) => {
    setOpen(false);
    setQuery('');
    if (focusTrigger) btnRef.current?.focus();
  }, []);

  const commit = (i: number) => {
    const o = visible[i];
    if (!o || o.disabled) return;
    close();
    if (o.value !== value) onChange(o.value);
  };

  /** Type-to-select: repeated first letter cycles, a quick sequence matches a prefix. */
  const typeAhead = (ch: string): number => {
    const now = Date.now();
    const t = typed.current;
    t.buf = now - t.at > 700 ? ch : t.buf + ch;
    t.at = now;
    const buf = t.buf.toLowerCase();
    const repeat = buf.length > 1 && [...buf].every((c) => c === buf[0]);
    const needle = repeat ? buf[0] : buf;
    const from = open ? active : selectedIndex;
    const base = from < 0 ? 0 : from;
    const offset = from < 0 ? 0 : needle.length === 1 ? 1 : 0;
    const n = options.length;
    for (let k = 0; k < n; k++) {
      const i = (base + offset + k) % n;
      const o = options[i];
      if (!o.disabled && textOf(o).toLowerCase().startsWith(needle)) return i;
    }
    return -1;
  };

  const page = (dir: 1 | -1) =>
    setActive((a) => {
      let target = Math.max(0, Math.min(visible.length - 1, a + dir * 10));
      const n = nextEnabled(visible, target, dir);
      target = n >= 0 ? n : nextEnabled(visible, target, dir === 1 ? -1 : 1);
      return target >= 0 ? target : a;
    });

  const listKeys = (e: KeyboardEvent, inInput: boolean) => {
    const plain = !e.ctrlKey && !e.metaKey && !e.altKey;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setActive((a) => {
          const n = nextEnabled(visible, a + 1, 1);
          return n >= 0 ? n : a;
        });
        return;
      case 'ArrowUp':
        e.preventDefault();
        if (e.altKey) {
          commit(active);
          return;
        }
        setActive((a) => {
          const n = nextEnabled(visible, a - 1, -1);
          return n >= 0 ? n : a;
        });
        return;
      case 'Home':
        if (inInput) return;
        e.preventDefault();
        setActive(nextEnabled(visible, 0, 1));
        return;
      case 'End':
        if (inInput) return;
        e.preventDefault();
        setActive(nextEnabled(visible, visible.length - 1, -1));
        return;
      case 'PageDown':
        e.preventDefault();
        page(1);
        return;
      case 'PageUp':
        e.preventDefault();
        page(-1);
        return;
      case 'Enter':
        e.preventDefault();
        commit(active);
        return;
      case ' ':
        if (inInput) return;
        e.preventDefault();
        commit(active);
        return;
      case 'Escape':
        e.preventDefault();
        e.stopPropagation();
        close();
        return;
      case 'Tab':
        if (inInput) {
          e.preventDefault();
          close();
        } else close(false);
        return;
      default:
        if (!inInput && plain && e.key.length === 1) {
          const i = typeAhead(e.key);
          if (i >= 0) setActive(i);
        }
    }
  };

  const onTriggerKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (open) {
      if (!searchable) listKeys(e, false);
      return;
    }
    const plain = !e.ctrlKey && !e.metaKey && !e.altKey;
    switch (e.key) {
      case 'ArrowDown':
      case 'ArrowUp':
      case 'Enter':
      case ' ':
        e.preventDefault();
        openList('selected');
        return;
      case 'Home':
        e.preventDefault();
        openList('first');
        return;
      case 'End':
        e.preventDefault();
        openList('last');
        return;
      default:
        if (plain && e.key.length === 1) {
          e.preventDefault();
          if (searchable) openList('first', e.key);
          else {
            const i = typeAhead(e.key);
            if (i >= 0) openList(i);
          }
        }
    }
  };

  // Position while open; follow scroll and resize.
  useLayoutEffect(() => {
    if (!open) {
      natural.current = 0;
      setPos(null);
      return;
    }
    place();
    const on = () => place();
    window.addEventListener('resize', on);
    window.addEventListener('scroll', on, true);
    return () => {
      window.removeEventListener('resize', on);
      window.removeEventListener('scroll', on, true);
    };
  }, [open, place]);

  // Close on a press outside.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && e.target instanceof Node && !rootRef.current.contains(e.target)) close(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open, close]);

  // focus the filter once the popover is placed (a hidden, unplaced popover cannot take focus)
  const placed = !!pos;
  useEffect(() => {
    if (open && searchable && placed) searchRef.current?.focus();
  }, [open, searchable, placed]);

  // Filtering resets the active option to the first match.
  useEffect(() => {
    if (open && searchable) setActive(nextEnabled(visible, 0, 1));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  useEffect(() => {
    if (!open || active < 0) return;
    const el = document.getElementById(optId(active));
    el?.scrollIntoView?.({ block: 'nearest' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, active]);

  const listLabelledBy = props['aria-labelledby'] ?? (props['aria-label'] ? undefined : `${id}-label`);
  const activeId = open && active >= 0 && active < visible.length ? optId(active) : undefined;

  return (
    <div
      ref={rootRef}
      className={`select${size ? ' ' + size : ''}${inline ? ' inline' : ''}${className ? ' ' + className : ''}`}
      data-popover-open={open ? 'true' : undefined}
    >
      <button
        ref={btnRef}
        id={id}
        type="button"
        role="combobox"
        className={`select-btn${mono ? ' mono' : ''}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        aria-activedescendant={!searchable ? activeId : undefined}
        aria-label={props['aria-label']}
        aria-labelledby={props['aria-labelledby']}
        aria-describedby={props['aria-describedby']}
        aria-invalid={invalid || undefined}
        disabled={disabled}
        onClick={() => (open ? close() : openList('selected'))}
        onKeyDown={onTriggerKey}
      >
        <span className={`select-value${selected || value ? '' : ' placeholder'}`}>{selected ? selected.label : value || placeholder}</span>
        <IconChevronDown className="select-chevron" />
      </button>
      {open && (
        <div ref={popRef} className="select-pop" style={pos ? { left: pos.left, top: pos.top, bottom: pos.bottom, width: pos.width } : { visibility: 'hidden', left: 0, top: 0 }}>
          {searchable && (
            <div className="select-search">
              <IconSearch className="ico-muted" />
              <input
                ref={searchRef}
                type="text"
                role="searchbox"
                aria-label={searchLabel}
                aria-controls={listId}
                aria-activedescendant={activeId}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => listKeys(e, true)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          )}
          <ul id={listId} role="listbox" aria-labelledby={listLabelledBy} aria-label={listLabelledBy ? undefined : props['aria-label']} tabIndex={-1} className="select-list" style={pos ? { maxHeight: pos.maxHeight - (searchable ? 48 : 0) } : undefined}>
            {visible.map((o, i) => {
              const sel = o.value === value;
              return (
                <li
                  key={o.value}
                  id={optId(i)}
                  role="option"
                  aria-selected={sel}
                  aria-disabled={o.disabled || undefined}
                  className={`select-opt${i === active ? ' active' : ''}${sel ? ' selected' : ''}${mono ? ' mono' : ''}`}
                  onMouseDown={(e) => e.preventDefault()}
                  onMouseMove={() => {
                    if (!o.disabled && i !== active) setActive(i);
                  }}
                  onClick={() => commit(i)}
                >
                  <span className="select-check" aria-hidden="true">
                    {sel && <IconCheck />}
                  </span>
                  <span className="select-opt-body">
                    <span className="select-opt-label" title={textOf(o)}>
                      {o.label}
                    </span>
                    {o.hint && <span className="select-opt-hint">{o.hint}</span>}
                  </span>
                </li>
              );
            })}
          </ul>
          {visible.length === 0 && (
            <div className="select-empty" role="status">
              {query ? <>Nothing matches “{query}”.</> : 'No options.'}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
