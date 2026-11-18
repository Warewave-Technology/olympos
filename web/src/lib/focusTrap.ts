import { useEffect, useRef } from 'react';

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export function focusableIn(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.hasAttribute('inert') && el.getAttribute('aria-hidden') !== 'true');
}

/** Open traps, innermost last: only the top one reacts to keys and focus (nested dialogs). */
const stack: object[] = [];

/**
 * Traps Tab/Shift+Tab inside `ref`, closes on Escape, focuses the first field on open
 * (or `initialFocus`), and returns focus to the previously focused element on close.
 */
export function useFocusTrap<T extends HTMLElement>(active: boolean, onEscape: () => void, initialFocus?: React.RefObject<HTMLElement | null>) {
  const ref = useRef<T | null>(null);
  const escRef = useRef(onEscape);
  escRef.current = onEscape;

  useEffect(() => {
    if (!active) return;
    const root = ref.current;
    if (!root) return;
    const previous = document.activeElement as HTMLElement | null;
    const items = focusableIn(root);
    const first =
      initialFocus?.current ??
      items.find((el) => el.getAttribute('data-autofocus') !== null) ??
      items.find((el) => el.matches('input:not([readonly]),select,textarea')) ??
      items[0] ??
      root;
    first.focus();
    const token = {};
    stack.push(token);
    const top = () => stack[stack.length - 1] === token;

    const onKey = (e: KeyboardEvent) => {
      if (!top()) return;
      if (e.key === 'Escape') {
        // An open popover (Select listbox) inside the dialog closes itself first.
        if (e.target instanceof Element && e.target.closest('[data-popover-open="true"]')) return;
        e.stopPropagation();
        e.preventDefault();
        escRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const items = focusableIn(root);
      if (items.length === 0) {
        e.preventDefault();
        root.focus();
        return;
      }
      const firstEl = items[0];
      const lastEl = items[items.length - 1];
      const cur = document.activeElement as HTMLElement | null;
      if (e.shiftKey && (cur === firstEl || !root.contains(cur))) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && (cur === lastEl || !root.contains(cur))) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    const onFocusIn = (e: FocusEvent) => {
      if (!top()) return;
      if (root && e.target instanceof Node && !root.contains(e.target)) {
        const items = focusableIn(root);
        (items[0] ?? root).focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('focusin', onFocusIn);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('focusin', onFocusIn);
      document.body.style.overflow = prevOverflow;
      const i = stack.indexOf(token);
      if (i >= 0) stack.splice(i, 1);
      if (previous && document.contains(previous)) previous.focus();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  return ref;
}
