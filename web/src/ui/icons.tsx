// Small inline SVG icons. Decorative unless a label is passed.
import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement> & { label?: string };

function Svg({ label, children, ...rest }: P & { children: React.ReactNode }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={label ? undefined : true}
      role={label ? 'img' : undefined}
      aria-label={label}
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconClose = (p: P) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Svg>
);
export const IconCheck = (p: P) => (
  <Svg {...p}>
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </Svg>
);
export const IconCross = (p: P) => (
  <Svg {...p}>
    <path d="M7 7l10 10M17 7L7 17" />
  </Svg>
);
export const IconWarn = (p: P) => (
  <Svg {...p}>
    <path d="M12 4l9 16H3z" />
    <path d="M12 10v4M12 17.5v.01" />
  </Svg>
);
export const IconInfo = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5M12 8v.01" />
  </Svg>
);
export const IconCopy = (p: P) => (
  <Svg {...p}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a1 1 0 011-1h9" />
  </Svg>
);
export const IconMenu = (p: P) => (
  <Svg {...p}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </Svg>
);
export const IconClock = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Svg>
);

export const IconChevronDown = (p: P) => (
  <Svg {...p}>
    <path d="M6 9l6 6 6-6" />
  </Svg>
);
export const IconSearch = (p: P) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  </Svg>
);
export const IconInbox = (p: P) => (
  <Svg {...p}>
    <path d="M3 13l3-8h12l3 8" />
    <path d="M3 13v6h18v-6h-6l-1.5 2h-3L9 13z" />
  </Svg>
);

export function IconMicrosoft(p: SVGProps<SVGSVGElement>) {
  return (
    <svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true" focusable="false" {...p}>
      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
    </svg>
  );
}

/** ✓ / ✗ / ! with a text alternative so status is never icon-only. */
export function CheckIcon({ ok, warn, label }: { ok: boolean | null | undefined; warn?: boolean; label?: string }) {
  if (ok === null || ok === undefined) return <IconClock className="ico ico-muted" label={label ?? 'Pending'} />;
  if (warn) return <IconWarn className="ico ico-warn" label={label ?? 'Warning'} />;
  return ok ? <IconCheck className="ico ico-ok" label={label ?? 'Passed'} /> : <IconCross className="ico ico-crit" label={label ?? 'Failed'} />;
}
