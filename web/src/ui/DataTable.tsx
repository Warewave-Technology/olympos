import { useEffect, useMemo, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from 'react';
import { EmptyState, ErrorState, Loading } from './kit';
import { Select } from './Select';
import { IconChevronDown } from './icons';

export type SortDir = 'asc' | 'desc';
export type SortValue = string | number | boolean | null | undefined;

export interface Column<T> {
  id: string;
  header: ReactNode;
  /** Plain-text header for screen readers when `header` is not a string (or is visually hidden). */
  headerText?: string;
  cell: (row: T) => ReactNode;
  /** Makes the column sortable (client side). Nulls always sort last. */
  sortValue?: (row: T) => SortValue;
  /** First click sorts this way (default asc; numbers usually want desc). */
  defaultDir?: SortDir;
  /** Text the filter matches against (defaults to the sort value when it is a string). */
  searchText?: (row: T) => string;
  align?: 'num' | 'actions';
  /** Extra class on every <td> (e.g. "mono", "wrap"). */
  className?: string | ((row: T) => string | undefined);
  thClassName?: string;
  /** Header hidden visually (e.g. the actions column). */
  srOnlyHeader?: boolean;
  hidden?: boolean;
  style?: React.CSSProperties;
}

export interface DataTableProps<T> {
  rows: T[] | undefined;
  columns: Column<T>[];
  rowKey: (row: T) => string;
  /** Accessible name of the table. */
  label: string;
  /** "images", "backup runs" — used by the loading and error states. */
  what?: string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** Shown when there are no rows at all. */
  empty?: ReactNode;
  /** Shown when rows exist but the filter hides all of them. */
  noMatch?: ReactNode;
  /** Client-side text filter: the table matches it against each column's searchText. */
  filterText?: string;
  /** Custom filter instead of the column search text. */
  filterFn?: (row: T, q: string) => boolean;
  initialSort?: { id: string; dir: SortDir } | null;
  /** Rows per page (default 25). `false` turns paging off (short, fixed lists). */
  pageSize?: number | false;
  pageSizes?: number[];
  onRowClick?: (row: T) => void;
  /** Accessible name of a clickable row ("Open orders-pg"). */
  rowLabel?: (row: T) => string;
  rowClassName?: (row: T) => string | undefined;
  /** Sticky header inside a scroll box (default on). */
  stickyHeader?: boolean;
  /** Extra footer content to the right of the range (e.g. "Load older"). */
  footerExtra?: ReactNode;
  /** Changes the range text, e.g. "loaded" for server-paged lists. */
  countNoun?: string;
  /** Resets to the first page when this value changes (filters outside the table). */
  resetKey?: unknown;
  className?: string;
  /** Called with the rows after filter and sort (export, counts). */
  onVisibleRows?: (rows: T[]) => void;
}

const DEFAULT_SIZES = [25, 50, 100];

function compare(a: SortValue, b: SortValue): number {
  const an = a === null || a === undefined || a === '';
  const bn = b === null || b === undefined || b === '';
  if (an && bn) return 0;
  if (an) return 1;
  if (bn) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

const interactive = (el: EventTarget | null, row: HTMLElement): boolean => {
  let n = el as HTMLElement | null;
  while (n && n !== row) {
    if (/^(A|BUTTON|INPUT|SELECT|TEXTAREA|LABEL|SUMMARY)$/.test(n.tagName) || n.getAttribute('role') === 'button') return true;
    n = n.parentElement;
  }
  return false;
};

/**
 * Table with column definitions, client-side sort, a filter hook-in and paging.
 * Sortable headers are buttons (Enter/Space) and carry aria-sort. Clickable rows are
 * focusable and open with Enter or Space; clicks on links and buttons inside a row
 * keep their own behaviour.
 */
export function DataTable<T>(props: DataTableProps<T>) {
  const { rows, columns: allColumns, rowKey, label, what = 'rows', loading, error, onRetry, empty, noMatch, filterText = '', filterFn, onRowClick, rowLabel, rowClassName, stickyHeader = true, footerExtra, countNoun, resetKey, className, onVisibleRows } = props;
  const columns = allColumns.filter((c) => !c.hidden);
  const sizes = props.pageSizes ?? DEFAULT_SIZES;
  const paged = props.pageSize !== false;
  const [size, setSize] = useState<number>(typeof props.pageSize === 'number' ? props.pageSize : sizes[0]);
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<{ id: string; dir: SortDir } | null>(props.initialSort ?? null);

  const q = filterText.trim().toLowerCase();
  const filtered = useMemo(() => {
    const list = rows ?? [];
    if (!q) return list;
    if (filterFn) return list.filter((r) => filterFn(r, q));
    return list.filter((r) =>
      columns.some((c) => {
        const t = c.searchText ? c.searchText(r) : c.sortValue ? c.sortValue(r) : undefined;
        return typeof t === 'string' && t.toLowerCase().includes(q);
      }),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, q, filterFn, allColumns]);

  const sorted = useMemo(() => {
    const col = sort && columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return filtered;
    const get = col.sortValue;
    const dir = sort!.dir === 'asc' ? 1 : -1;
    // nulls last in both directions; stable for equal keys
    return filtered
      .map((r, i) => ({ r, i, v: get(r) }))
      .sort((a, b) => {
        const an = a.v === null || a.v === undefined || a.v === '';
        const bn = b.v === null || b.v === undefined || b.v === '';
        if (an !== bn) return an ? 1 : -1;
        return compare(a.v, b.v) * dir || a.i - b.i;
      })
      .map((x) => x.r);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, sort, allColumns]);

  useEffect(() => {
    onVisibleRows?.(sorted);
  }, [sorted, onVisibleRows]);

  useEffect(() => setPage(0), [q, resetKey, size]);
  const pages = paged ? Math.max(1, Math.ceil(sorted.length / size)) : 1;
  const cur = Math.min(page, pages - 1);
  const visible = paged ? sorted.slice(cur * size, cur * size + size) : sorted;

  const toggleSort = (c: Column<T>) => {
    setSort((s) => (s && s.id === c.id ? { id: c.id, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { id: c.id, dir: c.defaultDir ?? 'asc' }));
    setPage(0);
  };

  if (loading) return <Loading label={`Loading ${what}…`} />;
  if (error) return <ErrorState what={what} error={error} onRetry={onRetry} />;
  if ((rows ?? []).length === 0) return <>{empty ?? <EmptyState title={`No ${what} yet`} />}</>;

  const activate = (r: T) => onRowClick?.(r);
  const from = sorted.length === 0 ? 0 : cur * size + 1;
  const to = paged ? Math.min(sorted.length, cur * size + size) : sorted.length;
  const showPager = paged && sorted.length > Math.min(...sizes);
  const total = (rows ?? []).length;

  return (
    <div className={`dt${className ? ' ' + className : ''}`}>
      <div className={`table-wrap${stickyHeader ? ' dt-scroll' : ''}`}>
        <table className="t" aria-label={label} aria-rowcount={sorted.length + 1}>
          <thead>
            <tr>
              {columns.map((c) => {
                const active = sort?.id === c.id;
                const ariaSort = c.sortValue ? (active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined;
                const cls = [c.align === 'num' ? 'num' : c.align === 'actions' ? 'actions' : '', c.thClassName ?? '', c.sortValue ? 'sortable' : ''].filter(Boolean).join(' ') || undefined;
                return (
                  <th key={c.id} scope="col" aria-sort={ariaSort} className={cls} style={c.style}>
                    {c.srOnlyHeader ? (
                      <span className="sr-only">{c.headerText ?? c.header}</span>
                    ) : c.sortValue ? (
                      <button type="button" className={`th-sort${active ? ' on' : ''}`} onClick={() => toggleSort(c)} aria-label={c.headerText}>
                        <span>{c.header}</span>
                        <IconChevronDown className={`th-sort-ico${active ? (sort!.dir === 'asc' ? ' asc' : ' desc') : ''}`} aria-hidden="true" />
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="wrap">
                  {noMatch ?? <EmptyState title="Nothing matches">Try another search or filter.</EmptyState>}
                </td>
              </tr>
            ) : (
              visible.map((r) => {
                const extra = rowClassName?.(r);
                const cls = [onRowClick ? 'clickable' : '', extra ?? ''].filter(Boolean).join(' ') || undefined;
                return (
                  <tr
                    key={rowKey(r)}
                    className={cls}
                    tabIndex={onRowClick ? 0 : undefined}
                    aria-label={onRowClick && rowLabel ? rowLabel(r) : undefined}
                    onClick={
                      onRowClick
                        ? (e: MouseEvent<HTMLTableRowElement>) => {
                            if (interactive(e.target, e.currentTarget)) return;
                            activate(r);
                          }
                        : undefined
                    }
                    onKeyDown={
                      onRowClick
                        ? (e: KeyboardEvent<HTMLTableRowElement>) => {
                            if (e.target !== e.currentTarget) return;
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              activate(r);
                            }
                          }
                        : undefined
                    }
                  >
                    {columns.map((c) => {
                      const extraCls = typeof c.className === 'function' ? c.className(r) : c.className;
                      const tdCls = [c.align === 'num' ? 'num' : c.align === 'actions' ? 'actions' : '', extraCls ?? ''].filter(Boolean).join(' ') || undefined;
                      return (
                        <td key={c.id} className={tdCls} style={c.style}>
                          {c.cell(r)}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {(showPager || footerExtra || q) && (
        <div className="dt-foot">
          <span className="dt-range" aria-live="polite">
            {sorted.length === 0 ? `0 of ${total.toLocaleString('en-US')}${countNoun ? ' ' + countNoun : ''}` : `${from.toLocaleString('en-US')}–${to.toLocaleString('en-US')} of ${sorted.length.toLocaleString('en-US')}${countNoun ? ' ' + countNoun : ''}`}
            {q && sorted.length !== total ? <span className="muted"> · filtered from {total.toLocaleString('en-US')}</span> : null}
          </span>
          <div className="dt-controls">
            {footerExtra}
            {showPager && (
              <>
                <span className="inline-sm">
                  <span className="muted small" aria-hidden="true">
                    Rows
                  </span>
                  <Select<string> size="sm" inline aria-label="Rows per page" value={String(size)} onChange={(v) => setSize(Number(v))} options={sizes.map((n) => ({ value: String(n), label: String(n) }))} />
                </span>
                <nav className="inline-sm" aria-label={`${label} pages`}>
                  <button type="button" className="btn sm" onClick={() => setPage(cur - 1)} disabled={cur === 0} aria-label="Previous page">
                    Previous
                  </button>
                  <span className="muted small" aria-current="page">
                    Page {cur + 1} of {pages}
                  </span>
                  <button type="button" className="btn sm" onClick={() => setPage(cur + 1)} disabled={cur >= pages - 1} aria-label="Next page">
                    Next
                  </button>
                </nav>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** Debounced copy of a value (search fields that hit the server). */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
