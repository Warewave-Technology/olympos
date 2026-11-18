import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useInfiniteQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { ActivityEntry, ItemList } from '../api/types';
import { dateTime } from '../lib/format';
import { activityRoute } from '../router';
import { Badge, EmptyState, ErrorState, Loading, type Tone } from '../ui/kit';
import { PageHead } from '../ui/status';

const PAGE = 50;
/** Each group is one `action` prefix (the API filters by a single prefix). */
const GROUPS = [
  { id: '', label: 'All' },
  { id: 'grant.', label: 'Access' },
  { id: 'login.', label: 'Sign-ins' },
  { id: 'cr.', label: 'Change requests' },
  { id: 'vault.', label: 'Vaults & drift' },
  { id: 'backup.', label: 'Backups' },
  { id: 'cluster.', label: 'Clusters' },
  { id: 'audit.', label: 'Audit' },
];

export function actionTone(action: string): Tone {
  if (/(failed|rejected|unmanaged_write|denied|revoked|offline|critical)$/.test(action) || action.endsWith('.rejected')) return 'crit';
  if (/(opened|stale|missed|expiring|expired|compressed)$/.test(action)) return 'warn';
  if (/(succeeded|applied|approved|online|enabled)$/.test(action)) return 'ok';
  return 'info';
}

export function detailsText(d: Record<string, unknown> | null | undefined): string {
  if (!d) return '';
  if (typeof d.summary === 'string' && d.summary) return d.summary;
  return Object.entries(d)
    .filter(([, v]) => v !== null && v !== undefined && v !== '' && typeof v !== 'object')
    .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${String(v)}`)
    .join(' · ');
}

/** Prefer a human name from details over a raw UUID. */
function objectLabel(e: ActivityEntry): string {
  const d = e.details ?? {};
  for (const k of ['name', 'principal', 'service', 'cluster']) if (typeof d[k] === 'string' && d[k]) return d[k] as string;
  return e.object_id;
}

function csv(rows: ActivityEntry[]): string {
  const esc = (s: string) => `"${s.replace(/"/g, '""')}"`;
  const head = ['time', 'actor', 'actor_kind', 'action', 'object_type', 'object_id', 'details'];
  return [head.join(','), ...rows.map((r) => [r.at, r.actor_name, r.actor_kind, r.action, r.object_type, r.object_id, detailsText(r.details)].map((v) => esc(String(v ?? ''))).join(','))].join('\n');
}

export function ActivityPage() {
  const search = activityRoute.useSearch();
  const navigate = useNavigate({ from: '/activity' });
  const [term, setTerm] = useState(search.q ?? '');
  const group = search.group ?? '';
  useEffect(() => {
    const t = setTimeout(() => {
      if ((search.q ?? '') !== term) void navigate({ search: (s) => ({ ...s, q: term || undefined }), replace: true });
    }, 300);
    return () => clearTimeout(t);
  }, [term, search.q, navigate]);

  const q = useInfiniteQuery({
    queryKey: ['activity', { q: search.q, group }],
    queryFn: ({ pageParam }) => api.get<ItemList<ActivityEntry>>('/activity', { q: search.q, action: group, limit: PAGE, before: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => (last.items.length < PAGE ? undefined : last.items[last.items.length - 1].at),
  });
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];

  const exportCsv = () => {
    const blob = new Blob([csv(rows)], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `olympos-activity-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  return (
    <>
      <PageHead
        title="Activity log"
        sub="Every action on Olympos, append-only · retained 400 days"
        actions={
          <button type="button" className="btn" onClick={exportCsv} disabled={rows.length === 0}>
            Export CSV
          </button>
        }
      />
      <div className="inline">
        <label className="sr-only" htmlFor="aq">
          Search activity
        </label>
        <input id="aq" type="search" className="in search" style={{ width: 320 }} placeholder="Search actor, object, action…" value={term} onChange={(e) => setTerm(e.target.value)} />
        <div className="pills" role="group" aria-label="Filter by area">
          {GROUPS.map((g) => (
            <button key={g.id} type="button" className="pill" aria-pressed={group === g.id} onClick={() => navigate({ search: (s) => ({ ...s, group: g.id || undefined }), replace: true })}>
              {g.label}
            </button>
          ))}
        </div>
      </div>
      <section className="card" aria-label="Activity entries">
        {q.isPending ? (
          <Loading label="Loading activity…" />
        ) : q.isError ? (
          <ErrorState what="the activity log" error={q.error} onRetry={() => q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState title={search.q || group ? 'No matching activity' : 'No activity yet'}>{search.q || group ? 'Try a broader search or another filter.' : 'Sign-ins, grants, backups and change requests are recorded here as they happen.'}</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Object</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{dateTime(e.at)}</td>
                    <td className={e.actor_kind === 'user' ? undefined : 'muted'}>{e.actor_name || e.actor_kind}</td>
                    <td>
                      <Badge tone={actionTone(e.action)}>{e.action}</Badge>
                    </td>
                    <td className={e.object_id ? 'mono' : 'muted'} title={e.object_id}>
                      {objectLabel(e) || '—'}
                    </td>
                    <td className="muted wrap">{detailsText(e.details) || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {rows.length > 0 && (
          <div className="card-foot spread">
            <span>Showing {rows.length.toLocaleString('en-US')} · values and tokens are never logged</span>
            {q.hasNextPage && (
              <button type="button" className="btn sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
                {q.isFetchingNextPage ? 'Loading…' : 'Load older entries'}
              </button>
            )}
          </div>
        )}
      </section>
    </>
  );
}
